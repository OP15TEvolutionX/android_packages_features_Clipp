// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.util.Base64;
import android.util.Log;

import org.evolution.clipp.ClippCrypto;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Peer-to-peer part of Clipp on one Wi-Fi network.
 *
 * <p>The phone advertises itself over DNS-SD and finds peers the same way; the TXT record carries
 * the host ID and name, sealed with the group key, so other groups can't read or fake it. Each
 * peer gets two links, as the desktop app expects: the outgoing one, opened by us, sends our
 * clips; the incoming one, opened by the peer, carries its clips to us. Outgoing links are retried
 * with backoff until the peer stops advertising.
 *
 * <p>A transport is used once: {@link #close} stops everything, and the engine builds a new one.
 */
public final class ClippTransport implements AutoCloseable {
    private static final String TAG = "ClippTransport";
    /** Seconds before the next outgoing attempt, by attempt number; the last one repeats. */
    private static final long[] RETRY_DELAYS_S = {2, 4, 8, 16, 32, 60, 120, 300};
    /** At most this many unauthenticated incoming connections at a time. */
    private static final int MAX_HANDSHAKES = 10;

    public interface Events {
        /** Peer state for Settings: "connected", "disconnected" or "connection_error". */
        void state(String id, String name, String state);

        /** A clip from a peer; called on the link's reader thread. */
        void receive(ClippWire.Item item);
    }

    private final NsdManager nsd;
    private final PowerManager power;
    private final Network network;
    private final byte[] root, host, mdnsKey;
    private final String name;
    private final Events events;
    private final int imageLimit;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService timers = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService readers =
            new ThreadPoolExecutor(
                    0, Integer.MAX_VALUE, 30, TimeUnit.SECONDS, new SynchronousQueue<>());
    private final ExecutorService writers =
            new ThreadPoolExecutor(
                    0, Integer.MAX_VALUE, 30, TimeUnit.SECONDS, new SynchronousQueue<>());
    /** One clip decoded at a time; see {@link ClippWire.Channel#receive}. */
    private final Semaphore decoding = new Semaphore(1);
    private final Semaphore auth = new Semaphore(MAX_HANDSHAKES);
    // Peer and link state is guarded by the peers monitor.
    // DNS-SD candidate/resolve collections below are confined to the main handler.
    private final Map<String, Peer> peers = new LinkedHashMap<>();
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final Map<String, NsdServiceInfo> candidates = new LinkedHashMap<>();
    private final ArrayDeque<NsdServiceInfo> resolveQueue = new ArrayDeque<>();
    private final Set<String> resolvingNames = new HashSet<>();
    private final Set<String> discoveredNames = new HashSet<>();
    /** NsdManager resolves one service at a time, so resolves are queued. */
    private boolean resolving;
    // Main-thread only: successive transports wait for the previous NSD lifecycle to end.
    private static CompletableFuture<Void> previousStop = CompletableFuture.completedFuture(null);
    private final CompletableFuture<Void> advertisementStopped = new CompletableFuture<>();
    private final CompletableFuture<Void> discoveryStopped = new CompletableFuture<>();
    private final CompletableFuture<Void> resourcesStopped = new CompletableFuture<>();
    private final AtomicBoolean closeRequested = new AtomicBoolean();
    private volatile boolean closed;
    /** Latest clip, sent to peers that ask for a sync. */
    private volatile ClippWire.Item latest;
    private ServerSocket listener;
    private final InetAddress localAddress;
    private final int localPrefix;
    private String resolvingName;
    private NsdManager.DiscoveryListener discovery;
    private NsdManager.RegistrationListener registration;

    /** A device in the group, keyed by its host ID. */
    private final class Peer {
        final String id;
        String name;
        InetAddress address;
        int port;
        /** Seen over DNS-SD; only advertised peers get outgoing connections. */
        boolean advertised, connecting;
        /** Failed outgoing attempts in a row, for the retry delay. */
        int attempt;
        Link incoming, outgoing;
        ScheduledFuture<?> retry;

        Peer(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }

    private interface SendAction {
        void run() throws IOException;
    }

    /**
     * One authenticated connection. Writes go through one writer task at a time: queued control
     * commands first, then the newest pending clip. Older pending clips are dropped.
     */
    private final class Link {
        final Socket socket;
        final ClippWire.Channel channel;
        final Peer peer;
        final boolean outgoing;
        final AtomicReference<ClippWire.Item> pending = new AtomicReference<>();
        final AtomicBoolean sending = new AtomicBoolean();
        final ArrayBlockingQueue<SendAction> commands = new ArrayBlockingQueue<>(32);
        ScheduledFuture<?> ping;

        Link(Socket s, ClippWire.Channel c, Peer p, boolean out) {
            socket = s;
            channel = c;
            peer = p;
            outgoing = out;
        }

        void queue(ClippWire.Item item) {
            pending.set(item);
            drain();
        }

        private void drain() {
            if (closed || socket.isClosed() || !sending.compareAndSet(false, true)) return;
            if (!write(
                    () -> {
                        try {
                            while (!closed && !socket.isClosed()) {
                                SendAction command = commands.poll();
                                if (command != null) {
                                    command.run();
                                    continue;
                                }
                                ClippWire.Item item = pending.getAndSet(null);
                                if (item == null) break;
                                send(item.frame(false));
                            }
                        } catch (Exception e) {
                            stop();
                        } finally {
                            sending.set(false);
                            if (pending.get() != null || !commands.isEmpty()) drain();
                        }
                    })) {
                sending.set(false);
                stop();
            }
        }

        void command(SendAction action) {
            if (!commands.offer(action)) {
                stop();
                return;
            }
            drain();
        }

        /** Writer thread only. A peer that stops reading loses the link after 30 s. */
        void send(byte[] frame) throws IOException {
            ScheduledFuture<?> deadline =
                    timers.schedule(() -> closeSocket(socket), 30, TimeUnit.SECONDS);
            try {
                channel.send(frame);
            } finally {
                deadline.cancel(false);
            }
        }

        void command(byte[] data) {
            command(() -> send(data));
        }

        void stop() {
            if (ping != null) ping.cancel(false);
            closeSocket(socket);
            pending.set(null);
            commands.clear();
        }
    }

    public ClippTransport(
            Context context,
            Network network,
            InetAddress address,
            byte[] root,
            byte[] host,
            String name,
            int limit,
            Events events)
            throws IOException {
        this.localAddress = address;
        int prefix = 0;
        ConnectivityManager connectivity = context.getSystemService(ConnectivityManager.class);
        LinkProperties properties =
                connectivity == null ? null : connectivity.getLinkProperties(network);
        if (properties != null)
            for (LinkAddress link : properties.getLinkAddresses())
                if (link.getAddress().equals(address)) {
                    prefix = link.getPrefixLength();
                    break;
                }
        this.localPrefix = prefix;
        this.nsd = context.getSystemService(NsdManager.class);
        this.power = context.getSystemService(PowerManager.class);
        this.network = network;
        this.root = root.clone();
        this.host = host.clone();
        this.mdnsKey = ClippCrypto.role(root, ClippCrypto.ROLE_DISCOVERY);
        this.name = name;
        this.imageLimit = limit;
        this.events = events;
        listener = new ServerSocket();
        listener.bind(new InetSocketAddress(address, 0));
    }

    public void start() {
        main.post(this::startDiscovery);
    }

    /** Keeps a clip for later syncs without sending it now. */
    public void remember(ClippWire.Item item) {
        latest = item;
    }

    /** Sends a clip to every connected peer. */
    public void publish(ClippWire.Item item) {
        latest = item;
        synchronized (peers) {
            for (Peer p : peers.values()) if (p.outgoing != null) p.outgoing.queue(item);
        }
    }

    private boolean write(Runnable r) {
        if (closed) return false;
        try {
            writers.execute(r);
            return true;
        } catch (RejectedExecutionException ignored) {
            return false;
        }
    }

    private void trackSocket(Socket socket) throws IOException {
        synchronized (sockets) {
            if (closed) {
                socket.close();
                throw new IOException("Stopped");
            }
            sockets.add(socket);
        }
    }

    private void closeSocket(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
        sockets.remove(s);
    }

    private void acceptLoop() {
        while (!closed) {
            try {
                Socket s = listener.accept();
                if (!auth.tryAcquire()) {
                    s.close();
                    continue;
                }
                try {
                    trackSocket(s);
                    readers.execute(
                            () -> {
                                establish(s, null, false);
                            });
                } catch (RejectedExecutionException | IOException e) {
                    auth.release();
                    closeSocket(s);
                }
            } catch (IOException e) {
                // The listener was closed.
                break;
            }
        }
    }

    /**
     * Runs one connection on a reader thread: handshake, link registration, then the read loop
     * until the socket closes. {@code expected} is the peer we dialled, or null for incoming.
     */
    private void establish(Socket s, Peer expected, boolean outgoing) {
        boolean authHeld = !outgoing;
        Link link = null;
        ClippWire.Channel channel = null;
        ScheduledFuture<?> deadline = null;
        try {
            trackSocket(s);
            s.setTcpNoDelay(true);
            s.setSoTimeout(10000);
            deadline = timers.schedule(() -> closeSocket(s), 10, TimeUnit.SECONDS);
            channel =
                    new ClippWire.Channel(
                            s.getInputStream(), s.getOutputStream(), root, host, name, outgoing);
            String id = ClippWire.hex(channel.remoteId);
            if (Arrays.equals(host, channel.remoteId)
                    || (expected != null && !id.equals(expected.id)))
                throw new IOException("Identity");
            if (authHeld) {
                auth.release();
                authHeld = false;
            }
            Peer peer;
            synchronized (peers) {
                peer = peers.get(id);
                if (peer == null) {
                    peer = new Peer(id, channel.remoteName);
                    peers.put(id, peer);
                }
                peer.name = channel.remoteName;
                link = new Link(s, channel, peer, outgoing);
                Link old = outgoing ? peer.outgoing : peer.incoming;
                if (outgoing) peer.outgoing = link;
                else peer.incoming = link;
                if (old != null) old.stop();
                peer.attempt = 0;
                // An authenticated inbound link proves a known peer has woken up.
                if (!outgoing) schedule(peer, true);
            }
            deadline.cancel(false);
            deadline = null;
            s.setSoTimeout(90000);
            events.state(peer.id, peer.name, "connected");
            final Link active = link;
            if (outgoing) {
                link.ping =
                        timers.scheduleWithFixedDelay(
                                () -> active.command(ClippWire.utf8("PING")),
                                30,
                                33,
                                TimeUnit.SECONDS);
            } else {
                // Complete history synchronization without changing the OS clipboard.
                byte[] request = new byte[20];
                System.arraycopy(ClippWire.utf8("SYNC"), 0, request, 0, 4);
                link.command(request);
            }
            while (!closed && !s.isClosed()) {
                byte[] frame =
                        channel.receive(
                                imageLimit + ClippWire.HEADER + ClippWire.FRAME_OVERHEAD, decoding);
                try {
                    handleFrame(link, frame);
                } finally {
                    channel.releaseReceiveBudget(decoding);
                }
            }
        } catch (Exception failure) {
            if (!closed) Log.w(TAG, "Connection ended", failure);
            if (expected != null && !closed)
                events.state(expected.id, expected.name, "connection_error");
        } finally {
            if (authHeld) auth.release();
            if (deadline != null) deadline.cancel(false);
            if (link != null) {
                link.stop();
                synchronized (peers) {
                    Peer peer = link.peer;
                    if (link.outgoing) peer.connecting = false;
                    if (link.outgoing && peer.outgoing == link) peer.outgoing = null;
                    if (!link.outgoing && peer.incoming == link) peer.incoming = null;
                    if (!closed) {
                        events.state(
                                peer.id,
                                peer.name,
                                peer.incoming != null || peer.outgoing != null
                                        ? "connected"
                                        : "disconnected");
                        if (link.outgoing) schedule(peer, false);
                        if (!peer.advertised && peer.incoming == null && peer.outgoing == null)
                            peers.remove(peer.id);
                    }
                }
            } else closeSocket(s);
            if (channel != null) channel.wipe();
            if (link == null && expected != null && !closed)
                synchronized (peers) {
                    expected.connecting = false;
                    schedule(expected, false);
                }
        }
    }

    /** Handles one decrypted frame from a link. */
    private void handleFrame(Link link, byte[] frame) throws IOException {
        if (frame.length < 4) throw new IOException("Frame");
        String tag = new String(frame, 0, 4, StandardCharsets.US_ASCII);
        switch (tag) {
            case "PING":
                link.command(ClippWire.utf8("PONG"));
                break;
            case "PONG":
            case "NONE":
            case "CDEL":
            case "REGW":
            case "REOS":
            case "RDEL":
            case "RERR":
            case "ROKP":
            case "EOSY":
                break;
            case "RSYN":
                // Desktop sends register anti-entropy even to clipboard-only peers.
                // We have no register store to contribute; finish without changing it.
                link.command(ClippWire.utf8("REOS"));
                break;
            case "CLIP": {
                ClippWire.Item item = ClippWire.decode(frame, imageLimit);
                if ((item.flags & ClippWire.FLAG_PRIVATE) != 0) break;
                if ((item.flags & ClippWire.FLAG_REPLAY) == 0) events.receive(item);
                break;
            }
            case "SYNC": {
                // The peer wants our latest clip as history, ended by "EOSY".
                if (frame.length != 20) throw new IOException("Sync");
                ClippWire.Item snapshot = latest;
                link.command(
                        () -> {
                            if (snapshot != null) link.send(snapshot.frame(true));
                            link.send(ClippWire.utf8("EOSY"));
                        });
                break;
            }
            case "RCNT": {
                // The peer asks for our current text, if any.
                ClippWire.Item current = latest;
                if (current != null && current.format == ClippWire.TEXT)
                    link.command(current.frame(false));
                else link.command(ClippWire.utf8("NONE"));
                break;
            }
            default:
                // Authenticated protocol extensions must not disconnect clipboard sync.
                Log.d(TAG, "Ignoring frame " + tag);
                break;
        }
    }

    /**
     * Plans the next outgoing connection to an advertised peer that has none: now if
     * {@code immediate}, otherwise after the backoff delay plus up to a second of jitter.
     * Must hold {@link #peers}.
     */
    private void schedule(Peer peer, boolean immediate) {
        if (closed || !peer.advertised || peer.outgoing != null || peer.connecting) return;
        if (peer.retry != null && !peer.retry.isDone()) {
            if (!immediate) return;
            peer.retry.cancel(false);
        }
        long seconds =
                immediate
                        ? 0
                        : RETRY_DELAYS_S[Math.min(peer.attempt++, RETRY_DELAYS_S.length - 1)];
        long delayMs =
                seconds == 0 ? 0 : seconds * 1000 + ThreadLocalRandom.current().nextLong(1000);
        peer.retry = timers.schedule(() -> dial(peer), delayMs, TimeUnit.MILLISECONDS);
    }

    /** Opens the outgoing connection to a peer; the connection then runs on a reader thread. */
    private void dial(Peer peer) {
        if (closed || !peer.advertised) return;
        synchronized (peers) {
            if (peer.connecting || peer.outgoing != null) return;
            peer.connecting = true;
            peer.retry = null;
        }
        try {
            readers.execute(
                    () -> {
                        Socket s = new Socket();
                        try {
                            network.bindSocket(s);
                            trackSocket(s);
                            s.connect(new InetSocketAddress(peer.address, peer.port), 5000);
                            establish(s, peer, true);
                        } catch (Exception e) {
                            closeSocket(s);
                            if (!closed)
                                synchronized (peers) {
                                    peer.connecting = false;
                                    events.state(peer.id, peer.name, "connection_error");
                                    schedule(peer, false);
                                }
                        }
                    });
        } catch (RejectedExecutionException e) {
            synchronized (peers) {
                peer.connecting = false;
                schedule(peer, false);
            }
        }
    }

    /**
     * Main thread: starts accepting, advertises this device and starts discovery. Waits first
     * until the previous transport has fully withdrawn its NSD service.
     */
    private void startDiscovery() {
        if (closed || closeRequested.get()) return;
        if (!previousStop.isDone()) {
            previousStop.thenRun(() -> main.post(this::startDiscovery));
            return;
        }
        try {
            readers.execute(this::acceptLoop);
            NsdServiceInfo info = new NsdServiceInfo();
            info.setServiceName(
                    "clipp-"
                            + ClippWire.hex(host).substring(0, 8)
                            + "-"
                            + UUID.randomUUID().toString().substring(0, 8));
            info.setServiceType(ClippDiscovery.SERVICE_TYPE);
            info.setPort(listener.getLocalPort());
            info.setNetwork(network);
            info.setHostAddresses(Collections.singletonList(localAddress));
            byte[] packet = ClippDiscovery.encode(host, name);
            info.setAttribute("v", ClippDiscovery.TXT_VERSION);
            info.setAttribute(
                    "d",
                    Base64.encodeToString(
                            ClippCrypto.seal(mdnsKey, packet), Base64.NO_WRAP | Base64.NO_PADDING));
            registration =
                    new NsdManager.RegistrationListener() {
                        public void onServiceRegistered(NsdServiceInfo i) {}

                        public void onServiceUnregistered(NsdServiceInfo i) {
                            advertisementStopped.complete(null);
                        }

                        public void onRegistrationFailed(NsdServiceInfo i, int e) {
                            Log.w(TAG, "mDNS registration failed: " + e);
                            advertisementStopped.complete(null);
                        }

                        public void onUnregistrationFailed(NsdServiceInfo i, int e) {
                            Log.w(TAG, "mDNS unregistration failed: " + e);
                            advertisementStopped.complete(null);
                        }
                    };
            nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, registration);
            discovery =
                    new NsdManager.DiscoveryListener() {
                        public void onDiscoveryStarted(String t) {}

                        public void onDiscoveryStopped(String t) {
                            discoveryStopped.complete(null);
                        }

                        public void onStartDiscoveryFailed(String t, int e) {
                            Log.w(TAG, "mDNS discovery failed: " + e);
                            discoveryStopped.complete(null);
                        }

                        public void onStopDiscoveryFailed(String t, int e) {
                            Log.w(TAG, "mDNS discovery stop failed: " + e);
                            discoveryStopped.complete(null);
                        }

                        public void onServiceFound(NsdServiceInfo service) {
                            main.post(() -> serviceFound(service));
                        }

                        public void onServiceLost(NsdServiceInfo service) {
                            main.post(() -> serviceLost(service));
                        }
                    };
            nsd.discoverServices(
                    ClippDiscovery.SERVICE_TYPE,
                    NsdManager.PROTOCOL_DNS_SD,
                    network,
                    Runnable::run,
                    discovery);

        } catch (Exception e) {
            Log.w(TAG, "mDNS start failed", e);
        }
    }

    /** Main thread: queues a newly seen service for resolving. */
    private void serviceFound(NsdServiceInfo service) {
        if (closed) return;
        String serviceName = service.getServiceName();
        discoveredNames.add(serviceName);
        if (resolvingNames.contains(serviceName)) return;
        resolvingNames.add(serviceName);
        resolveQueue.add(service);
        resolveNext();
    }

    /**
     * Main thread: forgets a service. The peer stops being advertised once none of its services
     * is left (a desktop may advertise more than one), and is removed if it has no links.
     */
    private void serviceLost(NsdServiceInfo service) {
        if (closed) return;
        String serviceName = service.getServiceName();
        discoveredNames.remove(serviceName);
        if (!serviceName.equals(resolvingName)) resolvingNames.remove(serviceName);
        resolveQueue.removeIf(queued -> queued.getServiceName().equals(serviceName));
        NsdServiceInfo prior = candidates.remove(serviceName);
        if (prior == null) return;
        try {
            String id = decodeId(prior);
            for (NsdServiceInfo remaining : candidates.values())
                if (id.equals(decodeId(remaining))) return;
            synchronized (peers) {
                Peer peer = peers.get(id);
                if (peer == null) return;
                peer.advertised = false;
                if (peer.retry != null) peer.retry.cancel(false);
                if (peer.incoming == null && peer.outgoing == null) {
                    peers.remove(id);
                    events.state(id, peer.name, "disconnected");
                }
            }
        } catch (Exception ignored) {
            // Not one of our group's services.
        }
    }

    /** Main thread: resolves the next queued service, one at a time. */
    private void resolveNext() {
        if (closed || resolving || resolveQueue.isEmpty()) return;
        resolving = true;
        NsdServiceInfo service = resolveQueue.remove();
        resolvingName = service.getServiceName();
        try {
            nsd.resolveService(
                    service,
                    new NsdManager.ResolveListener() {
                        public void onResolveFailed(NsdServiceInfo s, int e) {
                            done(null);
                        }

                        public void onServiceResolved(NsdServiceInfo s) {
                            done(s);
                        }

                        private void done(NsdServiceInfo s) {
                            main.post(
                                    () -> {
                                        resolving = false;
                                        resolvingName = null;
                                        resolvingNames.remove(service.getServiceName());
                                        if (!closed
                                                && s != null
                                                && discoveredNames.contains(
                                                        service.getServiceName())) found(s);
                                        resolveNext();
                                    });
                        }
                    });
        } catch (Exception e) {
            resolving = false;
            resolvingName = null;
            resolvingNames.remove(service.getServiceName());
            resolveNext();
        }
    }

    /** Opens the sealed TXT payload; throws if it isn't from our group. */
    private byte[] decode(NsdServiceInfo s) {
        Map<String, byte[]> attrs = s.getAttributes();
        if (!Arrays.equals(attrs.get("v"), ClippWire.utf8(ClippDiscovery.TXT_VERSION)))
            throw new IllegalArgumentException();
        byte[] p = ClippCrypto.open(mdnsKey, Base64.decode(attrs.get("d"), Base64.NO_WRAP));
        ClippDiscovery.validate(p);
        return p;
    }

    private String decodeId(NsdServiceInfo s) {
        return ClippDiscovery.hostId(decode(s));
    }

    private boolean sameSubnet(InetAddress candidate) {
        if (localPrefix <= 0) return false;
        byte[] a = candidate.getAddress(), b = localAddress.getAddress();
        if (a.length != b.length) return false;
        for (int i = 0, bits = localPrefix; bits > 0; i++, bits -= 8) {
            int mask = 0xff << (8 - Math.min(bits, 8));
            if ((a[i] & mask) != (b[i] & mask)) return false;
        }
        return true;
    }

    /**
     * A resolved service: records the peer's address, preferring an IPv4 address on our subnet,
     * and connects to it if anything changed. Services of other groups fail to decode and are
     * ignored.
     */
    private void found(NsdServiceInfo s) {
        try {
            if (s.getNetwork() != null && !s.getNetwork().equals(network)) return;
            byte[] packet = decode(s), idBytes = ClippDiscovery.host(packet);
            String id = ClippWire.hex(idBytes);
            InetAddress address = s.getHost(), firstIpv4 = null, localIpv4 = null;
            for (InetAddress candidate : s.getHostAddresses()) {
                if (!(candidate instanceof Inet4Address)) continue;
                if (firstIpv4 == null) firstIpv4 = candidate;
                if (sameSubnet(candidate)) {
                    localIpv4 = candidate;
                    break;
                }
            }
            if (localIpv4 != null) address = localIpv4;
            else if (firstIpv4 != null) address = firstIpv4;
            if (Arrays.equals(idBytes, host)
                    || address == null
                    || s.getPort() < 1024
                    || s.getPort() > 65535) return;
            synchronized (peers) {
                Peer peer = peers.get(id);
                if (peer == null) {
                    peer = new Peer(id, ClippDiscovery.name(packet));
                    peers.put(id, peer);
                }
                boolean changed =
                        !Objects.equals(peer.address, address)
                                || peer.port != s.getPort()
                                || !peer.advertised
                                || !candidates.containsKey(s.getServiceName());
                peer.address = address;
                peer.port = s.getPort();
                peer.advertised = true;
                candidates.put(s.getServiceName(), s);
                if (changed) {
                    peer.attempt = 0;
                    schedule(peer, true);
                }
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * NsdService acknowledges removal before sending goodbye packets (100 ms, 2100 ms, 4100 ms on
     * our platform). Keep the CPU awake briefly so real suspend cannot strand these queued packets.
     * Never keep sockets open.
     */
    private void allowGoodbyeAnnouncements() {
        if (power == null || !power.isDeviceIdleMode()) return;
        PowerManager.WakeLock cleanup =
                power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Clipp:mdns-withdraw");
        try {
            cleanup.setReferenceCounted(false);
            cleanup.acquire(5000);
            // Independent of the main thread and transport pools, which stop below.
            Thread release =
                    new Thread(
                            () -> {
                                try {
                                    Thread.sleep(4500);
                                } catch (InterruptedException error) {
                                    Thread.currentThread().interrupt();
                                } finally {
                                    if (cleanup.isHeld()) cleanup.release();
                                }
                            },
                            "Clipp-mdns-withdraw");
            release.setDaemon(true);
            release.start();
        } catch (RuntimeException error) {
            if (cleanup.isHeld()) cleanup.release();
            Log.w(TAG, "mDNS cleanup wake lock failed", error);
        }
    }

    /** Main-thread only: withdraw first so DNS-SD can send its goodbye promptly. */
    private void stopDiscoveryAndAdvertising() {
        if (registration != null) {
            allowGoodbyeAnnouncements();
            NsdManager.RegistrationListener previous = registration;
            registration = null;
            try {
                nsd.unregisterService(previous);
            } catch (Exception error) {
                Log.w(TAG, "mDNS withdrawal failed", error);
                advertisementStopped.complete(null);
            }
        } else advertisementStopped.complete(null);
        if (discovery != null) {
            NsdManager.DiscoveryListener previous = discovery;
            discovery = null;
            try {
                nsd.stopServiceDiscovery(previous);
            } catch (Exception error) {
                Log.w(TAG, "mDNS discovery stop failed", error);
                discoveryStopped.complete(null);
            }
        } else discoveryStopped.complete(null);
    }

    @Override
    public void close() {
        // Main-thread callers (including deep Doze) may finish an already queued stop now.
        if (Looper.myLooper() == Looper.getMainLooper()) {
            closeRequested.set(true);
            closeOnMain();
        } else if (closeRequested.compareAndSet(false, true)) main.post(this::closeOnMain);
    }

    private void closeOnMain() {
        if (closed) return;
        previousStop =
                CompletableFuture.allOf(
                        previousStop, advertisementStopped, discoveryStopped, resourcesStopped);
        stopDiscoveryAndAdvertising();
        closed = true;
        try {
            listener.close();
        } catch (IOException ignored) {
        }
        synchronized (sockets) {
            for (Socket s : sockets) closeSocket(s);
        }
        synchronized (peers) {
            for (Peer p : peers.values()) {
                if (p.incoming != null) p.incoming.stop();
                if (p.outgoing != null) p.outgoing.stop();
                if (p.retry != null) p.retry.cancel(false);
            }
            peers.clear();
        }
        timers.shutdownNow();
        writers.shutdownNow();
        readers.shutdownNow();
        Arrays.fill(root, (byte) 0);
        Arrays.fill(mdnsKey, (byte) 0);
        latest = null;
        resourcesStopped.complete(null);
    }
}
