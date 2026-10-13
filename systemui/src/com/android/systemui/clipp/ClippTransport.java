// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.content.Context;
import android.net.Network;
import android.net.nsd.*;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;

import org.evolution.clipp.ClippCrypto;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Five authenticated peers, each with the two directional links expected by Clipp. */
public final class ClippTransport implements AutoCloseable {
    public interface Events {
        void state(String id, String name, String state);

        void receive(ClippWire.Item item);
    }

    private final NsdManager nsd;
    private final Network network;
    private final byte[] root, host, mdnsKey;
    private final String name;
    private final Events events;
    private final Set<String> blocked;
    private final int imageLimit;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService timers = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService readers =
            new ThreadPoolExecutor(0, 16, 30, TimeUnit.SECONDS, new SynchronousQueue<>());
    private final ThreadPoolExecutor writers =
            new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(20));
    private final Semaphore decoding = new Semaphore(1), auth = new Semaphore(10);
    private final Map<String, Peer> peers = new LinkedHashMap<>();
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final Map<String, NsdServiceInfo> candidates = new LinkedHashMap<>();
    private final ArrayDeque<NsdServiceInfo> resolveQueue = new ArrayDeque<>();
    private final Set<String> resolvingNames = new HashSet<>();
    private boolean resolving;
    private volatile boolean closed;
    private volatile ClippWire.Item latest;
    private ServerSocket listener;
    private final InetAddress localAddress;
    private NsdManager.DiscoveryListener discovery;
    private NsdManager.RegistrationListener registration;

    private final class Peer {
        final String id;
        String name;
        InetAddress address;
        int port;
        boolean advertised, connecting;
        int attempt;
        Link incoming, outgoing;
        ScheduledFuture<?> retry;

        Peer(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }

    private final class Link {
        final Socket socket;
        final ClippWire.Channel channel;
        final Peer peer;
        final boolean outgoing;
        final AtomicReference<ClippWire.Item> pending = new AtomicReference<>();
        final AtomicBoolean sending = new AtomicBoolean();
        ScheduledFuture<?> ping;

        Link(Socket s, ClippWire.Channel c, Peer p, boolean out) {
            socket = s;
            channel = c;
            peer = p;
            outgoing = out;
        }

        void queue(ClippWire.Item item) {
            pending.set(item);
            if (sending.compareAndSet(false, true))
                write(
                        () -> {
                            try {
                                ClippWire.Item next;
                                while ((next = pending.getAndSet(null)) != null
                                        && !closed
                                        && !socket.isClosed()) send(next.frame(false));
                            } catch (Exception e) {
                                stop();
                            } finally {
                                sending.set(false);
                                ClippWire.Item next = pending.get();
                                if (next != null && !closed && !socket.isClosed()) queue(next);
                            }
                        });
        }

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
            write(
                    () -> {
                        try {
                            send(data);
                        } catch (Exception e) {
                            stop();
                        }
                    });
        }

        void stop() {
            if (ping != null) ping.cancel(false);
            closeSocket(socket);
            pending.set(null);
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
            Set<String> blocked,
            Events events)
            throws IOException {
        this.localAddress = address;
        this.nsd = context.getSystemService(NsdManager.class);
        this.network = network;
        this.root = root.clone();
        this.host = host.clone();
        this.mdnsKey = ClippCrypto.role(root, 3);
        this.name = name;
        this.imageLimit = limit;
        this.blocked = new HashSet<>(blocked);
        this.events = events;
        listener = new ServerSocket();
        listener.bind(new InetSocketAddress(address, 0));
    }

    public void start() {
        readers.execute(this::acceptLoop);
        main.post(this::startDiscovery);
    }

    public void remember(ClippWire.Item item) {
        latest = item;
    }

    public void publish(ClippWire.Item item) {
        latest = item;
        synchronized (peers) {
            for (Peer p : peers.values()) if (p.outgoing != null) p.outgoing.queue(item);
        }
    }

    private void write(Runnable r) {
        if (closed) return;
        try {
            writers.execute(r);
        } catch (RejectedExecutionException ignored) {
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
                sockets.add(s);
                try {
                    readers.execute(
                            () -> {
                                try {
                                    establish(s, null, false);
                                } finally {
                                    auth.release();
                                }
                            });
                } catch (RejectedExecutionException e) {
                    auth.release();
                    closeSocket(s);
                }
            } catch (IOException e) {
                if (!closed) events.state("network", name, "connection_error");
                break;
            }
        }
    }

    private void establish(Socket s, Peer expected, boolean outgoing) {
        Link link = null;
        ClippWire.Channel channel = null;
        ScheduledFuture<?> deadline = null;
        try {
            sockets.add(s);
            s.setTcpNoDelay(true);
            s.setSoTimeout(10000);
            deadline = timers.schedule(() -> closeSocket(s), 10, TimeUnit.SECONDS);
            channel =
                    new ClippWire.Channel(
                            s.getInputStream(), s.getOutputStream(), root, host, name, outgoing);
            String id = ClippWire.hex(channel.remoteId);
            if (Arrays.equals(host, channel.remoteId)
                    || blocked.contains(id)
                    || (expected != null && !id.equals(expected.id)))
                throw new IOException("Identity");
            Peer peer;
            synchronized (peers) {
                peer = peers.get(id);
                if (peer == null) {
                    if (peers.size() >= 5) throw new IOException("Device limit");
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
                // Ask for one latest item; replay is collected and applied only at EOSY.
                byte[] request = new byte[24];
                System.arraycopy(ClippWire.utf8("SYNC"), 0, request, 0, 4);
                ByteBuffer.wrap(request).putInt(20, 1);
                link.command(request);
            }
            ClippWire.Item catchup = null;
            while (!closed && !s.isClosed()) {
                byte[] frame = channel.receive(imageLimit + ClippWire.HEADER + 21, decoding);
                try {
                    if (frame.length < 4) throw new IOException("Frame");
                    String tag =
                            new String(frame, 0, 4, java.nio.charset.StandardCharsets.US_ASCII);
                    switch (tag) {
                        case "PING":
                            link.command(ClippWire.utf8("PONG"));
                            break;
                        case "PONG":
                        case "NONE":
                        case "CDEL":
                            break;
                        case "CLIP":
                            {
                                ClippWire.Item item = ClippWire.decode(frame, imageLimit);
                                if ((item.flags & 2) != 0) break;
                                if ((item.flags & 1) != 0) catchup = item;
                                else events.receive(item);
                                break;
                            }
                        case "EOSY":
                            if (catchup != null) {
                                events.receive(catchup);
                                catchup = null;
                            }
                            break;
                        case "SYNC":
                            if (frame.length != 24) throw new IOException("Sync");
                            ClippWire.Item snapshot = latest;
                            Link sender = link;
                            write(
                                    () -> {
                                        try {
                                            if (snapshot != null) sender.send(snapshot.frame(true));
                                            sender.send(ClippWire.utf8("EOSY"));
                                        } catch (Exception e) {
                                            sender.stop();
                                        }
                                    });
                            break;
                        case "RCNT":
                            ClippWire.Item current = latest;
                            if (current != null && current.format == ClippWire.TEXT)
                                link.command(current.frame(false));
                            else link.command(ClippWire.utf8("NONE"));
                            break;
                        default:
                            throw new IOException("Unsupported frame");
                    }
                } finally {
                    decoding.release();
                }
            }
        } catch (Exception ignored) {
            if (expected != null && !closed)
                events.state(expected.id, expected.name, "connection_error");
        } finally {
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

    private void schedule(Peer peer, boolean immediate) {
        if (closed || !peer.advertised || peer.outgoing != null || peer.connecting) return;
        if (peer.retry != null && !peer.retry.isDone()) {
            if (!immediate) return;
            peer.retry.cancel(false);
        }
        long[] delays = {2, 4, 8, 16, 32, 60, 120, 300};
        long seconds = immediate ? 0 : delays[Math.min(peer.attempt++, delays.length - 1)];
        peer.retry =
                timers.schedule(
                        () -> {
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
                                                sockets.add(s);
                                                s.connect(
                                                        new InetSocketAddress(
                                                                peer.address, peer.port),
                                                        5000);
                                                establish(s, peer, true);
                                            } catch (Exception e) {
                                                closeSocket(s);
                                                if (!closed)
                                                    synchronized (peers) {
                                                        peer.connecting = false;
                                                        events.state(
                                                                peer.id,
                                                                peer.name,
                                                                "connection_error");
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
                        },
                        seconds == 0
                                ? 0
                                : seconds * 1000 + ThreadLocalRandom.current().nextLong(1000),
                        TimeUnit.MILLISECONDS);
    }

    private void startDiscovery() {
        if (closed) return;
        try {
            NsdServiceInfo info = new NsdServiceInfo();
            info.setServiceName(
                    "clipp-"
                            + ClippWire.hex(host).substring(0, 8)
                            + "-"
                            + UUID.randomUUID().toString().substring(0, 8));
            info.setServiceType("_clipp._tcp.");
            info.setPort(listener.getLocalPort());
            info.setNetwork(network);
            info.setHostAddresses(Collections.singletonList(localAddress));
            byte[] packet = new byte[100];
            ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).putInt(0, 0x434c4950);
            ByteBuffer.wrap(packet).putShort(4, (short) 1);
            System.arraycopy(host, 0, packet, 12, 16);
            ClippWire.name(packet, 36, 64, name);
            info.setAttribute("v", "1");
            info.setAttribute(
                    "d",
                    Base64.encodeToString(
                            ClippCrypto.call(2, mdnsKey, packet, null),
                            Base64.NO_WRAP | Base64.NO_PADDING));
            registration =
                    new NsdManager.RegistrationListener() {
                        public void onServiceRegistered(NsdServiceInfo i) {}

                        public void onServiceUnregistered(NsdServiceInfo i) {}

                        public void onRegistrationFailed(NsdServiceInfo i, int e) {
                            if (!closed) events.state("network", name, "connection_error");
                        }

                        public void onUnregistrationFailed(NsdServiceInfo i, int e) {}
                    };
            nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, registration);
            discovery =
                    new NsdManager.DiscoveryListener() {
                        public void onDiscoveryStarted(String t) {}

                        public void onDiscoveryStopped(String t) {}

                        public void onStartDiscoveryFailed(String t, int e) {
                            if (!closed) events.state("network", name, "connection_error");
                        }

                        public void onStopDiscoveryFailed(String t, int e) {}

                        public void onServiceFound(NsdServiceInfo service) {
                            main.post(
                                    () -> {
                                        if (closed
                                                || resolvingNames.contains(service.getServiceName())
                                                || resolveQueue.size() >= 32) return;
                                        resolvingNames.add(service.getServiceName());
                                        resolveQueue.add(service);
                                        resolveNext();
                                    });
                        }

                        public void onServiceLost(NsdServiceInfo service) {
                            main.post(
                                    () -> {
                                        NsdServiceInfo prior =
                                                candidates.remove(service.getServiceName());
                                        if (prior == null) return;
                                        try {
                                            String id = decodeId(prior);
                                            for (NsdServiceInfo remaining : candidates.values())
                                                if (id.equals(decodeId(remaining))) return;
                                            synchronized (peers) {
                                                Peer peer = peers.get(id);
                                                if (peer != null) {
                                                    peer.advertised = false;
                                                    if (peer.retry != null)
                                                        peer.retry.cancel(false);
                                                    if (peer.incoming == null
                                                            && peer.outgoing == null) {
                                                        peers.remove(id);
                                                        events.state(id, peer.name, "disconnected");
                                                    }
                                                }
                                            }
                                        } catch (Exception ignored) {
                                        }
                                    });
                        }
                    };
            nsd.discoverServices(
                    "_clipp._tcp.", NsdManager.PROTOCOL_DNS_SD, network, Runnable::run, discovery);
            events.state("network", name, "listening");
        } catch (Exception e) {
            if (!closed) events.state("network", name, "connection_error");
        }
    }

    private void resolveNext() {
        if (closed || resolving || resolveQueue.isEmpty()) return;
        resolving = true;
        NsdServiceInfo service = resolveQueue.remove();
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
                                        resolvingNames.remove(service.getServiceName());
                                        if (!closed && s != null) found(s);
                                        resolveNext();
                                    });
                        }
                    });
        } catch (Exception e) {
            resolving = false;
            resolvingNames.remove(service.getServiceName());
            resolveNext();
        }
    }

    private byte[] decode(NsdServiceInfo s) {
        Map<String, byte[]> attrs = s.getAttributes();
        if (!Arrays.equals(attrs.get("v"), ClippWire.utf8("1")))
            throw new IllegalArgumentException();
        byte[] p =
                ClippCrypto.call(3, mdnsKey, Base64.decode(attrs.get("d"), Base64.NO_WRAP), null);
        if (p.length != 100
                || ByteBuffer.wrap(p).order(ByteOrder.LITTLE_ENDIAN).getInt(0) != 0x434c4950
                || ByteBuffer.wrap(p).getShort(4) != 1) throw new IllegalArgumentException();
        return p;
    }

    private String decodeId(NsdServiceInfo s) {
        return ClippWire.hex(Arrays.copyOfRange(decode(s), 12, 28));
    }

    private void found(NsdServiceInfo s) {
        try {
            if (s.getNetwork() != null && !s.getNetwork().equals(network)) return;
            byte[] packet = decode(s), idBytes = Arrays.copyOfRange(packet, 12, 28);
            String id = ClippWire.hex(idBytes);
            InetAddress address = s.getHost();
            for (InetAddress candidate : s.getHostAddresses()) {
                if (candidate instanceof Inet4Address) {
                    address = candidate;
                    break;
                }
            }
            if (Arrays.equals(idBytes, host)
                    || blocked.contains(id)
                    || address == null
                    || s.getPort() < 1024
                    || s.getPort() > 65535) return;
            synchronized (peers) {
                Peer peer = peers.get(id);
                if (peer == null) {
                    if (peers.size() >= 5) return;
                    peer = new Peer(id, ClippWire.name(packet, 36, 64));
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
                if (candidates.size() < 32) candidates.put(s.getServiceName(), s);
                if (changed) {
                    peer.attempt = 0;
                    schedule(peer, true);
                }
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        try {
            listener.close();
        } catch (IOException ignored) {
        }
        for (Socket s : sockets) closeSocket(s);
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
        main.post(
                () -> {
                    if (discovery != null)
                        try {
                            nsd.stopServiceDiscovery(discovery);
                        } catch (Exception ignored) {
                        }
                    if (registration != null)
                        try {
                            nsd.unregisterService(registration);
                        } catch (Exception ignored) {
                        }
                });
        Arrays.fill(root, (byte) 0);
        Arrays.fill(mdnsKey, (byte) 0);
        latest = null;
    }
}
