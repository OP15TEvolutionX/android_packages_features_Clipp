// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.app.KeyguardManager;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.database.ContentObserver;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.PowerManager;
import android.os.UserManager;
import android.util.Base64;
import android.util.Log;
import android.webkit.MimeTypeMap;

import org.evolution.clipp.ClippContract;
import org.evolution.clipp.ClippPayload;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Clipboard bridge for one user, owned by {@link ClippStartable}.
 *
 * <p>Copies made on the phone are published to Clipp peers, and clips received from peers are
 * written to the phone's clipboard. A {@link ClippTransport} only exists while sync is enabled,
 * the user is unlocked, Wi-Fi has an IPv4 address and the device is not in deep Doze. Any change
 * to these conditions (or to the connection settings) closes it and builds a new one.
 *
 * <p>Threads: settings, clipboard state and image files are handled on {@link #worker}; clipboard
 * writes happen on the main thread. {@link #generation} grows with every transport change, so
 * work started for an old transport can tell it is stale and drop out.
 */
public final class ClippEngine implements AutoCloseable {
    private static final String TAG = "ClippEngine";

    /** Received images are cached here and served by {@link ClipboardImageProvider}. */
    static final String IMAGE_DIR = "Clipp/images";
    static final long MAX_IMAGE_PIXELS = 32_000_000;
    static final long IMAGE_CACHE_BYTES = 200L * 1024 * 1024;
    static final long IMAGE_CACHE_AGE_MS = 24L * 60 * 60 * 1000;

    /** Marks clips written by Clipp so they are not sent back to the peers. */
    private static final String EXTRA_RECEIVED = "org.evolution.clipp.received";
    /** Asks SystemUI not to show the clipboard overlay for this clip. */
    private static final String EXTRA_SUPPRESS_OVERLAY =
            "com.android.systemui.SUPPRESS_CLIPBOARD_OVERLAY";

    /** Wi-Fi and VPN callbacks come in bursts; one reload after they settle is enough. */
    private static final long NETWORK_DEBOUNCE_MS = 1000;
    /** Event IDs remembered to drop duplicate deliveries of the same copy. */
    private static final int SEEN_EVENTS = 256;

    private final Context context;
    private final ClipboardManager clipboard;
    private final ConnectivityManager connectivity;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private volatile ClippTransport transport;
    /** {@code enabled} is true while a transport may run, not just when the switch is on. */
    private volatile boolean closed, enabled;
    private volatile boolean showImagePreview = true;
    private volatile boolean showTextPreview = true;
    private volatile int generation;
    private JSONObject config = new JSONObject();
    /** Everything that needs a new transport when it changes; see {@link #reloadOnWorker}. */
    private String runtimeKey = "";
    /** Content key of the clip last sent or received, so the same content isn't sent twice. */
    private volatile String current = "";
    /** Cached image the clipboard points at now; never pruned from the cache. */
    private volatile String publishedImage = "";
    /** Latest clip; a new transport offers it to peers that ask for a sync. */
    private ClippWire.Item localItem;
    /** Received clip not yet written because the screen was locked; retried on unlock. */
    private volatile ClippPayload deferred;
    /** Grows with every local copy, so an older remote clip doesn't overwrite a newer copy. */
    private final AtomicLong localRevision = new AtomicLong();
    private final Object networkLifecycle = new Object();
    private final LinkedHashMap<String, Boolean> seen = new LinkedHashMap<>();
    private final ClipboardManager.OnPrimaryClipChangedListener clips = this::localChanged;
    private final ContentObserver observer =
            new ContentObserver(main) {
                @Override
                public void onChange(boolean self) {
                    reload();
                }
            };
    private ScheduledFuture<?> pendingReload;
    private final Object reloadLock = new Object();
    // A callback object can be registered only once, hence one for each request.
    private final ConnectivityManager.NetworkCallback networks = debouncedReload();
    private final ConnectivityManager.NetworkCallback vpnNetworks = debouncedReload();
    private final BroadcastReceiver screen =
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context c, Intent i) {
                    onPowerOrUnlock(i);
                }
            };

    public ClippEngine(Context context) {
        this.context = context;
        clipboard = context.getSystemService(ClipboardManager.class);
        connectivity = context.getSystemService(ConnectivityManager.class);
    }

    public void start() {
        context.getContentResolver().registerContentObserver(ClippContract.CONFIG, false, observer);
        clipboard.addPrimaryClipChangedListener(clips);
        connectivity.registerNetworkCallback(
                new NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build(),
                networks);
        try {
            connectivity.registerNetworkCallback(
                    new NetworkRequest.Builder()
                            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                            .build(),
                    vpnNetworks);
        } catch (Exception e) {
            Log.w(TAG, "Failed to register VPN network callback", e);
        }
        IntentFilter filter = new IntentFilter();
        filter.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        filter.addAction(Intent.ACTION_USER_PRESENT);
        filter.addAction(Intent.ACTION_USER_UNLOCKED);
        // USER_PRESENT is emitted by SystemUI as an implicit broadcast. Android filters
        // non-exported receivers even for the same app UID. All actions here are protected.
        context.registerReceiver(screen, filter, Context.RECEIVER_EXPORTED);
        reload();
    }

    private ConnectivityManager.NetworkCallback debouncedReload() {
        return new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network n) {
                reloadDebounced();
            }

            @Override
            public void onLost(Network n) {
                reloadDebounced();
            }

            @Override
            public void onCapabilitiesChanged(Network n, NetworkCapabilities c) {
                reloadDebounced();
            }

            @Override
            public void onLinkPropertiesChanged(Network n, LinkProperties p) {
                reloadDebounced();
            }
        };
    }

    /** Doze changes and unlocks; runs on the main thread. */
    private void onPowerOrUnlock(Intent intent) {
        if (context.getSystemService(PowerManager.class).isDeviceIdleMode()) {
            // Close the sockets right away instead of waiting behind image work on the worker.
            synchronized (networkLifecycle) {
                stopTransport();
            }
        }
        enqueue(
                () -> {
                    if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(intent.getAction())) {
                        // Leaving Doze must rebuild the transport even if nothing else changed.
                        runtimeKey = "";
                    }
                    reloadOnWorker();
                    if (Intent.ACTION_USER_PRESENT.equals(intent.getAction())) {
                        applyDeferred();
                    }
                });
    }

    /** Writes the clip that arrived while the screen was locked. */
    private void applyDeferred() {
        ClippPayload pending = deferred;
        if (!enabled || pending == null) return;
        try {
            apply(pending, generation, true);
        } catch (Exception error) {
            Log.w(TAG, "Deferred clipboard update failed", error);
        }
    }

    /** Must hold {@link #networkLifecycle}. */
    private void stopTransport() {
        enabled = false;
        generation++;
        ClippTransport old = transport;
        transport = null;
        if (old != null) old.close();
    }

    private void enqueue(Runnable task) {
        if (closed) return;
        try {
            worker.execute(task);
        } catch (RejectedExecutionException ignored) {
            // Closed concurrently.
        }
    }

    /** Publishes a state for the Settings screen; Settings may be gone, which is fine. */
    private void status(String id, String state) {
        try {
            ClippContract.status(context.getContentResolver(), id, state);
        } catch (Exception ignored) {
        }
    }

    private void reload() {
        synchronized (reloadLock) {
            if (pendingReload != null && !pendingReload.isDone()) {
                pendingReload.cancel(false);
            }
        }
        enqueue(this::reloadOnWorker);
    }

    private void reloadDebounced() {
        if (closed) return;
        synchronized (reloadLock) {
            if (pendingReload != null && !pendingReload.isDone()) {
                pendingReload.cancel(false);
            }
            try {
                pendingReload =
                        worker.schedule(
                                this::reloadOnWorker, NETWORK_DEBOUNCE_MS, TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException ignored) {
            }
        }
    }

    /**
     * Reads the settings and the networks, then rebuilds the transport if anything it depends on
     * changed. Configuration and clipboard state are confined to the worker thread.
     */
    private void reloadOnWorker() {
        try {
            JSONObject next = ClippContract.read(context.getContentResolver());
            // The single "showPreview" switch predates the split and seeds both.
            boolean legacyPreview = next.optBoolean("showPreview", true);
            showImagePreview = next.optBoolean("showImagePreview", legacyPreview);
            showTextPreview = next.optBoolean("showTextPreview", legacyPreview);
            // Presentation changes must not restart peer connections.
            JSONObject connectionConfig = new JSONObject(next.toString());
            connectionConfig.remove("showPreview");
            connectionConfig.remove("showImagePreview");
            connectionConfig.remove("showTextPreview");
            config = next;
            Network wifi = null;
            Network vpn = null;
            for (Network n : connectivity.getAllNetworks()) {
                NetworkCapabilities caps = connectivity.getNetworkCapabilities(n);
                if (caps != null) {
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        wifi = n;
                    }
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        vpn = n;
                    }
                }
            }
            boolean active =
                    next.optBoolean("enabled")
                            && context.getSystemService(UserManager.class).isUserUnlocked()
                            && !context.getSystemService(PowerManager.class).isDeviceIdleMode();
            // A VPN is part of the key because it can change how local addresses are routed.
            String key =
                    connectionConfig.toString()
                            + ":"
                            + wifi
                            + ":"
                            + (wifi == null ? "" : connectivity.getLinkProperties(wifi))
                            + ":"
                            + vpn
                            + ":"
                            + (vpn == null ? "" : connectivity.getLinkProperties(vpn))
                            + ":"
                            + active;
            if (key.equals(runtimeKey)) return;
            runtimeKey = key;
            generation++;
            enabled = active;
            ClippTransport old = transport;
            transport = null;
            if (old != null) old.close();
            status("devices", "{}");
            if (!next.optBoolean("enabled")) {
                localItem = null;
                deferred = null;
                current = "";
            }
            if (!active || wifi == null) return;
            InetAddress address = ipv4(connectivity.getLinkProperties(wifi));
            if (address == null) return;
            byte[] host = parseHost(next.getString("hostId"));
            int epoch = generation;
            byte[] root = Base64.decode(next.getString("root"), Base64.NO_WRAP);
            ClippTransport t;
            try {
                t =
                        new ClippTransport(
                                context,
                                wifi,
                                address,
                                root,
                                host,
                                Build.MODEL,
                                ClippWire.MAX_IMAGE_BYTES,
                                transportEvents(epoch));
            } finally {
                Arrays.fill(root, (byte) 0);
            }
            // Doze or close() may have run on the main thread while the transport was built.
            synchronized (networkLifecycle) {
                if (epoch != generation
                        || closed
                        || context.getSystemService(PowerManager.class).isDeviceIdleMode()) {
                    enabled = false;
                    t.close();
                    runtimeKey = "";
                    return;
                }
                transport = t;
                if (localItem != null) t.publish(localItem);
                t.start();
            }
        } catch (Exception e) {
            Log.w(TAG, "Clipboard operation failed", e);
        }
    }

    private static InetAddress ipv4(LinkProperties props) {
        if (props == null) return null;
        for (LinkAddress a : props.getLinkAddresses()) {
            if (a.getAddress() instanceof Inet4Address) return a.getAddress();
        }
        return null;
    }

    private ClippTransport.Events transportEvents(int epoch) {
        return new ClippTransport.Events() {
            public void state(String id, String name, String state) {
                if (closed || epoch != generation || id.equals("network")) return;
                try {
                    status(id, new JSONObject().put("name", name).put("state", state).toString());
                } catch (Exception ignored) {
                }
            }

            public void receive(ClippWire.Item item) {
                if (closed) return;
                final long revision = localRevision.get();
                try {
                    // Waiting here makes the peer's reader thread the backpressure: it reads
                    // the next frame only after this one is on the clipboard.
                    worker.submit(
                                    () -> {
                                        if (!closed
                                                && enabled
                                                && epoch == generation
                                                && revision == localRevision.get())
                                            receiveRemote(item, epoch);
                                    })
                            .get(30, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                }
            }
        };
    }

    /** Parses the 32-digit lowercase hex host ID kept in the settings. */
    private static byte[] parseHost(String s) {
        if (!s.matches("[a-f0-9]{32}")) throw new IllegalArgumentException();
        byte[] id = new byte[16];
        for (int i = 0; i < 16; i++)
            id[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return id;
    }

    /** Returns false if the event was already handled. */
    private boolean markSeen(String event) {
        if (seen.containsKey(event)) return false;
        seen.put(event, true);
        while (seen.size() > SEEN_EVENTS) seen.remove(seen.keySet().iterator().next());
        return true;
    }

    /** Bounds of a PNG or other image, or null if it can't be decoded or is too large. */
    static BitmapFactory.Options imageBounds(byte[] data) {
        BitmapFactory.Options info = new BitmapFactory.Options();
        info.inJustDecodeBounds = true;
        BitmapFactory.decodeByteArray(data, 0, data.length, info);
        if (info.outWidth <= 0
                || info.outHeight <= 0
                || (long) info.outWidth * info.outHeight > MAX_IMAGE_PIXELS) return null;
        return info;
    }

    /** Checks a clip from a peer and writes it to the clipboard. Runs on the worker. */
    private void receiveRemote(ClippWire.Item wire, int epoch) {
        try {
            if ((wire.flags & (ClippWire.FLAG_PRIVATE | ClippWire.FLAG_REPLAY)) != 0
                    || !markSeen(wire.event)) return;
            ClippPayload item;
            if (wire.format == ClippWire.TEXT) {
                if (wire.data.length > ClippWire.MAX_TEXT_BYTES) return;
                String text =
                        StandardCharsets.UTF_8
                                .newDecoder()
                                .onMalformedInput(CodingErrorAction.REPORT)
                                .decode(ByteBuffer.wrap(wire.data))
                                .toString();
                // Desktop clipboard capture includes a C-string terminator in the wire data.
                if (text.endsWith("\u0000")) text = text.substring(0, text.length() - 1);
                item = ClippPayload.text(text);
            } else if (wire.format == ClippWire.PNG || wire.format == ClippWire.JPEG) {
                if (wire.data.length > ClippWire.MAX_IMAGE_BYTES) return;
                BitmapFactory.Options info = imageBounds(wire.data);
                String mime = wire.format == ClippWire.PNG ? "image/png" : "image/jpeg";
                // The declared format must match the actual bytes.
                if (info == null || !mime.equals(info.outMimeType)) return;
                item = ClippPayload.image(wire.data, mime, imageName(wire.format));
            } else return;
            // Event IDs suppress delivery duplicates. Equal content can still be a new copy,
            // especially when the previous clipboard write was postponed or cancelled.
            current = item.key;
            // Retain before posting: lock/Doze may cancel the main-thread write.
            deferred = item;
            apply(item, epoch, false);
            localItem =
                    wire.withFlags(wire.flags & ~(ClippWire.FLAG_REPLAY | ClippWire.FLAG_RELAY));
            ClippTransport active = transport;
            if (active != null) {
                active.remember(localItem);
                // Only a clip that asks for it is forwarded; mesh peers already have the rest.
                if ((wire.flags & ClippWire.FLAG_RELAY) != 0) active.publish(localItem);
            }
        } catch (Exception e) {
            Log.w(TAG, "Remote clipboard rejected", e);
        }
    }

    private static String imageName(int format) {
        return "clipp." + (format == ClippWire.PNG ? "png" : "jpg");
    }

    /** Clipboard listener, main thread: reads the new clip and sends it on the worker. */
    private void localChanged() {
        if (closed) return;
        // Disabled/paused sync must not read clipboard contents in the background.
        if (!enabled) {
            if (config.optBoolean("enabled")) {
                // Paused (locked or Doze): this copy is newer than any clip still waiting.
                localRevision.incrementAndGet();
                deferred = null;
            }
            return;
        }
        ClipData clip;
        try {
            clip = clipboard.getPrimaryClip();
        } catch (RuntimeException e) {
            return;
        }
        if (clip == null || clip.getItemCount() == 0) return;
        Uri imageUri = clip.getItemAt(0).getUri();
        publishedImage =
                imageUri != null && ClippContract.IMAGE_AUTHORITY.equals(imageUri.getAuthority())
                        ? imageUri.getLastPathSegment()
                        : "";
        PersistableBundle extras = clip.getDescription().getExtras();
        if (extras != null && extras.getBoolean(EXTRA_RECEIVED)) return;
        localRevision.incrementAndGet();
        deferred = null;
        if (!enabled || (extras != null && extras.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE)))
            return;
        int epoch = generation;
        long copied = System.currentTimeMillis();
        enqueue(
                () -> {
                    if (!enabled || epoch != generation) return;
                    try {
                        publishLocal(clip.getItemAt(0), copied);
                    } catch (Exception e) {
                        Log.w(TAG, "Clipboard operation failed", e);
                    }
                });
    }

    /** Sends a phone clip to the peers. Runs on the worker. */
    private void publishLocal(ClipData.Item first, long copied) throws Exception {
        Uri uri = first.getUri();
        ClippPayload item;
        int format;
        byte[] data;
        if (uri != null) {
            String mime = context.getContentResolver().getType(uri);
            if (mime == null || !mime.startsWith("image/")) return;
            try (InputStream in = context.getContentResolver().openInputStream(uri)) {
                data = bounded(in, ClippWire.MAX_IMAGE_BYTES);
            }
            BitmapFactory.Options info = imageBounds(data);
            if (info == null) return;
            if ("image/png".equals(info.outMimeType) || "image/jpeg".equals(info.outMimeType)) {
                mime = info.outMimeType;
            } else {
                // Clipp only carries PNG and JPEG; anything else is re-encoded as PNG.
                data = toPng(data);
                if (data == null) return;
                mime = "image/png";
            }
            format = "image/png".equals(mime) ? ClippWire.PNG : ClippWire.JPEG;
            item = ClippPayload.image(data, mime, imageName(format));
        } else {
            if (first.getText() == null) return;
            String text = first.getText().toString().replace("\r\n", "\n").replace('\r', '\n');
            data = ClippWire.utf8(text);
            if (data.length > ClippWire.MAX_TEXT_BYTES) return;
            format = ClippWire.TEXT;
            item = ClippPayload.text(text);
        }
        if (item.key.equals(current)) return;
        // Peers order copies from one device by this number, so it must survive restarts.
        SharedPreferences prefs = context.getSharedPreferences("clipp_local", 0);
        long sequence = prefs.getLong("sequence", 0) + 1;
        if (!prefs.edit().putLong("sequence", sequence).commit())
            throw new IOException("Sequence persistence failed");
        current = item.key;
        localItem =
                ClippWire.local(
                        data,
                        format,
                        parseHost(config.getString("hostId")),
                        Build.MODEL,
                        sequence,
                        copied);
        markSeen(localItem.event);
        ClippTransport active = transport;
        if (active != null) active.publish(localItem);
    }

    /** Returns the image as PNG within the size limit, or null if it can't be decoded. */
    private static byte[] toPng(byte[] data) {
        Bitmap bitmap = BitmapFactory.decodeByteArray(data, 0, data.length);
        if (bitmap == null) return null;
        try {
            LimitedOutput out = new LimitedOutput(ClippWire.MAX_IMAGE_BYTES);
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) return null;
            return out.toByteArray();
        } finally {
            bitmap.recycle();
        }
    }

    /** Reads the whole stream, failing once it grows past {@code max} bytes. */
    static byte[] bounded(InputStream in, int max) throws IOException {
        if (in == null) throw new IOException("Input");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[65536];
        int n;
        while ((n = in.read(buffer)) != -1) {
            if (out.size() + n > max) throw new IOException("Limit");
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    /** Stops PNG encoding as soon as the output passes the limit. */
    private static final class LimitedOutput extends ByteArrayOutputStream {
        private final int limit;

        LimitedOutput(int limit) {
            this.limit = limit;
        }

        @Override
        public synchronized void write(byte[] b, int off, int len) {
            if ((long) count + len > limit) throw new IllegalArgumentException("Image limit");
            super.write(b, off, len);
        }

        @Override
        public synchronized void write(int b) {
            if (count >= limit) throw new IllegalArgumentException("Image limit");
            super.write(b);
        }
    }

    /**
     * Writes a received clip to the clipboard on the main thread. Does nothing while the screen
     * is locked; the clip stays in {@link #deferred} until USER_PRESENT.
     */
    private void apply(ClippPayload item, int epoch, boolean suppressOverlay) throws Exception {
        // USER_PRESENT follows dismissal of the keyguard. Check its visual state rather
        // than the separately updated TrustManager device-lock state.
        if (context.getSystemService(KeyguardManager.class).isKeyguardLocked()) return;
        ClipData clip;
        if (item.image == null) {
            clip = ClipData.newPlainText("Clipp", item.text);
        } else {
            Uri uri = cacheImage(item);
            clip =
                    new ClipData(
                            new ClipDescription("Clipp", new String[] {item.mime}),
                            new ClipData.Item(uri));
        }
        PersistableBundle marker = new PersistableBundle();
        marker.putBoolean(EXTRA_RECEIVED, true);
        if (suppressOverlay || !(item.image == null ? showTextPreview : showImagePreview))
            marker.putBoolean(EXTRA_SUPPRESS_OVERLAY, true);
        clip.getDescription().setExtras(marker);
        long revision = localRevision.get();
        main.post(
                () -> {
                    // Skip if the transport changed, a newer clip arrived or the user copied
                    // something in the meantime.
                    if (closed
                            || !enabled
                            || epoch != generation
                            || !item.key.equals(current)
                            || revision != localRevision.get()) return;
                    if (context.getSystemService(KeyguardManager.class).isKeyguardLocked())
                        return;
                    try {
                        clipboard.setPrimaryClip(clip);
                        if (deferred == item) deferred = null;
                        publishedImage =
                                item.image == null
                                        ? ""
                                        : clip.getItemAt(0).getUri().getLastPathSegment();
                    } catch (RuntimeException e) {
                        Log.w(TAG, "Clipboard update failed", e);
                        // Let the same content through again next time.
                        enqueue(
                                () -> {
                                    if (!closed
                                            && epoch == generation
                                            && item.key.equals(current)) {
                                        current = "";
                                    }
                                });
                    }
                });
    }

    /**
     * Stores a received image under its SHA-256 name and returns its provider URI. Files older
     * than a day are removed, and the oldest go first when the cache would pass its size limit.
     * The image on the clipboard now is always kept.
     */
    private Uri cacheImage(ClippPayload item) throws Exception {
        File dir = new File(context.getFilesDir(), IMAGE_DIR);
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("Image directory unavailable");
        }
        String name =
                ClippPayload.sha256(item.image).toLowerCase(Locale.ROOT)
                        + "."
                        + extension(item.mime);
        File file = new File(dir, name);
        File[] files =
                dir.listFiles(cached -> cached.isFile() && !cached.getName().endsWith(".tmp"));
        long used = 0;
        if (files != null)
            for (File old : files) {
                if (!old.equals(file)
                        && !old.getName().equals(publishedImage)
                        && System.currentTimeMillis() - old.lastModified() > IMAGE_CACHE_AGE_MS)
                    old.delete();
                if (old.isFile()) used += old.length();
            }
        if (!file.exists()) {
            if (used + item.image.length > IMAGE_CACHE_BYTES && files != null) {
                Arrays.sort(files, Comparator.comparingLong(File::lastModified));
                for (File old : files) {
                    if (!old.isFile() || old.equals(file) || old.getName().equals(publishedImage))
                        continue;
                    long size = old.length();
                    if (old.delete()) used -= size;
                    if (used + item.image.length <= IMAGE_CACHE_BYTES) break;
                }
            }
            if (used + item.image.length > IMAGE_CACHE_BYTES)
                throw new IOException("Image cache limit exceeded");
            // Write to a temporary file first so the provider never serves half an image.
            File temp = new File(dir, name + ".tmp");
            try (FileOutputStream out = new FileOutputStream(temp)) {
                out.write(item.image);
            } catch (IOException e) {
                temp.delete();
                throw e;
            }
            if (!temp.renameTo(file)) {
                temp.delete();
                throw new IOException("Image publish failed");
            }
        }
        return Uri.parse("content://" + ClippContract.IMAGE_AUTHORITY + "/" + name);
    }

    private static String extension(String mime) throws IOException {
        String ext = MimeTypeMap.getSingleton().getExtensionFromMimeType(mime);
        if ("jpeg".equals(ext)) ext = "jpg";
        if (ext != null
                && List.of("png", "jpg", "gif", "webp", "bmp", "heic", "heif", "avif")
                        .contains(ext)) return ext;
        throw new IOException("Unsupported image encoding");
    }

    @Override
    public void close() {
        synchronized (networkLifecycle) {
            if (closed) return;
            closed = true;
            stopTransport();
        }
        worker.shutdownNow();
        clipboard.removePrimaryClipChangedListener(clips);
        try {
            connectivity.unregisterNetworkCallback(networks);
        } catch (Exception ignored) {
        }
        try {
            connectivity.unregisterNetworkCallback(vpnNetworks);
        } catch (Exception ignored) {
        }
        context.getContentResolver().unregisterContentObserver(observer);
        context.unregisterReceiver(screen);
        localItem = null;
        deferred = null;
    }
}
