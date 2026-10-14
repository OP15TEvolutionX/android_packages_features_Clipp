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
import android.webkit.MimeTypeMap;

import org.evolution.clipp.ClippContract;
import org.evolution.clipp.ClippPayload;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** Native clipboard bridge, event-driven discovery, and deep-Doze network suspension. */
public final class ClippEngine implements AutoCloseable {
    private final Context context;
    private final ClipboardManager clipboard;
    private final ConnectivityManager connectivity;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private volatile ClippTransport transport;
    private volatile boolean closed, enabled;
    private volatile boolean showPreview = true;
    private volatile int generation;
    private JSONObject config = new JSONObject();
    private String runtimeKey = "";
    private volatile String current = "", publishedImage = "";
    private ClippWire.Item localItem;
    private volatile ClippPayload deferred;
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
    private final ConnectivityManager.NetworkCallback networks =
            new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network n) {
                    reload();
                }

                @Override
                public void onLost(Network n) {
                    reload();
                }

                @Override
                public void onLinkPropertiesChanged(Network n, LinkProperties p) {
                    reload();
                }
            };
    private final BroadcastReceiver screen =
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context c, Intent i) {
                    if (context.getSystemService(PowerManager.class).isDeviceIdleMode()) {
                        // Do not wait behind image decoding or file I/O on the worker.
                        synchronized (networkLifecycle) {
                            enabled = false;
                            generation++;
                            ClippTransport old = transport;
                            transport = null;
                            if (old != null) old.close();
                        }
                    }
                    enqueue(
                            () -> {
                                if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(
                                        i.getAction())) {
                                    runtimeKey = "";
                                }
                                reloadOnWorker();
                                if (Intent.ACTION_USER_PRESENT.equals(i.getAction())) {
                                    ClippPayload pending = deferred;
                                    if (enabled && pending != null) {
                                        try {
                                            apply(pending, generation, true);
                                        } catch (Exception error) {
                                            android.util.Log.w(
                                                    "ClippEngine",
                                                    "Deferred clipboard update failed",
                                                    error);
                                        }
                                    }
                                }
                            });
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
        IntentFilter filter = new IntentFilter();
        filter.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        filter.addAction(Intent.ACTION_USER_PRESENT);
        filter.addAction(Intent.ACTION_USER_UNLOCKED);
        // USER_PRESENT is emitted by SystemUI as an implicit broadcast. Android filters
        // non-exported receivers even for the same app UID. All actions here are protected.
        context.registerReceiver(screen, filter, Context.RECEIVER_EXPORTED);
        reload();
    }

    private void enqueue(Runnable task) {
        if (!closed)
            try {
                worker.execute(task);
            } catch (RejectedExecutionException ignored) {
            }
    }

    private void status(String id, String state) {
        try {
            ClippContract.status(context.getContentResolver(), id, state);
        } catch (Exception ignored) {
        }
    }

    private void reload() {
        enqueue(this::reloadOnWorker);
    }

    /** Configuration and clipboard state are confined to the worker thread. */
    private void reloadOnWorker() {
        try {
            JSONObject next = ClippContract.read(context.getContentResolver());
            showPreview = next.optBoolean("showPreview", true);
            // Presentation changes must not restart peer connections.
            JSONObject connectionConfig = new JSONObject(next.toString());
            connectionConfig.remove("showPreview");
            config = next;
            Network wifi = null;
            for (Network n : connectivity.getAllNetworks()) {
                NetworkCapabilities caps = connectivity.getNetworkCapabilities(n);
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    wifi = n;
                    break;
                }
            }
            boolean active =
                    next.optBoolean("enabled")
                            && context.getSystemService(UserManager.class).isUserUnlocked()
                            && !context.getSystemService(PowerManager.class).isDeviceIdleMode();
            String key =
                    connectionConfig.toString()
                            + ":"
                            + wifi
                            + ":"
                            + (wifi == null ? "" : connectivity.getLinkProperties(wifi))
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
            LinkProperties props = connectivity.getLinkProperties(wifi);
            java.net.InetAddress address = null;
            if (props != null)
                for (LinkAddress a : props.getLinkAddresses())
                    if (a.getAddress() instanceof java.net.Inet4Address) {
                        address = a.getAddress();
                        break;
                    }
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
                                android.os.Build.MODEL,
                                ClippWire.MAX_IMAGE_BYTES,
                                transportEvents(epoch));
            } finally {
                Arrays.fill(root, (byte) 0);
            }
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
            android.util.Log.w("ClippEngine", "Clipboard operation failed", e);
        }
    }

    private ClippTransport.Events transportEvents(int epoch) {
        return new ClippTransport.Events() {
            public void state(String id, String name, String state) {
                if (!closed && epoch == generation && !id.equals("network"))
                    try {
                        status(
                                id,
                                new JSONObject().put("name", name).put("state", state).toString());
                    } catch (Exception ignored) {
                    }
            }

            public void receive(ClippWire.Item item) {
                if (closed) return;
                final long revision = localRevision.get();
                try {
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

    private static byte[] parseHost(String s) {
        if (!s.matches("[a-f0-9]{32}")) throw new IllegalArgumentException();
        byte[] id = new byte[16];
        for (int i = 0; i < 16; i++)
            id[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return id;
    }

    private void receiveRemote(ClippWire.Item wire, int epoch) {
        try {
            if ((wire.flags & (ClippWire.FLAG_PRIVATE | ClippWire.FLAG_REPLAY)) != 0
                    || seen.containsKey(wire.event)) return;
            seen.put(wire.event, true);
            while (seen.size() > 256) seen.remove(seen.keySet().iterator().next());
            ClippPayload item;
            if (wire.format == ClippWire.TEXT) {
                if (wire.data.length > 1024 * 1024) return;
                String text =
                        StandardCharsets.UTF_8
                                .newDecoder()
                                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                                .decode(java.nio.ByteBuffer.wrap(wire.data))
                                .toString();
                // Desktop clipboard capture includes a C-string terminator in the wire data.
                if (text.endsWith("\u0000")) text = text.substring(0, text.length() - 1);
                item = ClippPayload.text(text);
            } else if (wire.format == ClippWire.PNG || wire.format == ClippWire.JPEG) {
                if (wire.data.length > ClippWire.MAX_IMAGE_BYTES) return;
                BitmapFactory.Options info = new BitmapFactory.Options();
                info.inJustDecodeBounds = true;
                BitmapFactory.decodeByteArray(wire.data, 0, wire.data.length, info);
                if (info.outWidth <= 0
                        || info.outHeight <= 0
                        || (long) info.outWidth * info.outHeight > 32000000) return;
                String mime = wire.format == ClippWire.PNG ? "image/png" : "image/jpeg";
                if (!mime.equals(info.outMimeType)) return;
                item =
                        ClippPayload.image(
                                wire.data,
                                mime,
                                "clipp." + (wire.format == ClippWire.PNG ? "png" : "jpg"));
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
                if ((wire.flags & ClippWire.FLAG_RELAY) != 0) active.publish(localItem);
            }
            // Ordinary mesh packets are already delivered to all peers. Do not relay them again.
        } catch (Exception e) {
            android.util.Log.w("ClippEngine", "Remote clipboard rejected", e);
        }
    }

    private void localChanged() {
        if (closed) return;
        // Disabled/paused sync must not read clipboard contents in the background.
        if (!enabled) {
            if (config.optBoolean("enabled")) {
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
        if (extras != null && extras.getBoolean("org.evolution.clipp.received")) return;
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
                        ClipData.Item first = clip.getItemAt(0);
                        Uri uri = first.getUri();
                        ClippPayload item;
                        int format;
                        byte[] data;
                        if (uri != null) {
                            String mime = context.getContentResolver().getType(uri);
                            if (mime == null || !mime.startsWith("image/")) return;
                            try (InputStream in =
                                    context.getContentResolver().openInputStream(uri)) {
                                data = bounded(in, ClippWire.MAX_IMAGE_BYTES);
                            }
                            BitmapFactory.Options info = new BitmapFactory.Options();
                            info.inJustDecodeBounds = true;
                            BitmapFactory.decodeByteArray(data, 0, data.length, info);
                            if (info.outWidth <= 0
                                    || info.outHeight <= 0
                                    || (long) info.outWidth * info.outHeight > 32000000) return;
                            if (!"image/png".equals(info.outMimeType)
                                    && !"image/jpeg".equals(info.outMimeType)) {
                                Bitmap bitmap = BitmapFactory.decodeByteArray(data, 0, data.length);
                                if (bitmap == null) return;
                                try {
                                    LimitedOutput out =
                                            new LimitedOutput(ClippWire.MAX_IMAGE_BYTES);
                                    if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out))
                                        return;
                                    data = out.toByteArray();
                                    mime = "image/png";
                                } finally {
                                    bitmap.recycle();
                                }
                            } else mime = info.outMimeType;
                            format = "image/png".equals(mime) ? ClippWire.PNG : ClippWire.JPEG;
                            item =
                                    ClippPayload.image(
                                            data,
                                            mime,
                                            "clipp." + (format == ClippWire.PNG ? "png" : "jpg"));
                        } else {
                            if (first.getText() == null) return;
                            String text =
                                    first.getText()
                                            .toString()
                                            .replace("\r\n", "\n")
                                            .replace('\r', '\n');
                            data = ClippWire.utf8(text);
                            if (data.length > 1024 * 1024) return;
                            format = ClippWire.TEXT;
                            item = ClippPayload.text(text);
                        }
                        if (item.key.equals(current)) return;
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
                        seen.put(localItem.event, true);
                        while (seen.size() > 256) seen.remove(seen.keySet().iterator().next());
                        ClippTransport active = transport;
                        if (active != null) active.publish(localItem);
                    } catch (Exception e) {
                        android.util.Log.w("ClippEngine", "Clipboard operation failed", e);
                    }
                });
    }

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

    private void apply(ClippPayload item, int epoch, boolean suppressOverlay) throws Exception {
        // USER_PRESENT follows dismissal of the keyguard. Check its visual state rather
        // than the separately updated TrustManager device-lock state.
        if (context.getSystemService(KeyguardManager.class).isKeyguardLocked()) return;
        ClipData clip;
        if (item.image == null) clip = ClipData.newPlainText("Clipp", item.text);
        else {
            File dir = new File(context.getFilesDir(), "Clipp/images");
            if (!dir.isDirectory() && !dir.mkdirs())
                throw new IOException("Image directory unavailable");
            String name = hash(item.image).toLowerCase(Locale.ROOT) + "." + extension(item.mime);
            File file = new File(dir, name);
            File[] files =
                    dir.listFiles(cached -> cached.isFile() && !cached.getName().endsWith(".tmp"));
            long used = 0;
            if (files != null)
                for (File old : files) {
                    if (!old.equals(file)
                            && !old.getName().equals(publishedImage)
                            && System.currentTimeMillis() - old.lastModified()
                                    > 24 * 60 * 60 * 1000L) old.delete();
                    if (old.isFile()) used += old.length();
                }
            if (!file.exists()) {
                if (used + item.image.length > 200L * 1024 * 1024 && files != null) {
                    Arrays.sort(files, Comparator.comparingLong(File::lastModified));
                    for (File old : files) {
                        if (!old.isFile()
                                || old.equals(file)
                                || old.getName().equals(publishedImage)) continue;
                        long size = old.length();
                        if (old.delete()) used -= size;
                        if (used + item.image.length <= 200L * 1024 * 1024) break;
                    }
                }
                if (used + item.image.length > 200L * 1024 * 1024)
                    throw new IOException("Image cache limit exceeded");
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
            Uri uri = Uri.parse("content://" + ClippContract.IMAGE_AUTHORITY + "/" + name);
            clip =
                    new ClipData(
                            new ClipDescription("Clipp", new String[] {item.mime}),
                            new ClipData.Item(uri));
        }
        PersistableBundle marker = new PersistableBundle();
        marker.putBoolean("org.evolution.clipp.received", true);
        if (suppressOverlay || !showPreview)
            marker.putBoolean("com.android.systemui.SUPPRESS_CLIPBOARD_OVERLAY", true);
        clip.getDescription().setExtras(marker);
        long revision = localRevision.get();
        main.post(
                () -> {
                    if (!closed
                            && enabled
                            && epoch == generation
                            && item.key.equals(current)
                            && revision == localRevision.get()) {
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
                            android.util.Log.w("ClippEngine", "Clipboard update failed", e);
                            enqueue(
                                    () -> {
                                        if (!closed
                                                && epoch == generation
                                                && item.key.equals(current)) {
                                            current = "";
                                        }
                                    });
                        }
                    }
                });
    }

    private static String extension(String mime) throws IOException {
        String ext = MimeTypeMap.getSingleton().getExtensionFromMimeType(mime);
        if ("jpeg".equals(ext)) ext = "jpg";
        if (ext != null
                && Arrays.asList("png", "jpg", "gif", "webp", "bmp", "heic", "heif", "avif")
                        .contains(ext)) return ext;
        throw new IOException("Unsupported image encoding");
    }

    private static String optional(JSONObject object, String key) {
        return object.isNull(key) ? "" : object.optString(key);
    }

    static String hash(byte[] bytes) throws Exception {
        return ClippPayload.sha256(bytes);
    }

    @Override
    public void close() {
        synchronized (networkLifecycle) {
            if (closed) return;
            closed = true;
            enabled = false;
            generation++;
            ClippTransport t = transport;
            transport = null;
            if (t != null) t.close();
        }
        worker.shutdownNow();
        clipboard.removePrimaryClipChangedListener(clips);
        connectivity.unregisterNetworkCallback(networks);
        context.getContentResolver().unregisterContentObserver(observer);
        context.unregisterReceiver(screen);
        localItem = null;
        deferred = null;
    }
}
