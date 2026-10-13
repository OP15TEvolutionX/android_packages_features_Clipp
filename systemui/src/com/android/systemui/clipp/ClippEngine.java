// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.app.KeyguardManager;
import android.content.*;
import android.database.ContentObserver;
import android.graphics.*;
import android.net.*;
import android.os.*;
import android.util.Base64;
import android.webkit.MimeTypeMap;

import org.evolution.clipp.*;
import org.json.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** Native clipboard bridge, event-driven discovery, and a five-minute screen-off grace period. */
public final class ClippEngine implements AutoCloseable {
    private final Context context;
    private final ClipboardManager clipboard;
    private final ConnectivityManager connectivity;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private volatile ClippTransport transport;
    private volatile boolean closed, enabled;
    private volatile int generation;
    private JSONObject config = new JSONObject();
    private String runtimeKey = "";
    private volatile String current = "", publishedImage = "";
    private ClippPayload latest;
    private ClippWire.Item localItem;
    private volatile ClippPayload deferred;
    private final AtomicLong localRevision = new AtomicLong();
    private volatile long lastLocalTime;
    private long graceUntil;
    private ScheduledFuture<?> graceTimer;
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
                    enqueue(
                            () -> {
                                String action = i.getAction();
                                if (Intent.ACTION_SCREEN_OFF.equals(action)) {
                                    graceUntil = SystemClock.elapsedRealtime() + 300000;
                                    if (graceTimer != null) graceTimer.cancel(false);
                                    graceTimer =
                                            worker.schedule(
                                                    ClippEngine.this::reload,
                                                    300000,
                                                    TimeUnit.MILLISECONDS);
                                } else if (Intent.ACTION_USER_PRESENT.equals(action)) {
                                    graceUntil = 0;
                                    if (graceTimer != null) graceTimer.cancel(false);
                                    runtimeKey = "";
                                }
                                reload();
                                if (Intent.ACTION_USER_PRESENT.equals(action) && deferred != null)
                                    try {
                                        apply(deferred, generation);
                                    } catch (Exception ignored) {
                                    }
                            });
                }
            };

    public ClippEngine(Context context) {
        this.context = context;
        clipboard = context.getSystemService(ClipboardManager.class);
        connectivity = context.getSystemService(ConnectivityManager.class);
        lastLocalTime = context.getSharedPreferences("clipp_local", 0).getLong("copied", 0);
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
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_SCREEN_ON);
        filter.addAction(Intent.ACTION_USER_PRESENT);
        filter.addAction(Intent.ACTION_USER_UNLOCKED);
        context.registerReceiver(screen, filter, Context.RECEIVER_NOT_EXPORTED);
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
        enqueue(
                () -> {
                    try {
                        JSONObject next = ClippContract.read(context.getContentResolver());
                        Network wifi = null;
                        for (Network n : connectivity.getAllNetworks()) {
                            NetworkCapabilities caps = connectivity.getNetworkCapabilities(n);
                            if (caps != null
                                    && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                                wifi = n;
                                break;
                            }
                        }
                        boolean interactive =
                                context.getSystemService(PowerManager.class).isInteractive();
                        boolean unlocked =
                                !context.getSystemService(KeyguardManager.class).isDeviceLocked();
                        boolean active =
                                next.optBoolean("enabled")
                                        && context.getSystemService(UserManager.class)
                                                .isUserUnlocked()
                                        && ((interactive && unlocked)
                                                || (graceUntil > SystemClock.elapsedRealtime()));
                        String key =
                                next.toString()
                                        + ":"
                                        + wifi
                                        + ":"
                                        + (wifi == null ? "" : connectivity.getLinkProperties(wifi))
                                        + ":"
                                        + active;
                        if (key.equals(runtimeKey)) return;
                        runtimeKey = key;
                        config = next;
                        generation++;
                        enabled = active;
                        ClippTransport old = transport;
                        transport = null;
                        if (old != null) old.close();
                        status("devices", "{}");
                        if (!next.optBoolean("enabled")) {
                            localItem = null;
                            latest = null;
                            deferred = null;
                            current = "";
                        }
                        if (!active || wifi == null) {
                            status("network", active ? "waiting_wifi" : "paused");
                            return;
                        }
                        LinkProperties props = connectivity.getLinkProperties(wifi);
                        java.net.InetAddress address = null;
                        if (props != null)
                            for (LinkAddress a : props.getLinkAddresses())
                                if (a.getAddress() instanceof java.net.Inet4Address) {
                                    address = a.getAddress();
                                    break;
                                }
                        if (address == null) {
                            status("network", "waiting_wifi");
                            return;
                        }
                        byte[] root = Base64.decode(next.getString("root"), Base64.NO_WRAP),
                                host = parseHost(next.getString("hostId"));
                        Set<String> blocked = new HashSet<>();
                        JSONArray list = next.optJSONArray("blocked");
                        if (list != null)
                            for (int i = 0; i < list.length(); i++) blocked.add(list.getString(i));
                        int epoch = generation;
                        ClippTransport t =
                                new ClippTransport(
                                        context,
                                        wifi,
                                        address,
                                        root,
                                        host,
                                        android.os.Build.MODEL,
                                        imageLimit(),
                                        blocked,
                                        new ClippTransport.Events() {
                                            public void state(
                                                    String id, String name, String state) {
                                                if (!closed && epoch == generation)
                                                    try {
                                                        status(
                                                                id,
                                                                id.equals("network")
                                                                        ? state
                                                                        : new JSONObject()
                                                                                .put("name", name)
                                                                                .put("state", state)
                                                                                .toString());
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
                                                                                && epoch
                                                                                        == generation
                                                                                && revision
                                                                                        == localRevision
                                                                                                .get())
                                                                            receiveRemote(
                                                                                    item, epoch);
                                                                    })
                                                            .get(30, TimeUnit.SECONDS);
                                                } catch (Exception ignored) {
                                                }
                                            }
                                        });
                        Arrays.fill(root, (byte) 0);
                        transport = t;
                        if (localItem != null) t.publish(localItem);
                        t.start();
                        if (deferred != null) apply(deferred, epoch);
                    } catch (Exception e) {
                        status("network", "connection_error");
                    }
                });
    }

    private static byte[] parseHost(String s) {
        if (!s.matches("[a-f0-9]{32}")) throw new IllegalArgumentException();
        byte[] id = new byte[16];
        for (int i = 0; i < 16; i++)
            id[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return id;
    }

    private int imageLimit() {
        return Math.max(5, Math.min(50, config.optInt("maxImageMb", 20))) * 1024 * 1024;
    }

    private void receiveRemote(ClippWire.Item wire, int epoch) {
        try {
            if ((wire.flags & 2) != 0 || seen.containsKey(wire.event)) return;
            seen.put(wire.event, true);
            while (seen.size() > 256) seen.remove(seen.keySet().iterator().next());
            // A reconnect supplies only the latest item. Never overwrite a newer local copy with
            // catch-up.
            if ((wire.flags & 1) != 0
                    && (wire.timestamp <= lastLocalTime || wire.timestamp <= remoteTime)) return;
            ClippPayload item;
            if (wire.format == ClippWire.TEXT && config.optBoolean("text", true)) {
                if (wire.data.length > 1024 * 1024) return;
                String text =
                        StandardCharsets.UTF_8
                                .newDecoder()
                                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                                .decode(java.nio.ByteBuffer.wrap(wire.data))
                                .toString();
                item = ClippPayload.text(text);
            } else if ((wire.format == ClippWire.PNG || wire.format == ClippWire.JPEG)
                    && config.optBoolean("images", true)) {
                if (wire.data.length > imageLimit()) return;
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
            if (!item.key.equals(current)) {
                current = item.key;
                latest = item;
                apply(item, epoch);
            }
            remoteTime =
                    Math.max(
                            remoteTime,
                            Math.min(wire.timestamp, System.currentTimeMillis() + 300000));
            localItem = wire.withFlags(wire.flags & ~5);
            ClippTransport active = transport;
            if (active != null) {
                active.remember(localItem);
                if ((wire.flags & 4) != 0) active.publish(localItem);
            }
            // Ordinary mesh packets are already delivered to all peers. Do not relay them again.
        } catch (Exception e) {
            status("network", "connection_error");
        }
    }

    private long remoteTime;

    private void localChanged() {
        if (closed) return;
        // Disabled/paused sync must not read clipboard contents in the background.
        if (!enabled) {
            if (config.optBoolean("enabled")) {
                localRevision.incrementAndGet();
                deferred = null;
                lastLocalTime = System.currentTimeMillis();
                context.getSharedPreferences("clipp_local", 0)
                        .edit()
                        .putLong("copied", lastLocalTime)
                        .apply();
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
        PersistableBundle extras = clip.getDescription().getExtras();
        if (extras != null && extras.getBoolean("org.evolution.clipp.received")) return;
        localRevision.incrementAndGet();
        deferred = null;
        lastLocalTime = System.currentTimeMillis();
        context.getSharedPreferences("clipp_local", 0)
                .edit()
                .putLong("copied", lastLocalTime)
                .apply();
        if (!enabled || (extras != null && extras.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE)))
            return;
        int epoch = generation;
        long copied = lastLocalTime;
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
                            if (!config.optBoolean("images", true)
                                    || mime == null
                                    || !mime.startsWith("image/")) return;
                            try (InputStream in =
                                    context.getContentResolver().openInputStream(uri)) {
                                data = bounded(in, imageLimit());
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
                                    LimitedOutput out = new LimitedOutput(imageLimit());
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
                            if (!config.optBoolean("text", true) || first.getText() == null) return;
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
                        current = item.key;
                        latest = item;
                        SharedPreferences prefs = context.getSharedPreferences("clipp_local", 0);
                        long sequence = prefs.getLong("sequence", 0) + 1;
                        if (!prefs.edit().putLong("sequence", sequence).commit()) return;
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
                        status("network", "connection_error");
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

    private void apply(ClippPayload item, int epoch) throws Exception {
        ClipData clip;
        if (item.image == null) clip = ClipData.newPlainText("Clipp", item.text);
        else {
            File dir = new File(context.getFilesDir(), "Clipp/images");
            if (!dir.isDirectory() && !dir.mkdirs())
                throw new IOException("Image directory unavailable");
            String name = hash(item.image).toLowerCase(Locale.ROOT) + "." + extension(item.mime);
            File file = new File(dir, name);
            File[] files = dir.listFiles();
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
        clip.getDescription().setExtras(marker);
        long revision = localRevision.get();
        main.post(
                () -> {
                    if (!closed
                            && enabled
                            && epoch == generation
                            && item.key.equals(current)
                            && revision == localRevision.get()) {
                        if (context.getSystemService(KeyguardManager.class).isDeviceLocked()) {
                            deferred = item;
                            return;
                        }
                        try {
                            clipboard.setPrimaryClip(clip);
                            deferred = null;
                            publishedImage =
                                    item.image == null
                                            ? ""
                                            : clip.getItemAt(0).getUri().getLastPathSegment();
                        } catch (RuntimeException e) {
                            enqueue(
                                    () -> {
                                        if (!closed
                                                && epoch == generation
                                                && item.key.equals(current)) {
                                            current = "";
                                            status("network", "connection_error");
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
        closed = true;
        enabled = false;
        generation++;
        ClippTransport t = transport;
        transport = null;
        if (t != null) t.close();
        if (graceTimer != null) graceTimer.cancel(false);
        worker.shutdownNow();
        clipboard.removePrimaryClipChangedListener(clips);
        connectivity.unregisterNetworkCallback(networks);
        context.getContentResolver().unregisterContentObserver(observer);
        context.unregisterReceiver(screen);
        latest = null;
        localItem = null;
        deferred = null;
    }
}
