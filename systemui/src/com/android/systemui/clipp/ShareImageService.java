// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.app.Service;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;
import android.webkit.MimeTypeMap;
import android.widget.Toast;

import com.android.systemui.res.R;

import org.evolution.clipp.ClippBytes;
import org.evolution.clipp.ClippContract;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Short-lived SystemUI service: copy while the sender's URI grant is held, then stop. */
public final class ShareImageService extends Service {
    private static final long MAX_IMAGE_BYTES = ClippWire.MAX_IMAGE_BYTES;
    private static final long MAX_IMAGE_PIXELS = 32_000_000;
    private static final long CACHE_BYTES = 200L * 1024 * 1024;
    private static final long CACHE_AGE_MS = 24L * 60 * 60 * 1000;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        worker.execute(
                () -> {
                    try {
                        if (intent == null
                                || intent.getData() == null
                                || !"content".equals(intent.getData().getScheme())) return;
                        copyImage(intent.getData());
                    } catch (Exception error) {
                        Log.w("ClippShare", "Cannot copy shared image", error);
                        main.post(
                                () ->
                                        Toast.makeText(
                                                        this,
                                                        R.string.clipp_share_failed,
                                                        Toast.LENGTH_SHORT)
                                                .show());
                    } finally {
                        stopSelf(startId);
                    }
                });
        return START_NOT_STICKY;
    }

    private void copyImage(Uri source) throws IOException {
        File directory = new File(getFilesDir(), "Clipp/images");
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("Cannot create image cache");
        }
        File temporary = File.createTempFile("shared-", ".tmp", directory);
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException error) {
            throw new IOException(error);
        }
        try {
            try (InputStream input = getContentResolver().openInputStream(source);
                    FileOutputStream output = new FileOutputStream(temporary)) {
                if (input == null) throw new IOException("Image unavailable");
                byte[] buffer = new byte[16 * 1024];
                long size = 0;
                int count;
                while ((count = input.read(buffer)) != -1) {
                    size += count;
                    if (size > MAX_IMAGE_BYTES) throw new IOException("Image too large");
                    digest.update(buffer, 0, count);
                    output.write(buffer, 0, count);
                }
            }
            BitmapFactory.Options info = new BitmapFactory.Options();
            info.inJustDecodeBounds = true;
            BitmapFactory.decodeFile(temporary.getPath(), info);
            if (info.outWidth <= 0
                    || info.outHeight <= 0
                    || (long) info.outWidth * info.outHeight > MAX_IMAGE_PIXELS
                    || info.outMimeType == null
                    || !info.outMimeType.startsWith("image/")) {
                throw new IOException("Invalid image");
            }
            String extension =
                    MimeTypeMap.getSingleton().getExtensionFromMimeType(info.outMimeType);
            if ("image/jpeg".equals(info.outMimeType)) extension = "jpg";
            if (extension == null
                    || !extension.matches("png|jpg|gif|webp|bmp|heic|heif|avif|wbmp")) {
                throw new IOException("Unsupported image type");
            }
            File image = new File(directory, ClippBytes.hex(digest.digest()) + "." + extension);
            if (!image.exists() && !temporary.renameTo(image))
                throw new IOException("Cannot publish image");
            Uri uri =
                    new Uri.Builder()
                            .scheme("content")
                            .authority(ClippContract.IMAGE_AUTHORITY)
                            .appendPath(image.getName())
                            .build();
            ClipData clip =
                    new ClipData(
                            new ClipDescription(
                                    getString(R.string.clipp_share_copy),
                                    new String[] {info.outMimeType}),
                            new ClipData.Item(uri));
            getSystemService(ClipboardManager.class).setPrimaryClip(clip);
            pruneCache(directory, image);
        } finally {
            temporary.delete();
        }
    }

    private static void pruneCache(File directory, File current) {
        File[] files =
                directory.listFiles(file -> file.isFile() && !file.getName().endsWith(".tmp"));
        if (files == null) return;
        Arrays.sort(files, Comparator.comparingLong(File::lastModified));
        long total = 0;
        for (File file : files) total += file.length();
        long expired = System.currentTimeMillis() - CACHE_AGE_MS;
        for (File file : files) {
            if (file.equals(current)) continue;
            if (file.lastModified() < expired || total > CACHE_BYTES) {
                long size = file.length();
                if (file.delete()) total -= size;
            }
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        worker.shutdown();
        super.onDestroy();
    }
}
