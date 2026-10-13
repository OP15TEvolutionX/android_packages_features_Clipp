// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.content.*;
import android.database.*;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;

import java.io.*;

/** Read-only files granted by ClipboardService; no broad external storage access. */
public final class ClipboardImageProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    private File file(Uri uri) throws FileNotFoundException {
        String name = uri.getLastPathSegment();
        if (name == null || !name.matches("[a-f0-9]{64}\\.(png|jpg|gif|webp|bmp|heic|heif|avif)"))
            throw new FileNotFoundException("Invalid image URI");
        File f = new File(new File(getContext().getFilesDir(), "Clipp/images"), name);
        if (!f.isFile()) throw new FileNotFoundException("Image unavailable");
        return f;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("Read only");
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public String getType(Uri uri) {
        String type =
                MimeTypeMap.getSingleton()
                        .getMimeTypeFromExtension(
                                MimeTypeMap.getFileExtensionFromUrl(uri.toString()));
        return type == null ? "image/png" : type;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String s, String[] a, String sort) {
        try {
            File f = file(uri);
            String[] cols =
                    projection == null
                            ? new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}
                            : projection;
            MatrixCursor cursor = new MatrixCursor(cols);
            Object[] row = new Object[cols.length];
            for (int i = 0; i < cols.length; i++) {
                if (OpenableColumns.DISPLAY_NAME.equals(cols[i])) row[i] = f.getName();
                if (OpenableColumns.SIZE.equals(cols[i])) row[i] = f.length();
            }
            cursor.addRow(row);
            return cursor;
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    @Override
    public Uri insert(Uri u, ContentValues v) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri u, String s, String[] a) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri u, ContentValues v, String s, String[] a) {
        throw new UnsupportedOperationException();
    }
}
