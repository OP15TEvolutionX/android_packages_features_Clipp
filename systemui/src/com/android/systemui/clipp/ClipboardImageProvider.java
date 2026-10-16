// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;

import java.io.File;
import java.io.FileNotFoundException;

/** Read-only files granted by ClipboardService; no broad external storage access. */
public final class ClipboardImageProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    private File imageFile(Uri uri) throws FileNotFoundException {
        String name = uri.getLastPathSegment();
        if (name == null
                || !name.matches("[a-f0-9]{64}\\.(png|jpg|gif|webp|bmp|heic|heif|avif|wbmp)"))
            throw new FileNotFoundException("Invalid image URI");
        File f = new File(new File(getContext().getFilesDir(), "Clipp/images"), name);
        if (!f.isFile()) throw new FileNotFoundException("Image unavailable");
        return f;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("Read only");
        return ParcelFileDescriptor.open(imageFile(uri), ParcelFileDescriptor.MODE_READ_ONLY);
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
    public Cursor query(
            Uri uri,
            String[] projection,
            String selection,
            String[] selectionArgs,
            String sortOrder) {
        try {
            File image = imageFile(uri);
            String[] columns =
                    projection == null
                            ? new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}
                            : projection;
            MatrixCursor cursor = new MatrixCursor(columns);
            Object[] row = new Object[columns.length];
            for (int i = 0; i < columns.length; i++) {
                if (OpenableColumns.DISPLAY_NAME.equals(columns[i])) row[i] = image.getName();
                if (OpenableColumns.SIZE.equals(columns[i])) row[i] = image.length();
            }
            cursor.addRow(row);
            return cursor;
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }
}
