// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.clipp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** Android clipboard content identity is separate from Clipp wire metadata. */
public final class ClippPayload {
    public final byte[] image;
    public final String text, mime, key;

    private ClippPayload(byte[] image, String text, String mime, String key) {
        this.image = image;
        this.text = text;
        this.mime = mime;
        this.key = key;
    }

    public static ClippPayload text(String text) throws Exception {
        return new ClippPayload(
                null, text, null, "T:" + sha256(text.getBytes(StandardCharsets.UTF_8)));
    }

    public static ClippPayload image(byte[] image, String mime, String name) throws Exception {
        return new ClippPayload(image, name, mime, "I:" + sha256(image));
    }

    public static String sha256(byte[] bytes) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder s = new StringBuilder();
        for (byte b : hash) s.append(String.format(Locale.ROOT, "%02x", b & 255));
        return s.toString();
    }
}
