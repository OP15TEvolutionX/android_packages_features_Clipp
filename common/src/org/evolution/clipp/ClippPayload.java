// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.clipp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Clip content as the Android clipboard sees it. {@link #key} identifies the content ("T:" or
 * "I:" plus a SHA-256), so the same text or image is recognized whichever way it came.
 */
public final class ClippPayload {
    public final byte[] image;
    /** {@code text} is the file name for an image; {@code mime} is null for text. */
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
        return ClippBytes.hex(hash);
    }
}
