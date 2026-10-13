// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.clipp;

/** Allocation-bounded lowercase hex encoding for device IDs and content digests. */
public final class ClippBytes {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    public static String hex(byte[] bytes) {
        char[] encoded = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            encoded[i * 2] = HEX[value >>> 4];
            encoded[i * 2 + 1] = HEX[value & 0xf];
        }
        return new String(encoded);
    }

    private ClippBytes() {}
}
