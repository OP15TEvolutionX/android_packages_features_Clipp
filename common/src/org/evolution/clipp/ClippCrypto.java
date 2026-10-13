// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.clipp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;

/** Small libsodium bridge. All wire strings are UTF-8, never JNI modified UTF-8. */
public final class ClippCrypto {
    static {
        System.loadLibrary("evolution_clipp_jni");
    }

    public static final int ROLE_CLIENT_TO_SERVER = 1;
    public static final int ROLE_SERVER_TO_CLIENT = 2;
    public static final int ROLE_DISCOVERY = 3;
    private static final int ROLE_FINGERPRINT = 4;

    // Operation numbers are the stable JNI ABI; callers use the named methods below.
    private static native byte[] call(int op, byte[] a, byte[] b, byte[] c);

    public static byte[] role(byte[] root, int role) {
        return call(1, root, new byte[] {(byte) role}, null);
    }

    public static byte[] seal(byte[] key, byte[] plaintext) {
        return call(2, key, plaintext, null);
    }

    public static byte[] open(byte[] key, byte[] ciphertext) {
        return call(3, key, ciphertext, null);
    }

    public static byte[] sealWithRole(byte[] root, int role, byte[] plaintext) {
        byte[] key = role(root, role);
        try {
            return seal(key, plaintext);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    public static byte[] openWithRole(byte[] root, int role, byte[] ciphertext) {
        byte[] key = role(root, role);
        try {
            return open(key, ciphertext);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    public static byte[] keyPair() {
        return call(4, null, null, null);
    }

    /** Returns receive key followed by transmit key, as in libsodium crypto_kx. */
    public static byte[] sessionKeys(boolean client, byte[] pair, byte[] remoteKey) {
        return call(client ? 5 : 6, pair, remoteKey, null);
    }

    /** Returns opaque stream state followed by the 24-byte public stream header. */
    public static byte[] initPush(byte[] key) {
        return call(7, key, null, null);
    }

    public static byte[] initPull(byte[] key, byte[] header) {
        return call(8, key, header, null);
    }

    /** Mutates state; the channel must serialize calls for each stream. */
    public static byte[] push(byte[] state, byte[] frame) {
        return call(9, state, frame, null);
    }

    /** Mutates state; only the channel's reader may call this. */
    public static byte[] pull(byte[] state, byte[] frame) {
        return call(10, state, frame, null);
    }

    public static byte[] decompress(byte[] data, int plainSize) {
        return call(11, data, integer(plainSize), null);
    }

    public static byte[] contentHash(byte[] data, int format) {
        return call(12, data, integer(format), null);
    }

    public static byte[] fingerprint(byte[] root) {
        byte[] key = role(root, ROLE_FINGERPRINT);
        try {
            return call(13, key, null, null);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] integer(int value) {
        return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
    }

    public static String canonical(String value) {
        String s = Normalizer.normalize(value, Normalizer.Form.NFC);
        StringBuilder out = new StringBuilder();
        s.codePoints()
                .forEach(
                        cp -> {
                            if (cp == 0x60
                                    || cp == 0xb4
                                    || cp == 0x2bc
                                    || cp == 0x2035
                                    || cp == 0x2018
                                    || cp == 0x2019
                                    || cp == 0x201a
                                    || cp == 0x201b
                                    || cp == 0x2032
                                    || cp == 0xff07) cp = 39;
                            else if (cp == 0x2036
                                    || cp == 0x201c
                                    || cp == 0x201d
                                    || cp == 0x201e
                                    || cp == 0x201f
                                    || cp == 0x2033
                                    || cp == 0xff02) cp = 34;
                            else if (cp == 0xa0
                                    || cp == 0x1680
                                    || cp == 0x202f
                                    || cp == 0x205f
                                    || cp == 0x3000
                                    || (cp >= 0x2000 && cp <= 0x200a)) cp = 32;
                            else if ((cp >= 0x2010 && cp <= 0x2015)
                                    || cp == 0x2212
                                    || cp == 0xfe58
                                    || cp == 0xfe63
                                    || cp == 0xff0d) cp = 45;
                            out.appendCodePoint(cp);
                        });
        return out.toString();
    }

    public static byte[] derive(String group, String password) {
        return call(
                0,
                (canonical(group) + "|" + canonical(password)).getBytes(StandardCharsets.UTF_8),
                null,
                null);
    }

    private ClippCrypto() {}
}
