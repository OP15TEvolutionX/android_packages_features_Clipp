// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.clipp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;

/**
 * Java side of native/crypto.cpp: libsodium, zstd and xxHash as used by the desktop Clipp.
 * All wire strings are UTF-8, never JNI modified UTF-8.
 *
 * <p>Keys: the group name and password give the root key (Argon2id). Role keys derived from it
 * seal the handshake in each direction, the discovery packet and the fingerprint shown in
 * Settings. Session traffic uses fresh crypto_kx keys and secretstream.
 */
public final class ClippCrypto {
    static {
        System.loadLibrary("evolution_clipp_jni");
    }

    public static final int ROLE_CLIENT_TO_SERVER = 1;
    public static final int ROLE_SERVER_TO_CLIENT = 2;
    public static final int ROLE_DISCOVERY = 3;
    private static final int ROLE_FINGERPRINT = 4;

    // Operation numbers are the JNI ABI and must match enum Op in native/crypto.cpp.
    private static final int OP_DERIVE = 0;
    private static final int OP_ROLE = 1;
    private static final int OP_SEAL = 2;
    private static final int OP_OPEN = 3;
    private static final int OP_KEY_PAIR = 4;
    private static final int OP_CLIENT_KEYS = 5;
    private static final int OP_SERVER_KEYS = 6;
    private static final int OP_INIT_PUSH = 7;
    private static final int OP_INIT_PULL = 8;
    private static final int OP_PUSH = 9;
    private static final int OP_PULL = 10;
    private static final int OP_DECOMPRESS = 11;
    private static final int OP_CONTENT_HASH = 12;
    private static final int OP_FINGERPRINT = 13;

    private static native byte[] call(int op, byte[] a, byte[] b, byte[] c);

    /** Derives the 32-byte key for one {@code ROLE_*}. */
    public static byte[] role(byte[] root, int role) {
        return call(OP_ROLE, root, new byte[] {(byte) role}, null);
    }

    /** crypto_secretbox with a random nonce in front; for messages up to 4 KiB. */
    public static byte[] seal(byte[] key, byte[] plaintext) {
        return call(OP_SEAL, key, plaintext, null);
    }

    public static byte[] open(byte[] key, byte[] ciphertext) {
        return call(OP_OPEN, key, ciphertext, null);
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

    /** crypto_kx key pair: public key followed by secret key. */
    public static byte[] keyPair() {
        return call(OP_KEY_PAIR, null, null, null);
    }

    /** Returns receive key followed by transmit key, as in libsodium crypto_kx. */
    public static byte[] sessionKeys(boolean client, byte[] pair, byte[] remoteKey) {
        return call(client ? OP_CLIENT_KEYS : OP_SERVER_KEYS, pair, remoteKey, null);
    }

    /** Returns opaque stream state followed by the 24-byte public stream header. */
    public static byte[] initPush(byte[] key) {
        return call(OP_INIT_PUSH, key, null, null);
    }

    public static byte[] initPull(byte[] key, byte[] header) {
        return call(OP_INIT_PULL, key, header, null);
    }

    /** Mutates state; the channel must serialize calls for each stream. */
    public static byte[] push(byte[] state, byte[] frame) {
        return call(OP_PUSH, state, frame, null);
    }

    /** Mutates state; only the channel's reader may call this. */
    public static byte[] pull(byte[] state, byte[] frame) {
        return call(OP_PULL, state, frame, null);
    }

    /** zstd; fails unless the result is exactly {@code plainSize} bytes. */
    public static byte[] decompress(byte[] data, int plainSize) {
        return call(OP_DECOMPRESS, data, integer(plainSize), null);
    }

    /** 16-byte XXH3-128 of the clip data, seeded with its format, as in the clip header. */
    public static byte[] contentHash(byte[] data, int format) {
        return call(OP_CONTENT_HASH, data, integer(format), null);
    }

    /** 16 bytes that identify the group without revealing its key; shown in Settings. */
    public static byte[] fingerprint(byte[] root) {
        byte[] key = role(root, ROLE_FINGERPRINT);
        try {
            return call(OP_FINGERPRINT, key, null, null);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] integer(int value) {
        return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
    }

    /**
     * NFC-normalizes the text and replaces typographic quotes, spaces and dashes with their
     * ASCII forms, so a password typed with a "smart" keyboard gives the same key as on desktop.
     */
    public static String canonical(String value) {
        String s = Normalizer.normalize(value, Normalizer.Form.NFC);
        StringBuilder out = new StringBuilder();
        s.codePoints().forEach(cp -> out.appendCodePoint(asciiPunctuation(cp)));
        return out.toString();
    }

    private static int asciiPunctuation(int cp) {
        switch (cp) {
            case 0x60: case 0xb4: case 0x2bc: case 0x2018: case 0x2019: case 0x201a:
            case 0x201b: case 0x2032: case 0x2035: case 0xff07:
                return '\'';
            case 0x201c: case 0x201d: case 0x201e: case 0x201f: case 0x2033: case 0x2036:
            case 0xff02:
                return '"';
            case 0xa0: case 0x1680: case 0x202f: case 0x205f: case 0x3000:
                return ' ';
            case 0x2212: case 0xfe58: case 0xfe63: case 0xff0d:
                return '-';
            default:
                if (cp >= 0x2000 && cp <= 0x200a) return ' ';
                if (cp >= 0x2010 && cp <= 0x2015) return '-';
                return cp;
        }
    }

    /** Root key of a group: Argon2id over "group|password", both canonicalized. */
    public static byte[] derive(String group, String password) {
        return call(
                OP_DERIVE,
                (canonical(group) + "|" + canonical(password)).getBytes(StandardCharsets.UTF_8),
                null,
                null);
    }

    private ClippCrypto() {}
}
