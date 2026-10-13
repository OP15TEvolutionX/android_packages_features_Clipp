// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import org.evolution.clipp.ClippBytes;
import org.evolution.clipp.ClippCrypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

/** Compatible Clipp binary framing; authentication precedes every clipboard frame. */
public final class ClippWire {
    public static final int HEADER = 285,
            PNG = 8,
            TEXT = 13,
            JPEG = 0x434a5047,
            MAX_IMAGE_BYTES = 50 * 1024 * 1024,
            MAX_FRAME = MAX_IMAGE_BYTES + HEADER + 21;

    public static final int FLAG_REPLAY = 1;
    public static final int FLAG_PRIVATE = 2;
    public static final int FLAG_RELAY = 4;

    // Packed ClipboardMessage layout from upstream NetworkDefs.h (big endian).
    private static final int FLAGS = 0;
    private static final int TIMESTAMP = 4;
    private static final int HASH_ALGORITHM = 12;
    private static final int HASH = 16;
    private static final int ORIGIN = 80;
    private static final int ORIGIN_NAME = 96;
    private static final int SEQUENCE = 224;
    private static final int EVENT = 232;
    private static final int FORMAT = 264;
    private static final int COMPRESSED = 268;
    private static final int ENCODED_SIZE = 269;
    private static final int PLAIN_SIZE = 277;
    private static final int ID_SIZE = 16;
    private static final int NAME_SIZE = 128;

    // CryptoChannel handshake and libsodium sizes; these are protocol, not Android policy.
    private static final int HANDSHAKE_SIZE = 192;
    private static final int SEALED_HANDSHAKE_SIZE = 232;
    private static final int KEY_SIZE = 32;
    private static final int STREAM_HEADER_SIZE = 24;
    private static final int HANDSHAKE_HOST = 32;
    private static final int HANDSHAKE_CAPS = 48;
    private static final int HANDSHAKE_NAME = 64;

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] integer(int n) {
        return ByteBuffer.allocate(4).putInt(n).array();
    }

    public static byte[] uuid(UUID u) {
        return ByteBuffer.allocate(16)
                .putLong(u.getMostSignificantBits())
                .putLong(u.getLeastSignificantBits())
                .array();
    }

    public static String hex(byte[] a) {
        return ClippBytes.hex(a);
    }

    public static void name(byte[] a, int offset, int size, String s) {
        byte[] value = utf8(s);
        int n = Math.min(size - 1, value.length);
        while (n > 0 && n < value.length && (value[n] & 0xc0) == 0x80) n--;
        System.arraycopy(value, 0, a, offset, n);
    }

    public static String name(byte[] a, int offset, int size) {
        int n = 0;
        while (n < size && a[offset + n] != 0) n++;
        return new String(a, offset, n, StandardCharsets.UTF_8);
    }

    public static final class Item {
        public final byte[] header, data;
        public final int format, flags;
        public final long timestamp;
        public final String event, origin;

        private Item(byte[] h, byte[] d) {
            header = h;
            data = d;
            ByteBuffer b = ByteBuffer.wrap(h);
            flags = b.getInt(FLAGS);
            timestamp = b.getLong(TIMESTAMP);
            format = b.getInt(FORMAT);
            event = hex(Arrays.copyOfRange(h, EVENT, EVENT + ID_SIZE));
            origin = hex(Arrays.copyOfRange(h, ORIGIN, ORIGIN + ID_SIZE));
        }

        public Item withFlags(int flags) {
            byte[] copy = header.clone();
            ByteBuffer.wrap(copy).putInt(FLAGS, flags);
            return new Item(copy, data);
        }

        public byte[] frame(boolean replay) {
            byte[] out = new byte[4 + HEADER + data.length];
            System.arraycopy(utf8("CLIP"), 0, out, 0, 4);
            System.arraycopy(header, 0, out, 4, HEADER);
            if (replay) ByteBuffer.wrap(out).putInt(4 + FLAGS, flags | FLAG_REPLAY);
            System.arraycopy(data, 0, out, 4 + HEADER, data.length);
            return out;
        }
    }

    public static Item local(
            byte[] data, int format, byte[] host, String name, long sequence, long timestamp) {
        if (format == TEXT)
            data =
                    utf8(
                            new String(data, StandardCharsets.UTF_8)
                                    .replace("\r\n", "\n")
                                    .replace('\r', '\n'));
        byte[] h = new byte[HEADER];
        ByteBuffer b = ByteBuffer.wrap(h);
        b.putLong(TIMESTAMP, timestamp);
        h[HASH_ALGORITHM] = 1;
        System.arraycopy(ClippCrypto.contentHash(data, format), 0, h, HASH, ID_SIZE);
        System.arraycopy(host, 0, h, ORIGIN, ID_SIZE);
        name(h, ORIGIN_NAME, NAME_SIZE, name);
        b.putLong(SEQUENCE, sequence);
        System.arraycopy(uuid(UUID.randomUUID()), 0, h, EVENT, ID_SIZE);
        b.putInt(FORMAT, format);
        b.putLong(ENCODED_SIZE, data.length);
        b.putLong(PLAIN_SIZE, data.length);
        return new Item(h, data);
    }

    public static Item decode(byte[] frame, int imageLimit) throws IOException {
        if (frame.length < 4 + HEADER) throw new IOException("Frame");
        byte[] h = Arrays.copyOfRange(frame, 4, 4 + HEADER);
        ByteBuffer b = ByteBuffer.wrap(h);
        int format = b.getInt(FORMAT);
        long encoded = b.getLong(ENCODED_SIZE), plain = b.getLong(PLAIN_SIZE);
        int limit = format == TEXT ? 1024 * 1024 : imageLimit;
        if ((format != TEXT && format != PNG && format != JPEG)
                || encoded < 0
                || encoded != frame.length - 4 - HEADER
                || plain < 0
                || plain > limit
                || h[COMPRESSED] < 0
                || h[COMPRESSED] > 1) throw new IOException("Payload");
        byte[] data = Arrays.copyOfRange(frame, 4 + HEADER, frame.length);
        if (h[COMPRESSED] == 1)
            try {
                data = ClippCrypto.decompress(data, (int) plain);
            } catch (RuntimeException e) {
                throw new IOException("Compression", e);
            }
        else if (encoded != plain) throw new IOException("Size");
        if (h[HASH_ALGORITHM] != 0 && h[HASH_ALGORITHM] != 1) throw new IOException("Hash");
        if (h[HASH_ALGORITHM] == 1
                && !Arrays.equals(
                        Arrays.copyOfRange(h, HASH, HASH + ID_SIZE),
                        ClippCrypto.contentHash(data, format))) throw new IOException("Hash");
        h[COMPRESSED] = 0;
        b.putLong(ENCODED_SIZE, data.length);
        return new Item(h, data);
    }

    public static final class Channel {
        private final DataInputStream in;
        private final DataOutputStream out;
        private byte[] tx, rx;
        private boolean receiveBudgetHeld;
        public final byte[] remoteId;
        public final String remoteName;
        public final int remoteCaps;

        public Channel(
                InputStream input,
                OutputStream output,
                byte[] root,
                byte[] host,
                String name,
                boolean client)
                throws IOException {
            in = new DataInputStream(input);
            out = new DataOutputStream(output);
            byte[] pair = null, keys = null, push = null;
            boolean authenticated = false;
            try {
                pair = ClippCrypto.keyPair();
                byte[] local = new byte[HANDSHAKE_SIZE];
                System.arraycopy(pair, 0, local, 0, KEY_SIZE);
                System.arraycopy(host, 0, local, HANDSHAKE_HOST, ID_SIZE);
                local[HANDSHAKE_CAPS] = 1;
                name(local, HANDSHAKE_NAME, NAME_SIZE, name);
                byte[] remote;
                if (client) {
                    out.write(
                            ClippCrypto.sealWithRole(
                                    root, ClippCrypto.ROLE_CLIENT_TO_SERVER, local));
                    out.flush();
                    remote =
                            ClippCrypto.openWithRole(
                                    root,
                                    ClippCrypto.ROLE_SERVER_TO_CLIENT,
                                    read(SEALED_HANDSHAKE_SIZE));
                } else {
                    remote =
                            ClippCrypto.openWithRole(
                                    root,
                                    ClippCrypto.ROLE_CLIENT_TO_SERVER,
                                    read(SEALED_HANDSHAKE_SIZE));
                    out.write(
                            ClippCrypto.sealWithRole(
                                    root, ClippCrypto.ROLE_SERVER_TO_CLIENT, local));
                    out.flush();
                }
                if (remote.length != HANDSHAKE_SIZE) throw new IOException("Handshake");
                remoteId = Arrays.copyOfRange(remote, HANDSHAKE_HOST, HANDSHAKE_HOST + ID_SIZE);
                remoteCaps = remote[HANDSHAKE_CAPS] & 255;
                remoteName = name(remote, HANDSHAKE_NAME, NAME_SIZE);
                keys =
                        ClippCrypto.sessionKeys(
                                client, pair, Arrays.copyOfRange(remote, 0, KEY_SIZE));
                push = ClippCrypto.initPush(Arrays.copyOfRange(keys, KEY_SIZE, KEY_SIZE * 2));
                tx = Arrays.copyOf(push, push.length - STREAM_HEADER_SIZE);
                if (client) {
                    out.write(push, push.length - STREAM_HEADER_SIZE, STREAM_HEADER_SIZE);
                    out.flush();
                    rx =
                            ClippCrypto.initPull(
                                    Arrays.copyOf(keys, KEY_SIZE), read(STREAM_HEADER_SIZE));
                    send(utf8("DONE"));
                } else {
                    rx =
                            ClippCrypto.initPull(
                                    Arrays.copyOf(keys, KEY_SIZE), read(STREAM_HEADER_SIZE));
                    out.write(push, push.length - STREAM_HEADER_SIZE, STREAM_HEADER_SIZE);
                    out.flush();
                    if (!Arrays.equals(receive(64), utf8("DONE")))
                        throw new IOException("Handshake");
                }
                authenticated = true;
            } catch (RuntimeException e) {
                throw new IOException("Authentication", e);
            } finally {
                if (pair != null) Arrays.fill(pair, (byte) 0);
                if (keys != null) Arrays.fill(keys, (byte) 0);
                if (push != null) Arrays.fill(push, (byte) 0);
                if (!authenticated) wipe();
            }
        }

        private byte[] read(int size) throws IOException {
            byte[] data = new byte[size];
            in.readFully(data);
            return data;
        }

        public synchronized void send(byte[] frame) throws IOException {
            if (frame.length > MAX_FRAME - 17) throw new IOException("Frame limit");
            try {
                byte[] encrypted = ClippCrypto.push(tx, frame);
                out.writeInt(encrypted.length);
                out.write(encrypted);
                out.flush();
            } catch (RuntimeException e) {
                throw new IOException("Encryption", e);
            }
        }

        public byte[] receive(int max) throws IOException {
            return receive(max, null);
        }

        public byte[] receive(int max, java.util.concurrent.Semaphore budget) throws IOException {
            int n = in.readInt();
            if (n < 21 || n > Math.min(MAX_FRAME, max)) throw new IOException("Frame limit");
            boolean acquired = false, returned = false;
            try {
                if (budget != null && n > 4096) {
                    try {
                        acquired = budget.tryAcquire(60, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Stopped", e);
                    }
                    if (!acquired) throw new IOException("Busy");
                }
                byte[] frame = ClippCrypto.pull(rx, read(n));
                if (budget != null
                        && !acquired
                        && frame.length >= 4
                        && frame[0] == 67
                        && frame[1] == 76
                        && frame[2] == 73
                        && frame[3] == 80) {
                    try {
                        acquired = budget.tryAcquire(60, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Stopped", e);
                    }
                    if (!acquired) throw new IOException("Busy");
                }
                receiveBudgetHeld = acquired;
                returned = true;
                return frame;
            } catch (RuntimeException e) {
                throw new IOException("Decryption", e);
            } finally {
                if (acquired && !returned) budget.release();
            }
        }

        public void releaseReceiveBudget(java.util.concurrent.Semaphore budget) {
            if (receiveBudgetHeld) {
                receiveBudgetHeld = false;
                budget.release();
            }
        }

        public synchronized void wipe() {
            if (tx != null) Arrays.fill(tx, (byte) 0);
            if (rx != null) Arrays.fill(rx, (byte) 0);
        }
    }

    private ClippWire() {}
}
