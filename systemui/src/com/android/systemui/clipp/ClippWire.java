// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import org.evolution.clipp.ClippCrypto;

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;

/** Compatible Clipp binary framing; authentication precedes every clipboard frame. */
public final class ClippWire {
    public static final int HEADER = 285,
            PNG = 8,
            TEXT = 13,
            JPEG = 0x434a5047,
            MAX_FRAME = 50 * 1024 * 1024 + HEADER + 21;

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
        StringBuilder b = new StringBuilder();
        for (byte v : a) b.append(String.format(Locale.ROOT, "%02x", v & 255));
        return b.toString();
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
            flags = b.getInt(0);
            timestamp = b.getLong(4);
            format = b.getInt(264);
            event = hex(Arrays.copyOfRange(h, 232, 248));
            origin = hex(Arrays.copyOfRange(h, 80, 96));
        }

        public Item withFlags(int flags) {
            byte[] copy = header.clone();
            ByteBuffer.wrap(copy).putInt(0, flags);
            return new Item(copy, data);
        }

        public byte[] frame(boolean replay) {
            byte[] out = new byte[4 + HEADER + data.length];
            System.arraycopy(utf8("CLIP"), 0, out, 0, 4);
            System.arraycopy(header, 0, out, 4, HEADER);
            if (replay) ByteBuffer.wrap(out).putInt(4, flags | 1);
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
        b.putLong(4, timestamp);
        h[12] = 1;
        System.arraycopy(ClippCrypto.call(12, data, integer(format), null), 0, h, 16, 16);
        System.arraycopy(host, 0, h, 80, 16);
        name(h, 96, 128, name);
        b.putLong(224, sequence);
        System.arraycopy(uuid(UUID.randomUUID()), 0, h, 232, 16);
        b.putInt(264, format);
        b.putLong(269, data.length);
        b.putLong(277, data.length);
        return new Item(h, data);
    }

    public static Item decode(byte[] frame, int imageLimit) throws IOException {
        if (frame.length < 4 + HEADER) throw new IOException("Frame");
        byte[] h = Arrays.copyOfRange(frame, 4, 4 + HEADER);
        ByteBuffer b = ByteBuffer.wrap(h);
        int format = b.getInt(264);
        long encoded = b.getLong(269), plain = b.getLong(277);
        int limit = format == TEXT ? 1024 * 1024 : imageLimit;
        if ((format != TEXT && format != PNG && format != JPEG)
                || encoded < 0
                || encoded != frame.length - 4 - HEADER
                || plain < 0
                || plain > limit
                || h[268] < 0
                || h[268] > 1) throw new IOException("Payload");
        byte[] data = Arrays.copyOfRange(frame, 4 + HEADER, frame.length);
        if (h[268] == 1)
            try {
                data = ClippCrypto.call(11, data, integer((int) plain), null);
            } catch (RuntimeException e) {
                throw new IOException("Compression", e);
            }
        else if (encoded != plain) throw new IOException("Size");
        if (h[12] != 0 && h[12] != 1) throw new IOException("Hash");
        if (h[12] == 1
                && !Arrays.equals(
                        Arrays.copyOfRange(h, 16, 32),
                        ClippCrypto.call(12, data, integer(format), null)))
            throw new IOException("Hash");
        h[268] = 0;
        b.putLong(269, data.length);
        return new Item(h, data);
    }

    public static final class Channel {
        private final DataInputStream in;
        private final DataOutputStream out;
        private byte[] tx, rx;
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
            try {
                byte[] pair = ClippCrypto.call(4, null, null, null), local = new byte[192];
                System.arraycopy(pair, 0, local, 0, 32);
                System.arraycopy(host, 0, local, 32, 16);
                local[48] = 1;
                name(local, 64, 128, name);
                byte[] remote;
                if (client) {
                    out.write(ClippCrypto.call(2, ClippCrypto.role(root, 1), local, null));
                    out.flush();
                    remote = ClippCrypto.call(3, ClippCrypto.role(root, 2), read(232), null);
                } else {
                    remote = ClippCrypto.call(3, ClippCrypto.role(root, 1), read(232), null);
                    out.write(ClippCrypto.call(2, ClippCrypto.role(root, 2), local, null));
                    out.flush();
                }
                if (remote.length != 192) throw new IOException("Handshake");
                remoteId = Arrays.copyOfRange(remote, 32, 48);
                remoteCaps = remote[48] & 255;
                remoteName = name(remote, 64, 128);
                byte[] keys =
                        ClippCrypto.call(
                                client ? 5 : 6, pair, Arrays.copyOfRange(remote, 0, 32), null);
                Arrays.fill(pair, (byte) 0);
                byte[] push = ClippCrypto.call(7, Arrays.copyOfRange(keys, 32, 64), null, null);
                tx = Arrays.copyOf(push, push.length - 24);
                if (client) {
                    out.write(push, push.length - 24, 24);
                    out.flush();
                    rx = ClippCrypto.call(8, Arrays.copyOf(keys, 32), read(24), null);
                    send(utf8("DONE"));
                } else {
                    rx = ClippCrypto.call(8, Arrays.copyOf(keys, 32), read(24), null);
                    out.write(push, push.length - 24, 24);
                    out.flush();
                    if (!Arrays.equals(receive(64), utf8("DONE")))
                        throw new IOException("Handshake");
                }
                Arrays.fill(keys, (byte) 0);
                Arrays.fill(push, (byte) 0);
            } catch (RuntimeException e) {
                throw new IOException("Authentication", e);
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
                byte[] encrypted = ClippCrypto.call(9, tx, frame, null);
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
                if (budget != null) {
                    try {
                        acquired = budget.tryAcquire(60, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Stopped", e);
                    }
                    if (!acquired) throw new IOException("Busy");
                }
                byte[] frame = ClippCrypto.call(10, rx, read(n), null);
                returned = true;
                return frame;
            } catch (RuntimeException e) {
                throw new IOException("Decryption", e);
            } finally {
                if (acquired && !returned) budget.release();
            }
        }

        public void wipe() {
            if (tx != null) Arrays.fill(tx, (byte) 0);
            if (rx != null) Arrays.fill(rx, (byte) 0);
        }
    }

    private ClippWire() {}
}
