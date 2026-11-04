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
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Clipp binary format, compatible with the desktop app.
 *
 * <p>A connection starts with a sealed handshake ({@link Channel}); after it every message is a
 * length-prefixed secretstream frame. A frame starts with a 4-byte ASCII tag. "CLIP" frames carry
 * a {@link #HEADER}-byte clip header followed by the clip data; the other tags are control
 * messages handled in {@link ClippTransport}.
 */
public final class ClippWire {
    /** Size of the packed clip header that follows the "CLIP" tag. */
    public static final int HEADER = 285;
    /** Clip formats; values match the desktop clipboard format IDs. */
    public static final int PNG = 8, TEXT = 13, JPEG = 0x434a5047;

    public static final int MAX_TEXT_BYTES = 1024 * 1024;
    public static final int MAX_IMAGE_BYTES = 50 * 1024 * 1024;

    private static final int TAG_SIZE = 4;
    /** Authentication tag and stream tag added by libsodium secretstream to every frame. */
    private static final int STREAM_OVERHEAD = 17;
    /** Bytes an encrypted "CLIP" frame adds to the clip header and data. */
    public static final int FRAME_OVERHEAD = TAG_SIZE + STREAM_OVERHEAD;
    /** Largest encrypted frame: a full image plus the tag, header and stream overhead. */
    public static final int MAX_FRAME = MAX_IMAGE_BYTES + HEADER + FRAME_OVERHEAD;
    /** Frames up to this size are read without taking the decoding budget. */
    private static final int SMALL_FRAME = 4096;

    /** History sent on connect; it must not change the receiver's clipboard. */
    public static final int FLAG_REPLAY = 1;
    /** Marked private by the sender; never synced. */
    public static final int FLAG_PRIVATE = 2;
    /** The receiver forwards the clip to its own peers. */
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

    /** Writes a NUL-terminated UTF-8 name, cut at a character boundary to fit. */
    public static void name(byte[] a, int offset, int size, String s) {
        byte[] value = utf8(s);
        int n = Math.min(size - 1, value.length);
        while (n > 0 && n < value.length && (value[n] & 0xc0) == 0x80) n--;
        System.arraycopy(value, 0, a, offset, n);
    }

    /** Reads a NUL-terminated UTF-8 name. */
    public static String name(byte[] a, int offset, int size) {
        int n = 0;
        while (n < size && a[offset + n] != 0) n++;
        return new String(a, offset, n, StandardCharsets.UTF_8);
    }

    /** One clip: the raw header and the uncompressed data. */
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

        /** Plain "CLIP" frame; {@code replay} marks it as history. */
        public byte[] frame(boolean replay) {
            byte[] out = new byte[TAG_SIZE + HEADER + data.length];
            System.arraycopy(utf8("CLIP"), 0, out, 0, TAG_SIZE);
            System.arraycopy(header, 0, out, TAG_SIZE, HEADER);
            if (replay) ByteBuffer.wrap(out).putInt(TAG_SIZE + FLAGS, flags | FLAG_REPLAY);
            System.arraycopy(data, 0, out, TAG_SIZE + HEADER, data.length);
            return out;
        }
    }

    /** Builds the header for a clip copied on this device. */
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

    /**
     * Parses a decrypted "CLIP" frame: checks the sizes, decompresses zstd data and verifies the
     * content hash. The returned header always says "uncompressed".
     */
    public static Item decode(byte[] frame, int imageLimit) throws IOException {
        if (frame.length < TAG_SIZE + HEADER) throw new IOException("Frame");
        byte[] h = Arrays.copyOfRange(frame, TAG_SIZE, TAG_SIZE + HEADER);
        ByteBuffer b = ByteBuffer.wrap(h);
        int format = b.getInt(FORMAT);
        long encoded = b.getLong(ENCODED_SIZE), plain = b.getLong(PLAIN_SIZE);
        int limit = format == TEXT ? MAX_TEXT_BYTES : imageLimit;
        if ((format != TEXT && format != PNG && format != JPEG)
                || encoded < 0
                || encoded != frame.length - TAG_SIZE - HEADER
                || plain < 0
                || plain > limit
                || h[COMPRESSED] < 0
                || h[COMPRESSED] > 1) throw new IOException("Payload");
        byte[] data = Arrays.copyOfRange(frame, TAG_SIZE + HEADER, frame.length);
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

    /**
     * Encrypted connection to one peer.
     *
     * <p>Handshake: each side sends its key-exchange public key, host ID and name, sealed with a
     * key derived from the group password, so only group members can read it. Session keys from
     * crypto_kx then start one secretstream per direction, and the client confirms with "DONE".
     */
    public static final class Channel {
        private final DataInputStream in;
        private final DataOutputStream out;
        /** Secretstream states; native code updates them in place on every frame. */
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
            if (frame.length > MAX_FRAME - STREAM_OVERHEAD) throw new IOException("Frame limit");
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

        /**
         * Reads one frame. With a {@code budget}, large frames and every "CLIP" frame hold a
         * permit until {@link #releaseReceiveBudget}, so peers decode clips one at a time
         * instead of keeping many images in memory at once.
         */
        public byte[] receive(int max, Semaphore budget) throws IOException {
            int n = in.readInt();
            if (n < FRAME_OVERHEAD || n > Math.min(MAX_FRAME, max))
                throw new IOException("Frame limit");
            boolean acquired = false, returned = false;
            try {
                if (budget != null && n > SMALL_FRAME) acquired = acquire(budget);
                byte[] frame = ClippCrypto.pull(rx, read(n));
                if (budget != null && !acquired && isClip(frame)) acquired = acquire(budget);
                receiveBudgetHeld = acquired;
                returned = true;
                return frame;
            } catch (RuntimeException e) {
                throw new IOException("Decryption", e);
            } finally {
                if (acquired && !returned) budget.release();
            }
        }

        private static boolean acquire(Semaphore budget) throws IOException {
            try {
                if (budget.tryAcquire(60, TimeUnit.SECONDS)) return true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Stopped", e);
            }
            throw new IOException("Busy");
        }

        private static boolean isClip(byte[] frame) {
            return frame.length >= TAG_SIZE
                    && frame[0] == 'C'
                    && frame[1] == 'L'
                    && frame[2] == 'I'
                    && frame[3] == 'P';
        }

        public void releaseReceiveBudget(Semaphore budget) {
            if (receiveBudgetHeld) {
                receiveBudgetHeld = false;
                budget.release();
            }
        }

        /** Clears the stream keys; the channel is unusable afterwards. */
        public synchronized void wipe() {
            if (tx != null) Arrays.fill(tx, (byte) 0);
            if (rx != null) Arrays.fill(rx, (byte) 0);
        }
    }

    private ClippWire() {}
}
