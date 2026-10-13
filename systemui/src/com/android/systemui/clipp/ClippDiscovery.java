// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/** Packed MDNSProtocol payload; Android DNS-SD and TXT encoding live in ClippTransport. */
public final class ClippDiscovery {
    public static final String SERVICE_TYPE = "_clipp._tcp.";
    public static final String TXT_VERSION = "1";
    private static final int PACKET_SIZE = 100;
    private static final int MAGIC = 0x434c4950;
    private static final int VERSION_OFFSET = 4;
    private static final int HOST_OFFSET = 12;
    private static final int HOST_SIZE = 16;
    private static final int NAME_OFFSET = 36;
    private static final int NAME_SIZE = 64;

    public static byte[] encode(byte[] host, String name) {
        byte[] packet = new byte[PACKET_SIZE];
        ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).putInt(0, MAGIC);
        ByteBuffer.wrap(packet).putShort(VERSION_OFFSET, (short) 1);
        System.arraycopy(host, 0, packet, HOST_OFFSET, HOST_SIZE);
        ClippWire.name(packet, NAME_OFFSET, NAME_SIZE, name);
        return packet;
    }

    public static void validate(byte[] packet) {
        if (packet.length != PACKET_SIZE
                || ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).getInt(0) != MAGIC
                || ByteBuffer.wrap(packet).getShort(VERSION_OFFSET) != 1) {
            throw new IllegalArgumentException("Discovery packet");
        }
    }

    public static byte[] host(byte[] packet) {
        validate(packet);
        return Arrays.copyOfRange(packet, HOST_OFFSET, HOST_OFFSET + HOST_SIZE);
    }

    public static String name(byte[] packet) {
        validate(packet);
        return ClippWire.name(packet, NAME_OFFSET, NAME_SIZE);
    }

    public static String hostId(byte[] packet) {
        validate(packet);
        return ClippWire.hex(host(packet));
    }

    private ClippDiscovery() {}
}
