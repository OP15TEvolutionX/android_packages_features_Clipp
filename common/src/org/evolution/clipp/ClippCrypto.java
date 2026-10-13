// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.clipp;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

/** Small libsodium bridge. All wire strings are UTF-8, never JNI modified UTF-8. */
public final class ClippCrypto {
    static {
        System.loadLibrary("evolution_clipp_jni");
    }

    public static native byte[] call(int op, byte[] a, byte[] b, byte[] c);

    public static byte[] role(byte[] root, int role) {
        return call(1, root, new byte[] {(byte) role}, null);
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
