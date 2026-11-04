// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.clipp;

import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;

import org.json.JSONObject;

/**
 * Calls between SystemUI and Settings. Settings owns the configuration in
 * {@code ClippConfigProvider}; SystemUI reads it and reports peer states back for display.
 * Credentials never go into Settings.Secure or broadcasts.
 */
public final class ClippContract {
    public static final Uri CONFIG = Uri.parse("content://com.android.settings.clipp/config");
    public static final Uri STATUS = Uri.parse("content://com.android.settings.clipp/status");
    public static final String IMAGE_AUTHORITY = "com.android.systemui.clipp.images";

    /** The configuration, including the decrypted group key under "root". */
    public static JSONObject read(ContentResolver resolver) throws Exception {
        Bundle result = resolver.call(CONFIG, "read", null, null);
        return new JSONObject(result.getString("config", "{}"));
    }

    /** Saves switches; the provider keeps the IDs and the group key as they are. */
    public static void save(ContentResolver resolver, JSONObject config) {
        Bundle b = new Bundle();
        b.putString("config", config.toString());
        resolver.call(CONFIG, "save", null, b);
    }

    /** A reported state; the ID "devices" returns all peers as one JSON object. */
    public static String status(ContentResolver resolver, String id) {
        Bundle result = resolver.call(STATUS, "status", id, null);
        return result == null ? "" : result.getString("status", "");
    }

    /** Reports a peer state; the ID "devices" clears all peers. */
    public static void status(ContentResolver resolver, String id, String state) {
        Bundle b = new Bundle();
        b.putString("status", state);
        resolver.call(STATUS, "status", id, b);
    }

    private ClippContract() {}
}
