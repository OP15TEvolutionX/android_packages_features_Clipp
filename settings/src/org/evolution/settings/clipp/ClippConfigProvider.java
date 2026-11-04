// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.settings.clipp;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.evolution.clipp.ClippBytes;
import org.evolution.clipp.ClippContract;
import org.evolution.clipp.ClippCrypto;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.KeyStore;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Clipp configuration for one user, kept in Settings' private storage.
 *
 * <p>The root key is encrypted with an Android Keystore key and only decrypted for SystemUI's
 * "read". "setup" runs Argon2 on the password, so this provider lives in its own process
 * (":clippconfig") to keep that memory spike out of Settings. Peer states reported by SystemUI
 * are kept here too, so the Settings screen can show them.
 *
 * <p>Methods: "read" (SystemUI or Settings), "setup" and "save" (Settings only), "status".
 */
public final class ClippConfigProvider extends ContentProvider {
    private static final String PREFS = "clipp";
    private static final String KEYSTORE_ALIAS = "evolution_clipp_group";
    /** Status IDs of peers are their host IDs; other IDs are free-form. */
    private static final String HOST_ID = "[a-f0-9]{32}";

    private final ConcurrentHashMap<String, String> states = new ConcurrentHashMap<>();

    @Override
    public boolean onCreate() {
        try {
            JSONObject saved = new JSONObject(prefs().getString("deviceStates", "{}"));
            java.util.Iterator<String> ids = saved.keys();
            while (ids.hasNext()) {
                String id = ids.next();
                if (id.matches(HOST_ID)) states.put(id, saved.getString(id));
            }
        } catch (JSONException ignored) {
        }
        return true;
    }

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private void persistStates(SharedPreferences prefs) {
        JSONObject saved = new JSONObject(states);
        prefs.edit().putString("deviceStates", saved.toString()).apply();
    }

    /** Settings itself may do anything; SystemUI with the platform signature may only read. */
    private void enforce(boolean write) {
        int uid = Binder.getCallingUid();
        if (uid == android.os.Process.myUid()) return;
        String[] names = getContext().getPackageManager().getPackagesForUid(uid);
        if (!write && names != null)
            for (String n : names)
                if (n.equals("com.android.systemui")
                        && getContext()
                                        .getPackageManager()
                                        .checkSignatures(uid, android.os.Process.myUid())
                                == android.content.pm.PackageManager.SIGNATURE_MATCH) return;
        throw new SecurityException("Clipp IPC denied");
    }

    /** AES-GCM key in the Keystore that wraps the root key at rest. */
    private SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(KEYSTORE_ALIAS)) {
            return (SecretKey) store.getKey(KEYSTORE_ALIAS, null);
        }
        KeyGenerator gen = KeyGenerator.getInstance("AES", "AndroidKeyStore");
        gen.init(
                new KeyGenParameterSpec.Builder(
                                KEYSTORE_ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build());
        return gen.generateKey();
    }

    @Override
    public synchronized Bundle call(String method, String arg, Bundle extras) {
        enforce(method.equals("save") || method.equals("setup"));
        SharedPreferences prefs = prefs();
        Bundle result = new Bundle();
        try {
            JSONObject config = new JSONObject(prefs.getString("config", "{}"));
            switch (method) {
                case "read":
                    result.putString("config", read(prefs, config).toString());
                    break;
                case "setup":
                    setup(prefs, config, extras);
                    break;
                case "save":
                    save(prefs, config, extras);
                    break;
                case "status":
                    if (extras == null) result.putString("status", status(arg));
                    else setStatus(prefs, arg, extras.getString("status", ""));
                    break;
                default:
                    throw new IllegalArgumentException("Method");
            }
            return result;
        } catch (Exception e) {
            throw new IllegalArgumentException("Clipp configuration unavailable", e);
        }
    }

    /** Returns the configuration with the decrypted root key; creates the host ID on first use. */
    private JSONObject read(SharedPreferences prefs, JSONObject config) throws Exception {
        if (config.optString("hostId").isEmpty()) {
            config.put("hostId", UUID.randomUUID().toString().replace("-", ""));
            prefs.edit().putString("config", config.toString()).commit();
        }
        if (!prefs.getString("root", "").isEmpty()) {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(
                    Cipher.DECRYPT_MODE,
                    key(),
                    new GCMParameterSpec(
                            128, Base64.decode(prefs.getString("iv", ""), Base64.NO_WRAP)));
            byte[] root = c.doFinal(Base64.decode(prefs.getString("root", ""), Base64.NO_WRAP));
            config.put("root", Base64.encodeToString(root, Base64.NO_WRAP));
            Arrays.fill(root, (byte) 0);
        }
        return config;
    }

    /**
     * Joins a group: derives and stores the root key and its fingerprint. Sync is switched off
     * and old peer states are cleared, since they belonged to the previous group.
     */
    private void setup(SharedPreferences prefs, JSONObject config, Bundle extras)
            throws Exception {
        String group = extras.getString("group", ""), password = extras.getString("password", "");
        if (group.isEmpty()
                || group.length() > 256
                || password.length() < 8
                || password.length() > 1024
                || group.indexOf(0) >= 0
                || password.indexOf(0) >= 0) {
            throw new IllegalArgumentException("Group credentials");
        }
        byte[] root = ClippCrypto.derive(group, password);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key());
        byte[] encrypted = c.doFinal(root);
        byte[] fingerprint = ClippCrypto.fingerprint(root);
        Arrays.fill(root, (byte) 0);
        config.put("group", group)
                .put("fingerprint", formatFingerprint(fingerprint))
                .put("enabled", false);
        if (!prefs.edit()
                .putString("config", config.toString())
                .putString("root", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .putString("iv", Base64.encodeToString(c.getIV(), Base64.NO_WRAP))
                .commit()) throw new IllegalStateException();
        states.clear();
        persistStates(prefs);
        getContext().getContentResolver().notifyChange(ClippContract.CONFIG, null);
    }

    /** Hex in groups of four bytes: "0a1b2c3d-...". */
    private static String formatFingerprint(byte[] fingerprint) {
        String hex = ClippBytes.hex(fingerprint);
        StringBuilder fp = new StringBuilder(35);
        for (int i = 0; i < fingerprint.length; i++) {
            if (i > 0 && i % 4 == 0) fp.append('-');
            fp.append(hex, i * 2, i * 2 + 2);
        }
        return fp.toString();
    }

    /** Saves the switches; the key material and IDs can't be changed this way. */
    private void save(SharedPreferences prefs, JSONObject config, Bundle extras)
            throws Exception {
        JSONObject next = new JSONObject(extras.getString("config"));
        next.remove("root");
        next.remove("text");
        next.remove("images");
        next.remove("maxImageMb");
        if (next.toString().length() > 32768) throw new IllegalArgumentException("Config");
        next.put("hostId", config.optString("hostId"))
                .put("group", config.optString("group"))
                .put("fingerprint", config.optString("fingerprint"));
        if (next.optBoolean("enabled") && prefs.getString("root", "").isEmpty())
            throw new IllegalArgumentException("Group missing");
        if (!prefs.edit().putString("config", next.toString()).commit())
            throw new IllegalStateException();
        getContext().getContentResolver().notifyChange(ClippContract.CONFIG, null);
    }

    /** One state, or for "devices" all peer states as a JSON object. */
    private String status(String id) throws JSONException {
        if (!"devices".equals(id)) return states.getOrDefault(id, "");
        JSONObject devices = new JSONObject();
        for (Map.Entry<String, String> entry : states.entrySet())
            if (entry.getKey().matches(HOST_ID)) devices.put(entry.getKey(), entry.getValue());
        return devices.toString();
    }

    /** Stores one state; any value for "devices" clears all peers (a new transport started). */
    private void setStatus(SharedPreferences prefs, String id, String value) {
        if ("devices".equals(id)) {
            states.keySet().removeIf(key -> key.matches(HOST_ID));
            persistStates(prefs);
            getContext().getContentResolver().notifyChange(ClippContract.STATUS, null);
            return;
        }
        if (value.length() > 2048) throw new IllegalArgumentException();
        String old = states.put(id, value);
        if (!value.equals(old)) {
            persistStates(prefs);
            getContext().getContentResolver().notifyChange(ClippContract.STATUS, null);
        }
    }

    @Override
    public Cursor query(Uri u, String[] p, String s, String[] a, String o) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getType(Uri u) {
        return null;
    }

    @Override
    public Uri insert(Uri u, ContentValues v) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri u, String s, String[] a) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri u, ContentValues v, String s, String[] a) {
        throw new UnsupportedOperationException();
    }
}
