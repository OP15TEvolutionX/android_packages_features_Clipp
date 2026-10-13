// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.settings.clipp;

import android.content.*;
import android.database.Cursor;
import android.net.Uri;
import android.os.*;
import android.security.keystore.*;
import android.util.Base64;

import org.evolution.clipp.*;
import org.json.*;

import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

/** Private per-user configuration. Argon2 runs in Settings' isolated provider process. */
public final class ClippConfigProvider extends ContentProvider {
    private final ConcurrentHashMap<String, String> states = new ConcurrentHashMap<>();

    @Override
    public boolean onCreate() {
        return true;
    }

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

    private SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        String alias = "evolution_clipp_group";
        if (store.containsAlias(alias)) return (SecretKey) store.getKey(alias, null);
        KeyGenerator gen = KeyGenerator.getInstance("AES", "AndroidKeyStore");
        gen.init(
                new KeyGenParameterSpec.Builder(
                                alias,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build());
        return gen.generateKey();
    }

    @Override
    public synchronized Bundle call(String method, String arg, Bundle extras) {
        enforce(method.equals("save") || method.equals("setup"));
        SharedPreferences prefs = getContext().getSharedPreferences("clipp", Context.MODE_PRIVATE);
        Bundle result = new Bundle();
        try {
            JSONObject config = new JSONObject(prefs.getString("config", "{}"));
            if (method.equals("read")) {
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
                    byte[] root =
                            c.doFinal(Base64.decode(prefs.getString("root", ""), Base64.NO_WRAP));
                    config.put("root", Base64.encodeToString(root, Base64.NO_WRAP));
                    Arrays.fill(root, (byte) 0);
                }
                result.putString("config", config.toString());
            } else if (method.equals("setup")) {
                String group = extras.getString("group", ""),
                        password = extras.getString("password", "");
                if (group.isEmpty()
                        || group.length() > 256
                        || password.length() < 8
                        || password.length() > 1024
                        || group.indexOf(0) >= 0
                        || password.indexOf(0) >= 0)
                    throw new IllegalArgumentException("Group credentials");
                byte[] root = ClippCrypto.derive(group, password);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key());
                byte[] encrypted = c.doFinal(root);
                byte[] fingerprint = ClippCrypto.call(13, ClippCrypto.role(root, 4), null, null);
                Arrays.fill(root, (byte) 0);
                StringBuilder fp = new StringBuilder();
                for (int i = 0; i < fingerprint.length; i++) {
                    if (i > 0 && i % 4 == 0) fp.append('-');
                    fp.append(String.format(Locale.ROOT, "%02x", fingerprint[i] & 255));
                }
                config.put("group", group).put("fingerprint", fp.toString()).put("enabled", false);
                if (!prefs.edit()
                        .putString("config", config.toString())
                        .putString("root", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                        .putString("iv", Base64.encodeToString(c.getIV(), Base64.NO_WRAP))
                        .commit()) throw new IllegalStateException();
                states.clear();
                getContext().getContentResolver().notifyChange(ClippContract.CONFIG, null);
            } else if (method.equals("save")) {
                JSONObject next = new JSONObject(extras.getString("config"));
                next.remove("root");
                if (next.toString().length() > 32768
                        || !Arrays.asList(5, 10, 20, 50).contains(next.optInt("maxImageMb", 20)))
                    throw new IllegalArgumentException("Config");
                next.put("hostId", config.optString("hostId"))
                        .put("group", config.optString("group"))
                        .put("fingerprint", config.optString("fingerprint"));
                JSONArray blocked = next.optJSONArray("blocked");
                if (blocked != null && blocked.length() > 32)
                    throw new IllegalArgumentException("Devices");
                if (blocked != null)
                    for (int i = 0; i < blocked.length(); i++)
                        if (!blocked.getString(i).matches("[a-f0-9]{32}"))
                            throw new IllegalArgumentException("Device");
                if (next.optBoolean("enabled") && prefs.getString("root", "").isEmpty())
                    throw new IllegalArgumentException("Group missing");
                if (!prefs.edit().putString("config", next.toString()).commit())
                    throw new IllegalStateException();
                getContext().getContentResolver().notifyChange(ClippContract.CONFIG, null);
            } else if (method.equals("status")) {
                if (extras == null) {
                    result.putString("status", states.getOrDefault(arg, ""));
                    if ("devices".equals(arg)) {
                        JSONObject devices = new JSONObject();
                        for (Map.Entry<String, String> entry : states.entrySet())
                            if (entry.getKey().matches("[a-f0-9]{32}"))
                                devices.put(entry.getKey(), entry.getValue());
                        result.putString("status", devices.toString());
                    }
                } else {
                    String value = extras.getString("status", "");
                    if ("devices".equals(arg)) {
                        states.keySet().removeIf(id -> id.matches("[a-f0-9]{32}"));
                        getContext().getContentResolver().notifyChange(ClippContract.STATUS, null);
                        return result;
                    }
                    if (value.length() > 2048) throw new IllegalArgumentException();
                    if (states.size() > 40 && !states.containsKey(arg)) return result;
                    String old = states.put(arg, value);
                    if (!value.equals(old))
                        getContext().getContentResolver().notifyChange(ClippContract.STATUS, null);
                }
            } else throw new IllegalArgumentException("Method");
            return result;
        } catch (Exception e) {
            throw new IllegalArgumentException("Clipp configuration unavailable", e);
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
