// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.settings.clipp;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceGroup;
import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreferenceCompat;

import com.android.settings.R;
import com.android.settings.SettingsPreferenceFragment;
import com.android.settingslib.widget.FooterPreference;

import org.evolution.clipp.ClippContract;
import org.json.JSONException;
import org.json.JSONObject;

public final class ClippSettings extends SettingsPreferenceFragment {
    private JSONObject config = new JSONObject();
    private final Handler main = new Handler(Looper.getMainLooper());
    private boolean preparing;
    private final ContentObserver observer =
            new ContentObserver(main) {
                @Override
                public void onChange(boolean self) {
                    updateStates();
                }
            };

    @Override
    public int getMetricsCategory() {
        return 0;
    }

    private void read() {
        try {
            config = ClippContract.read(getContext().getContentResolver());
            config.remove("root");
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        read();
        build();
    }

    @Override
    public void onResume() {
        super.onResume();
        getActivity().setTitle(R.string.clipboard_sync_title);
        getContext()
                .getContentResolver()
                .registerContentObserver(ClippContract.STATUS, false, observer);
        read();
        build();
    }

    @Override
    public void onPause() {
        getContext().getContentResolver().unregisterContentObserver(observer);
        super.onPause();
    }

    private void change(String key, Object value) throws JSONException {
        JSONObject next = new JSONObject(config.toString());
        next.put(key, value);
        ClippContract.save(getContext().getContentResolver(), next);
        config = next;
    }

    private void toggle(
            PreferenceGroup group, String key, int title, int summary, boolean initial) {
        SwitchPreferenceCompat p = new SwitchPreferenceCompat(getContext());
        p.setPersistent(false);
        p.setKey(key);
        p.setTitle(title);
        if (summary != 0) p.setSummary(summary);
        p.setChecked(config.optBoolean(key, initial));
        p.setOnPreferenceChangeListener(
                (pref, value) -> {
                    try {
                        change(key, value);
                        if ("enabled".equals(key)) {
                            Preference preview = findPreference("showPreview");
                            if (preview != null) preview.setEnabled((Boolean) value);
                        }
                        return true;
                    } catch (Exception e) {
                        Toast.makeText(
                                        getContext(),
                                        R.string.clipp_setup_required,
                                        Toast.LENGTH_SHORT)
                                .show();
                        return false;
                    }
                });
        group.addPreference(p);
    }

    private void build() {
        PreferenceScreen screen = getPreferenceManager().createPreferenceScreen(getContext());
        screen.setTitle(R.string.clipboard_sync_title);
        setPreferenceScreen(screen);
        toggle(
                screen,
                "enabled",
                R.string.clipboard_sync_enabled,
                R.string.clipboard_sync_summary,
                false);
        toggle(
                screen,
                "showPreview",
                R.string.clipboard_sync_show_preview,
                R.string.clipboard_sync_show_preview_summary,
                true);
        findPreference("showPreview").setEnabled(config.optBoolean("enabled"));
        PreferenceCategory options = new PreferenceCategory(getContext());
        screen.addPreference(options);
        Preference group = new Preference(getContext());
        group.setTitle(R.string.clipp_group);
        group.setSummary(
                preparing
                        ? getString(R.string.clipp_preparing)
                        : config.optString("group", getString(R.string.clipp_setup_required)));
        group.setEnabled(!preparing);
        group.setOnPreferenceClickListener(
                p -> {
                    setup();
                    return true;
                });
        options.addPreference(group);
        if (!config.optString("fingerprint").isEmpty()) {
            Preference fp = new Preference(getContext());
            fp.setTitle(R.string.clipp_fingerprint);
            fp.setSummary(config.optString("fingerprint"));
            fp.setSelectable(false);
            options.addPreference(fp);
        }
        PreferenceCategory devices = new PreferenceCategory(getContext());
        devices.setKey("devices");
        devices.setTitle(R.string.clipboard_sync_servers);
        screen.addPreference(devices);
        FooterPreference note = new FooterPreference(getContext());
        note.setTitle(R.string.clipboard_sync_note);
        note.setLearnMoreText(getString(R.string.clipboard_sync_learn_more));
        note.setLearnMoreAction(
                v ->
                        startActivity(
                                new Intent(
                                        Intent.ACTION_VIEW,
                                        Uri.parse("https://github.com/martona/clipp"))));
        screen.addPreference(note);
        updateStates();
    }

    private String status(String id) {
        try {
            return ClippContract.status(getContext().getContentResolver(), id);
        } catch (Exception e) {
            return "";
        }
    }

    private int stateLabel(String state) {
        switch (state) {
            case "connected":
                return R.string.clipboard_sync_connected;
            case "connection_error":
                return R.string.clipboard_sync_transfer_error;
            default:
                return R.string.clipboard_sync_disconnected;
        }
    }

    private void updateStates() {
        if (getPreferenceScreen() == null) return;
        PreferenceCategory category = findPreference("devices");
        if (category == null) return;
        category.removeAll();
        try {
            JSONObject devices = new JSONObject(status("devices"));
            java.util.Iterator<String> ids = devices.keys();
            while (ids.hasNext()) {
                String id = ids.next();
                JSONObject d = new JSONObject(devices.getString(id));
                Preference p = new Preference(getContext());
                p.setTitle(d.optString("name"));
                p.setSummary(stateLabel(d.optString("state")));
                p.setSelectable(false);
                category.addPreference(p);
            }
        } catch (Exception ignored) {
        }
        category.setVisible(category.getPreferenceCount() > 0);
    }

    private void setup() {
        LinearLayout box = new LinearLayout(getContext());
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad, pad, pad);
        EditText group = new EditText(getContext());
        group.setHint(R.string.clipp_group);
        group.setSingleLine(true);
        group.setText(config.optString("group"));
        box.addView(group);
        EditText password = new EditText(getContext());
        password.setHint(R.string.clipp_password);
        password.setSingleLine(true);
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        box.addView(password);
        TextView note = new TextView(getContext());
        note.setText(R.string.clipp_group_note);
        box.addView(note);
        AlertDialog dialog =
                new AlertDialog.Builder(getContext())
                        .setTitle(R.string.clipp_group)
                        .setView(box)
                        .setNegativeButton(android.R.string.cancel, null)
                        .setPositiveButton(R.string.clipboard_sync_save, null)
                        .create();
        dialog.setOnShowListener(
                d ->
                        dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                                .setOnClickListener(
                                        v -> {
                                            String name = group.getText().toString(),
                                                    secret = password.getText().toString();
                                            if (name.isEmpty() || secret.length() < 8) {
                                                password.setError(
                                                        getString(R.string.clipboard_sync_invalid));
                                                return;
                                            }
                                            Context app = getContext().getApplicationContext();
                                            preparing = true;
                                            dialog.dismiss();
                                            password.setText("");
                                            build();
                                            new Thread(
                                                            () -> {
                                                                boolean ok = true;
                                                                try {
                                                                    Bundle args = new Bundle();
                                                                    args.putString("group", name);
                                                                    args.putString(
                                                                            "password", secret);
                                                                    app.getContentResolver()
                                                                            .call(
                                                                                    ClippContract
                                                                                            .CONFIG,
                                                                                    "setup",
                                                                                    null,
                                                                                    args);
                                                                    args.clear();
                                                                } catch (Exception e) {
                                                                    ok = false;
                                                                }
                                                                boolean success = ok;
                                                                main.post(
                                                                        () -> {
                                                                            preparing = false;
                                                                            if (!isAdded()) return;
                                                                            read();
                                                                            build();
                                                                            Toast.makeText(
                                                                                            getContext(),
                                                                                            success
                                                                                                    ? R
                                                                                                            .string
                                                                                                            .clipp_ready
                                                                                                    : R
                                                                                                            .string
                                                                                                            .clipboard_sync_transfer_error,
                                                                                            Toast
                                                                                                    .LENGTH_LONG)
                                                                                    .show();
                                                                        });
                                                            },
                                                            "ClippGroupSetup")
                                                    .start();
                                        }));
        dialog.show();
    }
}
