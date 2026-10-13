// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package org.evolution.settings.clipp;

import android.app.AlertDialog;
import android.content.*;
import android.database.ContentObserver;
import android.os.*;
import android.text.*;
import android.text.method.LinkMovementMethod;
import android.text.style.URLSpan;
import android.widget.*;

import androidx.preference.*;

import com.android.settings.R;
import com.android.settings.SettingsPreferenceFragment;

import org.evolution.clipp.ClippContract;
import org.json.*;

public final class ClippSettings extends SettingsPreferenceFragment {
    private JSONObject config = new JSONObject();
    private final Handler main = new Handler(Looper.getMainLooper());
    private boolean resumed, preparing;
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
        resumed = true;
        getActivity().setTitle(R.string.clipboard_sync_title);
        getContext()
                .getContentResolver()
                .registerContentObserver(ClippContract.STATUS, false, observer);
        read();
        build();
    }

    @Override
    public void onPause() {
        resumed = false;
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
                R.string.clipboard_sync_title,
                R.string.clipboard_sync_summary,
                false);
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
        screen.addPreference(group);
        if (!config.optString("fingerprint").isEmpty()) {
            Preference fp = new Preference(getContext());
            fp.setTitle(R.string.clipp_fingerprint);
            fp.setSummary(config.optString("fingerprint"));
            fp.setSelectable(false);
            screen.addPreference(fp);
        }
        toggle(screen, "text", R.string.clipboard_sync_text, 0, true);
        toggle(
                screen,
                "images",
                R.string.clipboard_sync_images,
                R.string.clipboard_sync_images_summary,
                true);
        ListPreference size = new ListPreference(getContext());
        size.setPersistent(false);
        size.setTitle(R.string.clipboard_sync_size);
        size.setEntries(new String[] {"5 MB", "10 MB", "20 MB", "50 MB"});
        size.setEntryValues(new String[] {"5", "10", "20", "50"});
        size.setValue(Integer.toString(config.optInt("maxImageMb", 20)));
        size.setSummaryProvider(ListPreference.SimpleSummaryProvider.getInstance());
        size.setOnPreferenceChangeListener(
                (p, v) -> {
                    try {
                        change("maxImageMb", Integer.parseInt(v.toString()));
                        return true;
                    } catch (Exception e) {
                        return false;
                    }
                });
        screen.addPreference(size);
        Preference background = new Preference(getContext());
        background.setTitle(R.string.clipp_background);
        background.setSummary(R.string.clipp_background_summary);
        background.setSelectable(false);
        screen.addPreference(background);
        Preference state = new Preference(getContext());
        state.setKey("network_state");
        state.setTitle(R.string.clipp_network);
        state.setSelectable(false);
        screen.addPreference(state);
        PreferenceCategory devices = new PreferenceCategory(getContext());
        devices.setKey("devices");
        devices.setTitle(R.string.clipboard_sync_servers);
        screen.addPreference(devices);
        Preference note =
                new Preference(getContext()) {
                    @Override
                    public void onBindViewHolder(PreferenceViewHolder holder) {
                        super.onBindViewHolder(holder);
                        TextView text = (TextView) holder.findViewById(android.R.id.summary);
                        if (text != null) {
                            text.setMovementMethod(LinkMovementMethod.getInstance());
                            text.setLinkTextColor(0xff4285f4);
                        }
                    }
                };
        String description = getString(R.string.clipboard_sync_note);
        SpannableString link = new SpannableString(description);
        int start = description.indexOf("Clipp");
        if (start >= 0)
            link.setSpan(
                    new URLSpan("https://github.com/martona/clipp"),
                    start,
                    start + 5,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        note.setSummary(link);
        note.setSelectable(false);
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
            case "waiting_wifi":
                return R.string.clipp_waiting_wifi;
            case "listening":
                return R.string.clipp_discovering;
            case "paused":
                return R.string.clipp_paused;
            default:
                return R.string.clipboard_sync_disconnected;
        }
    }

    private void updateStates() {
        if (getPreferenceScreen() == null) return;
        Preference network = findPreference("network_state");
        if (network != null) network.setSummary(stateLabel(status("network")));
        PreferenceCategory category = findPreference("devices");
        if (category == null) return;
        category.removeAll();
        try {
            JSONObject devices = new JSONObject(status("devices"));
            java.util.Iterator<String> ids = devices.keys();
            int count = 0;
            while (ids.hasNext() && count++ < 5) {
                String id = ids.next();
                JSONObject d = new JSONObject(devices.getString(id));
                Preference p = new Preference(getContext());
                p.setTitle(d.optString("name"));
                p.setSummary(stateLabel(d.optString("state")));
                p.setOnPreferenceClickListener(
                        pref -> {
                            block(id, d.optString("name"));
                            return true;
                        });
                category.addPreference(p);
            }
        } catch (Exception ignored) {
        }
        JSONArray blocked = config.optJSONArray("blocked");
        if (blocked != null && blocked.length() > 0) {
            Preference restore = new Preference(getContext());
            restore.setTitle(R.string.clipp_restore);
            restore.setOnPreferenceClickListener(
                    p -> {
                        try {
                            change("blocked", new JSONArray());
                            build();
                        } catch (Exception ignored) {
                        }
                        return true;
                    });
            category.addPreference(restore);
        }
    }

    private void block(String id, String name) {
        new AlertDialog.Builder(getContext())
                .setTitle(name)
                .setMessage(R.string.clipp_block_note)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(
                        R.string.clipp_block,
                        (d, w) -> {
                            try {
                                JSONArray list = config.optJSONArray("blocked");
                                if (list == null) list = new JSONArray();
                                JSONArray next = new JSONArray(list.toString());
                                next.put(id);
                                change("blocked", next);
                                build();
                            } catch (Exception ignored) {
                            }
                        })
                .show();
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
