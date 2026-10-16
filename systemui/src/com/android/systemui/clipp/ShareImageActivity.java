// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import com.android.systemui.res.R;

/** NoDisplay share target. Delegate the temporary URI grant before finishing. */
public final class ShareImageActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            Intent share = getIntent();
            Uri image = share.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
            if (!Intent.ACTION_SEND.equals(share.getAction())
                    || share.getType() == null
                    || !share.getType().startsWith("image/")
                    || image == null
                    || !"content".equals(image.getScheme())) return;
            // ServiceRecord owns the forwarded grant while the worker copies the image.
            // Finishing this invisible activity must not revoke access mid-copy.
            startService(
                    new Intent(this, ShareImageService.class)
                            .setDataAndType(image, share.getType())
                            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION));
        } catch (RuntimeException error) {
            Log.w("ClippShare", "Cannot accept shared image", error);
            Toast.makeText(this, R.string.clipp_share_failed, Toast.LENGTH_SHORT).show();
        } finally {
            finish();
        }
    }
}
