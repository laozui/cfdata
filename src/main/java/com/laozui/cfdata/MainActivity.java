package com.laozui.cfdata;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.util.Log;
import android.view.ViewGroup;
import android.webkit.JsResult;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int REQ_SAVE_TXT = 1001;
    private static final String LOCAL_BASE = "http://127.0.0.1:18080";

    private WebView web;
    private TextView statusView;
    private CoreProcess core;
    private SharedPreferences prefs;
    private String pendingSaveText;
    private String pendingSaveName;
    private boolean localMode = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences("cfdata", MODE_PRIVATE);
        core = new CoreProcess(this);
        statusView = findViewById(R.id.statusView);
        web = findViewById(R.id.webView);
        setupWebView();

        findViewById(R.id.btnCopy).setOnClickListener(v -> requestIPs("copy"));
        findViewById(R.id.btnCopy).setOnLongClickListener(v -> {
            requestIPs("view");
            return true;
        });
        findViewById(R.id.btnSave).setOnClickListener(v -> requestIPs("save"));
        findViewById(R.id.btnShare).setOnClickListener(v -> requestIPs("share"));
        findViewById(R.id.btnSettings).setOnClickListener(v -> showSettings());
        findViewById(R.id.btnLog).setOnClickListener(v -> showInfo("核心日志", core.readLog()));

        startOrLoad();
    }

    @SuppressWarnings("SetJavaScriptEnabled")
    private void setupWebView() {
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(true);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        s.setUseWideViewPort(true);
        s.setLoadWithOverviewMode(true);
        s.setCacheMode(WebSettings.LOAD_NO_CACHE);
        s.setTextZoom(100);

        web.addJavascriptInterface(new JsBridge(this), "Android");
        web.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                statusView.setText("已连接 · " + (localMode ? "本机核心" : "远程服务"));
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    statusView.setText("页面加载失败，请检查服务地址");
                }
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onJsAlert(WebView view, String url, String message, final JsResult result) {
                new AlertDialog.Builder(MainActivity.this)
                        .setMessage(message)
                        .setPositiveButton("确定", (d, w) -> result.confirm())
                        .setOnCancelListener(d -> result.cancel())
                        .show();
                return true;
            }

            @Override
            public boolean onJsConfirm(WebView view, String url, String message, final JsResult result) {
                new AlertDialog.Builder(MainActivity.this)
                        .setMessage(message)
                        .setPositiveButton("确定", (d, w) -> result.confirm())
                        .setNegativeButton("取消", (d, w) -> result.cancel())
                        .setOnCancelListener(d -> result.cancel())
                        .show();
                return true;
            }
        });
    }

    private void startOrLoad() {
        localMode = prefs.getString("server", "").trim().isEmpty();
        final String base = currentBaseUrl();
        if (!localMode) {
            core.stop();
            statusView.setText("正在连接远程服务...");
            web.loadUrl(base + "/");
            return;
        }
        statusView.setText("正在启动本机扫描核心...");
        new Thread(() -> {
            boolean ok = core.start();
            runOnUiThread(() -> {
                if (isFinishing()) return;
                if (ok) {
                    web.loadUrl(base + "/");
                } else {
                    statusView.setText("本机核心启动失败");
                    showInfo("启动失败",
                            "Go 扫描核心没能启动。\n\n"
                                    + "点「设置」可改为连接电脑上已跑起来的 cfdata 服务（如 192.168.1.5:8080）。\n\n"
                                    + "—— 核心日志 ——\n" + core.readLog());
                }
            });
        }, "cfdata-starter").start();
    }

    private String currentBaseUrl() {
        String s = prefs.getString("server", "").trim();
        if (s.isEmpty()) return LOCAL_BASE;
        if (!s.startsWith("http://") && !s.startsWith("https://")) s = "http://" + s;
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    /** 底部工具条入口：原生直接拉 /api/ips 拿全量，失败才回落让网页抓表格 DOM。 */
    private void requestIPs(final String action) {
        final String base = currentBaseUrl();
        statusView.setText("正在读取全部 IP...");
        new Thread(() -> {
            final String text = fetchIpsText(base);
            runOnUiThread(() -> {
                if (isFinishing()) return;
                if (text != null && !text.isEmpty()) {
                    onIPList(action, text, countLines(text));
                } else {
                    web.evaluateJavascript("cfdataRequestIPs('" + action + "')", null);
                    web.postDelayed(() -> {
                        if (statusView.getText().toString().startsWith("正在读取")) {
                            statusView.setText("读取失败，请确认服务版本 / 网络");
                        }
                    }, 3500);
                }
            });
        }, "cfdata-fetch-ips").start();
    }

    private String fetchIpsText(String base) {
        String raw = httpGet(base + "/api/ips?format=txt", 15000);
        if (raw == null) return null;
        StringBuilder sb = new StringBuilder();
        for (String line : raw.split("\\r?\\n")) {
            String v = line.trim();
            if (v.isEmpty()) continue;
            // 旧版服务没有 /api/ips，"/" 兜底会返回 index.html —— 直接判为不可用
            if (!v.matches("[0-9a-fA-F:.]+")) return null;
            if (sb.length() > 0) sb.append('\n');
            sb.append(v);
        }
        return sb.toString();
    }

    private String httpGet(String urlStr, int readTimeout) {
        HttpURLConnection conn = null;
        try {
            URL u = new URL(urlStr);
            conn = (HttpURLConnection) u.openConnection();
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(readTimeout);
            conn.setRequestProperty("Cache-Control", "no-cache");
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) return null;
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Exception e) {
            Log.w("cfdata-http", e);
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** JS 桥与原生 HTTP 两条路径共用的结果处理器。 */
    void onIPList(String action, String text, int count) {
        statusView.setText("就绪 · " + count + " 个 IP");
        if (text == null || text.trim().isEmpty()) {
            toast("还没有扫描到 IP，先跑一次扫描");
            return;
        }
        String plain = text.endsWith("\n") ? text : text + "\n";
        switch (action) {
            case "copy":
                copyToClipboard(text);
                toast("已复制 " + count + " 个 IP，可直接粘贴");
                break;
            case "save":
                saveTxt(plain, defaultFileName());
                break;
            case "share":
                shareText(text);
                break;
            case "view":
                showSelectableList(text, count);
                break;
            default:
                break;
        }
    }

    void copyToClipboard(String text) {
        runOnUiThread(() -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("CF IP", text));
        });
    }

    void saveTxt(String text, String name) {
        pendingSaveText = text;
        pendingSaveName = name;
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE, name);
        try {
            startActivityForResult(intent, REQ_SAVE_TXT);
        } catch (Exception e) {
            toast("无法打开保存对话框: " + e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_SAVE_TXT || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        final Uri uri = data.getData();
        final String text = pendingSaveText;
        final String name = pendingSaveName;
        new Thread(() -> {
            boolean ok = false;
            OutputStream os = null;
            try {
                os = getContentResolver().openOutputStream(uri, "wt");
                if (os != null) {
                    os.write(text.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                    ok = true;
                }
            } catch (Exception e) {
                Log.w("cfdata-save", e);
            } finally {
                if (os != null) try { os.close(); } catch (Exception ignored) { }
            }
            final boolean result = ok;
            runOnUiThread(() -> toast(result
                    ? "已保存 " + name + "（" + countLines(text) + " 个 IP）"
                    : "保存失败，请重试"));
        }, "cfdata-save").start();
    }

    void shareText(String text) {
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TEXT, text);
        intent.putExtra(Intent.EXTRA_SUBJECT, "CF 优选 IP 列表");
        try {
            startActivity(Intent.createChooser(intent, "分享 IP 列表"));
        } catch (Exception e) {
            toast("分享失败: " + e.getMessage());
        }
    }

    /** 长按「全选复制」：给出可直接长按全选、编辑、复制的纯文本列表。 */
    private void showSelectableList(String text, int count) {
        EditText et = new EditText(this);
        et.setText(text);
        et.setKeyListener(null);
        et.setTextIsSelectable(true);
        et.setTextSize(12);
        et.setTypeface(Typeface.MONOSPACE);
        et.setTextColor(Color.parseColor("#1F2937"));
        et.setBackgroundColor(Color.parseColor("#F6F8FA"));
        int pad = dp(12);
        et.setPadding(pad, pad, pad, pad);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(et, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        et.post(() -> {
            et.requestFocus();
            et.selectAll();
        });
        new AlertDialog.Builder(this)
                .setTitle("全部 IP · " + count + " 个（已全选）")
                .setView(scroll)
                .setPositiveButton("复制", (d, w) -> {
                    copyToClipboard(et.getText().toString());
                    toast("已复制");
                })
                .setNeutralButton("保存 TXT", (d, w) -> saveTxt(et.getText().toString() + "\n", defaultFileName()))
                .setNegativeButton("关闭", null)
                .show();
    }

    private void showSettings() {
        final EditText input = new EditText(this);
        input.setHint("留空 = 本机扫描；或填 192.168.1.5:8080");
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        input.setText(prefs.getString("server", ""));
        input.setSingleLine(true);
        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(20);
        wrap.setPadding(pad, dp(8), pad, 0);
        wrap.addView(input, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        new AlertDialog.Builder(this)
                .setTitle("服务地址")
                .setMessage("默认在手机本机运行扫描核心。若要用电脑上已跑起来的 cfdata 服务，填它的局域网地址。")
                .setView(wrap)
                .setPositiveButton("保存并重载", (d, w) -> {
                    prefs.edit().putString("server", input.getText().toString().trim()).apply();
                    startOrLoad();
                })
                .setNeutralButton("网络自检", (d, w) -> runDiag())
                .setNegativeButton("取消", null)
                .show();
    }

    private void runDiag() {
        statusView.setText("正在自检（5~15 秒）...");
        final String base = currentBaseUrl();
        new Thread(() -> {
            final String raw = httpGet(base + "/api/diag?probe=1", 60000);
            runOnUiThread(() -> {
                if (isFinishing()) return;
                statusView.setText("就绪");
                showInfo("网络自检", raw == null
                        ? "自检失败：服务未连接，或对方是旧版 cfdata（无 /api/diag）。"
                        : prettyDiag(raw));
            });
        }, "cfdata-diag").start();
    }

    private String prettyDiag(String raw) {
        try {
            JSONObject d = new JSONObject(raw);
            JSONObject res = d.optJSONObject("resources");
            JSONObject v4 = res == null ? null : res.optJSONObject("ips-v4.txt");
            JSONObject loc = res == null ? null : res.optJSONObject("locations.json");
            JSONObject p = d.optJSONObject("probe");
            JSONObject s = d.optJSONObject("probe_stats");
            JSONObject prm = d.optJSONObject("params");

            StringBuilder b = new StringBuilder();
            b.append("内置资源\n")
                    .append("  IPv4 子网库：").append(v4 != null && v4.optBoolean("exists")
                    ? "已就绪（" + v4.optInt("bytes") + " 字节）" : "缺失，需要联网下载").append('\n')
                    .append("  数据中心库：").append(loc != null && loc.optBoolean("exists")
                    ? "已就绪" : "缺失").append('\n');

            if (p != null && p.optBoolean("ran")) {
                b.append("\n抽样探测 ").append(p.optInt("sample"))
                        .append(" 个 → 有效 ").append(p.optInt("valid")).append(" 个\n")
                        .append("  TCP 通 ").append(p.optInt("tcp_ok"))
                        .append(" / HTTP 响应 ").append(p.optInt("http_ok"))
                        .append(" / CF-RAY ").append(p.optInt("cf_ray"))
                        .append(" / TLS 兜底 ").append(p.optInt("tls_other")).append('\n');
                if (p.optInt("valid") == 0) {
                    if (p.optInt("tcp_ok") == 0) {
                        b.append("\n结论：TCP 完全不通 → 检查联网权限、关闭 VPN，或换 WiFi 再试。");
                    } else if (p.optInt("http_ok") == 0) {
                        b.append("\n结论：连得上但读不到 HTTP 响应 → 把超时调大，或打开网页里的「宽松模式」。");
                    } else {
                        b.append("\n结论：有响应但没有 Cloudflare 特征 → 多半被运营商 80 端口劫持，换网络或换端口。");
                    }
                } else {
                    b.append("\n结论：探测链路正常，直接开始扫描即可。");
                }
            } else {
                b.append("\n本轮未执行抽样探测。");
            }

            if (s != null) {
                b.append("\n\n本轮累计\n")
                        .append("  TCP 通 ").append(s.optLong("tcp_ok"))
                        .append(" / HTTP ").append(s.optLong("http_ok"))
                        .append(" / CF-RAY ").append(s.optLong("cf_ray"))
                        .append(" / TLS ").append(s.optLong("tls_ok"))
                        .append(" / 未命中 ").append(s.optLong("no_cf")).append('\n');
            }
            if (prm != null) {
                b.append("\n参数：超时 ").append(prm.optLong("timeout_ms"))
                        .append("ms / 采样 ").append(prm.optInt("sample"))
                        .append(" / 宽松 ").append(prm.optBoolean("loose") ? "开" : "关").append('\n');
            }
            b.append("\n当前结果：扫描 ").append(d.optInt("scan_results"))
                    .append(" 个 / 详细测试 ").append(d.optInt("test_results")).append(" 个");
            return b.toString();
        } catch (Exception e) {
            return raw;
        }
    }

    void showInfo(String title, String msg) {
        TextView tv = new TextView(this);
        tv.setText(msg);
        tv.setTextIsSelectable(true);
        tv.setTextSize(12);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextColor(Color.parseColor("#1F2937"));
        int pad = dp(16);
        tv.setPadding(pad, pad, pad, pad);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(tv, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(scroll)
                .setPositiveButton("关闭", null)
                .show();
    }

    void toast(String msg) {
        runOnUiThread(() -> Toast.makeText(getApplicationContext(), msg, Toast.LENGTH_SHORT).show());
    }

    private String defaultFileName() {
        return "cf_ips_" + new SimpleDateFormat("yyyyMMdd_HHmm", Locale.getDefault()).format(new Date()) + ".txt";
    }

    private static int countLines(String text) {
        if (text == null) return 0;
        String t = text.trim();
        if (t.isEmpty()) return 0;
        return t.split("\\r?\\n").length;
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density);
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        core.stop();
        if (web != null) web.destroy();
        super.onDestroy();
    }
}
