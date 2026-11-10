package com.laozui.cfdata;

import android.content.Context;
import android.content.SharedPreferences;
import android.webkit.JavascriptInterface;

/** 网页 window.Android 桥。JS 接口运行在 WebView 的 JavaBridge 线程，UI 操作统一切回主线程。 */
public class JsBridge {
    private final MainActivity activity;
    private final SharedPreferences prefs;

    JsBridge(MainActivity activity) {
        this.activity = activity;
        this.prefs = activity.getSharedPreferences("cfdata", Context.MODE_PRIVATE);
    }

    @JavascriptInterface
    public void toast(String msg) {
        activity.toast(msg);
    }

    @JavascriptInterface
    public void copyText(String text) {
        activity.copyToClipboard(text);
    }

    @JavascriptInterface
    public void saveTxt(String text, String name) {
        activity.runOnUiThread(() -> activity.saveTxt(text, name));
    }

    @JavascriptInterface
    public void shareText(String text) {
        activity.runOnUiThread(() -> activity.shareText(text));
    }

    @JavascriptInterface
    public void showDiag(String msg) {
        activity.runOnUiThread(() -> activity.showInfo("网络自检", msg));
    }

    @JavascriptInterface
    public void saveSpeedUrl(String url) {
        prefs.edit().putString("speed_url", url).apply();
    }

    @JavascriptInterface
    public String getSpeedUrl() {
        return prefs.getString("speed_url", "");
    }

    /** 网页把全量 IP 结果回传，由原生执行复制 / 保存 / 分享 / 全选查看。 */
    @JavascriptInterface
    public void onIPList(String action, String text, int count) {
        activity.runOnUiThread(() -> activity.onIPList(action, text, count));
    }
}
