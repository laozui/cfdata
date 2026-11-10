package com.laozui.cfdata;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 管理打包在 jniLibs 里的 Go 可执行核心（libcfdata.so）。
 *
 * Android 从 API 29 起禁止执行应用可写目录下的文件（W^X），因此 Go 二进制必须以
 * lib*.so 形式放进 jniLibs，由系统解压到只读的 nativeLibraryDir 后再执行。
 * 清单里必须保留 android:extractNativeLibs="true"。
 */
public class CoreProcess {
    public static final int PORT = 18080;
    private static final String TAG = "cfdata-core";
    private static final String[] ASSETS = {"ips-v4.txt", "locations.json", "cacert.pem"};

    private final Context ctx;
    private final File dataDir;
    private final File logFile;
    private Process process;
    private volatile boolean running;

    public CoreProcess(Context context) {
        this.ctx = context.getApplicationContext();
        this.dataDir = new File(ctx.getFilesDir(), "cfdata");
        this.logFile = new File(dataDir, "cfdata.log");
    }

    public String getLogPath() {
        return logFile.getAbsolutePath();
    }

    /** 把 IP 库、数据中心库、CA 根证书释放到私有目录：完全不依赖首次联网下载。 */
    public void ensureAssets() {
        if (!dataDir.exists() && !dataDir.mkdirs()) {
            appendLog("无法创建数据目录 " + dataDir);
            return;
        }
        for (String name : ASSETS) {
            File dst = new File(dataDir, name);
            if (dst.exists() && dst.length() > 0) continue;
            try (InputStream in = ctx.getAssets().open(name);
                 OutputStream out = new FileOutputStream(dst)) {
                byte[] buf = new byte[16384];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                appendLog("内置资源就绪: " + name + " (" + dst.length() + " 字节)");
            } catch (IOException e) {
                appendLog("释放资源失败 " + name + ": " + e.getMessage());
            }
        }
    }

    private String findBinary() {
        String libDir = ctx.getApplicationInfo().nativeLibraryDir;
        File[] files = new File(libDir).listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.getName().startsWith("libcfdata") && f.getName().endsWith(".so")) {
                    f.setExecutable(true, false);
                    return f.getAbsolutePath();
                }
            }
        }
        appendLog("未找到 libcfdata.so，nativeLibraryDir=" + libDir);
        return null;
    }

    public boolean start() {
        if (running && isAlive()) return true;
        ensureAssets();
        String bin = findBinary();
        if (bin == null) return false;

        try {
            ProcessBuilder pb = new ProcessBuilder(
                    bin,
                    "-port", String.valueOf(PORT),
                    "-data-dir", dataDir.getAbsolutePath(),
                    "-sample", "1200",
                    "-scan-timeout", "1500");
            pb.directory(dataDir);
            pb.redirectErrorStream(true);
            // CGO_ENABLED=0 的 Go 在 Android 上可能读不到系统根证书，
            // 显式指向内置的 Mozilla CA bundle，保证「重置资源」后仍能联网下载。
            pb.environment().put("SSL_CERT_FILE", new File(dataDir, "cacert.pem").getAbsolutePath());
            pb.environment().put("SSL_CERT_DIR", dataDir.getAbsolutePath());
            pb.environment().put("TMPDIR", ctx.getCacheDir().getAbsolutePath());
            appendLog("启动核心: " + bin);
            process = pb.start();
            running = true;
            startLogPump();
            return waitForPort(20000);
        } catch (Exception e) {
            appendLog("启动失败: " + e);
            return false;
        }
    }

    private boolean waitForPort(int timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (!isAlive()) {
                appendLog("核心进程提前退出");
                return false;
            }
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", PORT), 250);
                appendLog("本地服务就绪: 127.0.0.1:" + PORT);
                return true;
            } catch (IOException ignored) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    return false;
                }
            }
        }
        appendLog("等待本地服务超时");
        return false;
    }

    private void startLogPump() {
        final Process p = process;
        new Thread(() -> {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) appendLog(line);
            } catch (Exception e) {
                appendLog("日志流结束: " + e.getMessage());
            }
        }, "cfdata-log-pump").start();
    }

    private synchronized void appendLog(String line) {
        Log.d(TAG, line);
        try {
            if (logFile.exists() && logFile.length() > 128 * 1024) {
                // 日志滚回，避免长期占空间
                if (!logFile.delete()) logFile.createNewFile();
            }
            String stamp = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
            try (FileWriter w = new FileWriter(logFile, true)) {
                w.write("[" + stamp + "] " + line + "\n");
            }
        } catch (IOException ignored) {
        }
    }

    public synchronized String readLog() {
        StringBuilder sb = new StringBuilder();
        if (!logFile.exists()) return "（暂无日志）";
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new java.io.FileInputStream(logFile), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        } catch (IOException e) {
            sb.append("读取日志失败: ").append(e.getMessage());
        }
        return sb.length() == 0 ? "（暂无日志）" : sb.toString();
    }

    private boolean isAlive() {
        if (process == null) return false;
        try {
            return process.isAlive();
        } catch (Throwable t) {
            return true;
        }
    }

    public void stop() {
        running = false;
        Process p = process;
        if (p != null) {
            try {
                p.destroy();
                p.waitFor();
            } catch (Exception ignored) {
            }
            process = null;
            appendLog("核心已停止");
        }
    }
}
