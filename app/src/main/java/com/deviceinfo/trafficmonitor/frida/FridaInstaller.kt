package com.deviceinfo.trafficmonitor.frida

import android.content.Context
import android.os.Build
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

object FridaInstaller {

    const val FRIDA_VERSION = "16.5.9"
    const val BASE_DIR = "/data/local/tmp/access_monitor"
    const val GADGET_PATH = "$BASE_DIR/libfrida-gadget.so"
    const val CONFIG_PATH = "$BASE_DIR/libfrida-gadget.config.so"
    const val HOOKS_PATH = "$BASE_DIR/identifier_hooks.js"
    const val EVENTS_PATH = "$BASE_DIR/events.jsonl"

    @Volatile
    var status: FridaStatus = FridaStatus.NOT_INSTALLED

    @Volatile
    var lastError: String? = null

    enum class FridaStatus {
        NOT_INSTALLED,
        DOWNLOADING,
        READY,
        INJECTED,
        ERROR
    }

    suspend fun ensureReady(context: Context): Boolean = withContext(Dispatchers.IO) {
        if (!RootShell.isRootAvailable()) {
            status = FridaStatus.ERROR
            lastError = "Root недоступен"
            return@withContext false
        }

        prepareDirectory()
        copyAssetToDevice(context, "frida/libfrida-gadget.config.so", CONFIG_PATH)
        copyAssetToDevice(context, "frida/identifier_hooks.js", HOOKS_PATH)

        if (!isGadgetPresent()) {
            status = FridaStatus.DOWNLOADING
            if (!downloadGadget()) {
                status = FridaStatus.ERROR
                lastError = "Не удалось скачать frida-gadget $FRIDA_VERSION"
                return@withContext false
            }
        }

        status = FridaStatus.READY
        lastError = null
        true
    }

    private fun prepareDirectory() {
        RootShell.execAndRead("mkdir -p $BASE_DIR && chmod 777 $BASE_DIR")
        RootShell.execAndRead("touch $EVENTS_PATH && chmod 666 $EVENTS_PATH")
    }

    private fun copyAssetToDevice(context: Context, assetPath: String, devicePath: String) {
        val local = File(context.filesDir, assetPath.replace('/', '_'))
        context.assets.open(assetPath).use { input ->
            local.outputStream().use { output -> input.copyTo(output) }
        }
        RootShell.execAndRead("cp ${local.absolutePath} $devicePath && chmod 644 $devicePath")
    }

    fun prepareHooksForPackage(packageName: String, context: Context) {
        val template = context.assets.open("frida/identifier_hooks.js")
            .bufferedReader().readText()
            .replace("__TARGET_PACKAGE__", packageName)
        val local = File(context.filesDir, "identifier_hooks_active.js")
        local.writeText(template)
        RootShell.execAndRead("cp ${local.absolutePath} $HOOKS_PATH && chmod 644 $HOOKS_PATH")
    }

    private fun isGadgetPresent(): Boolean {
        return RootShell.execAndRead("test -f $GADGET_PATH && echo ok").trim() == "ok"
    }

    private fun downloadGadget(): Boolean {
        val abi = resolveDeviceAbi()
        val url = "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/" +
            "frida-gadget-$FRIDA_VERSION-android-$abi.so.xz"
        val xzPath = "$BASE_DIR/gadget.so.xz"
        val extracted = "$BASE_DIR/frida-gadget-$FRIDA_VERSION-android-$abi.so"

        return try {
            downloadFile(url, xzPath)
            val decompress = RootShell.execAndRead(
                "which xz >/dev/null 2>&1 && xz -d -f $xzPath || unxz -f $xzPath; " +
                    "test -f $extracted && mv $extracted $GADGET_PATH && chmod 755 $GADGET_PATH && echo ok"
            )
            decompress.trim() == "ok"
        } catch (e: Exception) {
            lastError = e.message
            false
        }
    }

    private fun resolveDeviceAbi(): String {
        val primary = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64"
        return when {
            primary.contains("arm64") -> "arm64"
            primary.contains("armeabi") || primary.contains("arm") -> "arm"
            primary.contains("x86_64") -> "x86_64"
            primary.contains("x86") -> "x86"
            else -> "arm64"
        }
    }

    private fun downloadFile(urlString: String, destPath: String) {
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        connection.connectTimeout = 30_000
        connection.readTimeout = 120_000
        connection.connect()

        val localTemp = File.createTempFile("gadget_", ".xz")
        connection.inputStream.use { input ->
            localTemp.outputStream().use { output -> input.copyTo(output) }
        }
        RootShell.execAndRead("cp ${localTemp.absolutePath} $destPath && chmod 644 $destPath")
        localTemp.delete()
    }

    suspend fun injectViaWrap(packageName: String): Boolean = withContext(Dispatchers.IO) {
        clearInjection(packageName)
        val result = RootShell.execAndRead(
            "setprop wrap.$packageName LD_PRELOAD=$GADGET_PATH && echo ok"
        )
        if (!result.contains("ok")) {
            lastError = "setprop wrap failed"
            return@withContext false
        }
        status = FridaStatus.INJECTED
        RootShell.execAndRead("am force-stop $packageName")
        delay(400)
        RootShell.exec("monkey -p $packageName -c android.intent.category.LAUNCHER 1")
        true
    }

    fun clearInjection(packageName: String) {
        RootShell.execAndRead("setprop wrap.$packageName ''")
        if (status == FridaStatus.INJECTED) {
            status = FridaStatus.READY
        }
    }

    fun clearEvents() {
        RootShell.execAndRead("truncate -s 0 $EVENTS_PATH 2>/dev/null || echo -n > $EVENTS_PATH")
    }

    fun resolveFridaCli(): String? {
        val candidates = listOf(
            "/data/local/tmp/frida",
            "/data/local/tmp/access_monitor/frida",
            "/data/data/com.termux/files/usr/bin/frida",
            "/data/adb/modules/frida/frida"
        )
        for (path in candidates) {
            if (RootShell.execAndRead("test -x $path && echo ok").trim() == "ok") return path
        }
        return RootShell.execAndRead("which frida 2>/dev/null").trim()
            .takeIf { it.isNotEmpty() && !it.contains("not found") }
    }

    fun statusLabel(): String = when (status) {
        FridaStatus.NOT_INSTALLED -> "Frida: не установлен"
        FridaStatus.DOWNLOADING -> "Frida: загрузка gadget…"
        FridaStatus.READY -> "Frida: готов"
        FridaStatus.INJECTED -> "Frida: хуки активны"
        FridaStatus.ERROR -> "Frida: ошибка (${lastError ?: "unknown"})"
    }
}
