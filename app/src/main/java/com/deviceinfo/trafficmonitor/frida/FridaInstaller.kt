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
        EXTRACTING,
        DOWNLOADING,
        READY,
        INJECTED,
        ERROR
    }

    /** Вызывается при старте приложения — подготавливает Frida заранее. */
    suspend fun prepareOnAppStart(context: Context) {
        ensureReady(context)
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
            status = FridaStatus.EXTRACTING
            if (!deployGadgetFromApp(context)) {
                status = FridaStatus.DOWNLOADING
                if (!downloadGadget(context)) {
                    status = FridaStatus.ERROR
                    lastError = lastError ?: "Frida gadget недоступен"
                    return@withContext false
                }
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

    /** Извлекает встроенный в APK frida-gadget для текущего ABI. */
    private fun deployGadgetFromApp(context: Context): Boolean {
        val abiFolder = resolveAssetAbiFolder()
        val assetPath = "frida/$abiFolder/libfrida-gadget.so"
        val cacheFile = File(context.filesDir, "frida-gadget-$abiFolder.so")

        return try {
            if (!cacheFile.exists() || cacheFile.length() == 0L) {
                context.assets.open(assetPath).use { input ->
                    cacheFile.outputStream().use { output -> input.copyTo(output) }
                }
            }
            RootShell.execAndRead(
                "cp ${cacheFile.absolutePath} $GADGET_PATH && chmod 755 $GADGET_PATH && echo ok"
            ).trim() == "ok"
        } catch (e: Exception) {
            lastError = "Встроенный gadget ($assetPath): ${e.message}"
            false
        }
    }

    private fun resolveAssetAbiFolder(): String {
        val primary = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        return when {
            primary.contains("arm64") -> "arm64-v8a"
            primary.contains("armeabi") || primary == "arm" -> "armeabi-v7a"
            primary.contains("x86_64") -> "x86_64"
            primary.contains("x86") -> "x86"
            else -> "arm64-v8a"
        }
    }

    /** Запасной вариант — скачать с GitHub, если ABI не встроен в APK. */
    private fun downloadGadget(context: Context): Boolean {
        val abi = resolveDownloadAbi()
        val url = "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/" +
            "frida-gadget-$FRIDA_VERSION-android-$abi.so.xz"
        val cacheXz = File(context.cacheDir, "frida-gadget-$abi.so.xz")
        val cacheSo = File(cacheXz.parent, cacheXz.name.removeSuffix(".xz"))

        return try {
            downloadFile(url, cacheXz)
            RootShell.execAndRead(
                "which xz >/dev/null 2>&1 && xz -d -f ${cacheXz.absolutePath} || unxz -f ${cacheXz.absolutePath}"
            )
            if (!cacheSo.exists()) {
                lastError = "Не удалось распаковать frida-gadget"
                return false
            }
            RootShell.execAndRead(
                "cp ${cacheSo.absolutePath} $GADGET_PATH && chmod 755 $GADGET_PATH && echo ok"
            ).trim() == "ok"
        } catch (e: Exception) {
            lastError = e.message
            false
        }
    }

    private fun resolveDownloadAbi(): String {
        val primary = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64"
        return when {
            primary.contains("arm64") -> "arm64"
            primary.contains("armeabi") || primary.contains("arm") -> "arm"
            primary.contains("x86_64") -> "x86_64"
            primary.contains("x86") -> "x86"
            else -> "arm64"
        }
    }

    private fun downloadFile(urlString: String, destFile: File) {
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        connection.connectTimeout = 30_000
        connection.readTimeout = 120_000
        connection.connect()
        connection.inputStream.use { input ->
            destFile.outputStream().use { output -> input.copyTo(output) }
        }
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

    fun statusLabel(): String = when (status) {
        FridaStatus.NOT_INSTALLED -> "Frida: не установлен"
        FridaStatus.EXTRACTING -> "Frida: установка из APK…"
        FridaStatus.DOWNLOADING -> "Frida: загрузка…"
        FridaStatus.READY -> "Frida: встроен, готов"
        FridaStatus.INJECTED -> "Frida: хуки активны"
        FridaStatus.ERROR -> "Frida: ошибка (${lastError ?: "unknown"})"
    }
}
