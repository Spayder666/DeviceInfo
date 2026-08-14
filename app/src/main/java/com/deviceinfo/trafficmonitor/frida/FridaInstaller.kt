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
    const val SERVER_PATH = "$BASE_DIR/frida-server"
    const val INJECT_PATH = "$BASE_DIR/frida-inject"
    const val INJECT_LOG = "$BASE_DIR/inject.log"

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

    /**
     * Инъекция через frida-inject (ptrace), без LD_PRELOAD/wrap.
     * wrap+gadget на Android 13+ ломает запуск из‑за linker namespace.
     */
    suspend fun injectManual(context: Context, packageName: String, restartApp: Boolean): Boolean =
        withContext(Dispatchers.IO) {
            if (!ensureReady(context)) return@withContext false
            if (!ensureFridaInject(context)) return@withContext false

            prepareHooksForPackage(packageName, context)
            preparePtrace()
            stopInjector()

            val pid = if (restartApp) {
                RootShell.execAndRead("am force-stop $packageName")
                delay(400)
                if (!RootShell.launchApp(packageName)) {
                    lastError = "Не удалось запустить приложение"
                    return@withContext false
                }
                waitForPid(packageName) ?: run {
                    lastError = "Приложение не запустилось (PID не найден)"
                    return@withContext false
                }
            } else {
                RootShell.findPid(packageName) ?: run {
                    lastError = "Приложение не запущено — сначала запустите его"
                    return@withContext false
                }
            }

            if (!startInjector(pid)) {
                return@withContext false
            }

            status = FridaStatus.INJECTED
            lastError = null
            true
        }

    private suspend fun waitForPid(packageName: String, attempts: Int = 20): Int? {
        repeat(attempts) {
            RootShell.findPid(packageName)?.let { return it }
            delay(250)
        }
        return null
    }

    private fun preparePtrace() {
        RootShell.execAndRead("setenforce 0 2>/dev/null")
        RootShell.execAndRead("echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        RootShell.execAndRead("chmod 777 $BASE_DIR && chmod 666 $EVENTS_PATH $HOOKS_PATH 2>/dev/null")
    }

    private fun startInjector(pid: Int): Boolean {
        RootShell.execAndRead("echo -n > $INJECT_LOG")
        val cmd = "$INJECT_PATH -p $pid -s $HOOKS_PATH -e --runtime=qjs"
        RootShell.execDetached("$cmd > $INJECT_LOG 2>&1")

        var lastLog = ""
        repeat(12) {
            Thread.sleep(400)
            lastLog = RootShell.execAndRead("cat $INJECT_LOG 2>/dev/null").trim()
            val running = RootShell.execAndRead(
                "pgrep -f '$INJECT_PATH' 2>/dev/null"
            ).trim().isNotEmpty()
            if (running && !looksLikeInjectFailure(lastLog)) {
                return true
            }
            if (looksLikeInjectFailure(lastLog)) {
                lastError = "frida-inject: ${lastLog.take(220)}"
                return false
            }
        }

        lastError = if (lastLog.isNotBlank()) {
            "frida-inject: ${lastLog.take(220)}"
        } else {
            "frida-inject не запустился (проверьте root / SELinux)"
        }
        return false
    }

    private fun looksLikeInjectFailure(log: String): Boolean {
        if (log.isBlank()) return false
        val lower = log.lowercase()
        return listOf("unable to", "failed", "error:", "permission denied", "not found", "cannot")
            .any { it in lower }
    }

    private fun stopInjector() {
        RootShell.execAndRead("pkill -f '$INJECT_PATH' 2>/dev/null")
    }

    private suspend fun ensureFridaInject(context: Context): Boolean = withContext(Dispatchers.IO) {
        if (RootShell.execAndRead("test -x $INJECT_PATH && echo ok").trim() == "ok") {
            return@withContext true
        }
        status = FridaStatus.EXTRACTING
        if (deployInjectFromApp(context)) return@withContext true
        status = FridaStatus.DOWNLOADING
        if (downloadFridaInject(context)) return@withContext true
        status = FridaStatus.ERROR
        lastError = lastError ?: "frida-inject недоступен"
        false
    }

    private fun deployInjectFromApp(context: Context): Boolean {
        val abiFolder = resolveAssetAbiFolder()
        val assetPath = "frida/$abiFolder/frida-inject"
        val cacheFile = File(context.filesDir, "frida-inject-$abiFolder")
        return try {
            if (!cacheFile.exists() || cacheFile.length() == 0L) {
                context.assets.open(assetPath).use { input ->
                    cacheFile.outputStream().use { output -> input.copyTo(output) }
                }
            }
            RootShell.execAndRead(
                "cp ${cacheFile.absolutePath} $INJECT_PATH && chmod 755 $INJECT_PATH && echo ok"
            ).trim() == "ok"
        } catch (e: Exception) {
            lastError = "Встроенный frida-inject: ${e.message}"
            false
        }
    }

    private fun downloadFridaInject(context: Context): Boolean {
        val abi = resolveDownloadAbi()
        val url = "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/" +
            "frida-inject-$FRIDA_VERSION-android-$abi.xz"
        val cacheXz = File(context.cacheDir, "frida-inject-$abi.xz")
        val cacheBin = File(context.cacheDir, "frida-inject-$abi")
        return try {
            downloadFile(url, cacheXz)
            RootShell.execAndRead(
                "which xz >/dev/null 2>&1 && xz -d -f ${cacheXz.absolutePath} || unxz -f ${cacheXz.absolutePath}"
            )
            if (!cacheBin.exists()) {
                lastError = "Не удалось распаковать frida-inject"
                return false
            }
            RootShell.execAndRead(
                "cp ${cacheBin.absolutePath} $INJECT_PATH && chmod 755 $INJECT_PATH && echo ok"
            ).trim() == "ok"
        } catch (e: Exception) {
            lastError = "frida-inject: ${e.message}"
            false
        }
    }

    private suspend fun ensureFridaServerRunning(context: Context): Boolean = withContext(Dispatchers.IO) {
        if (!deployFridaServerIfNeeded(context)) return@withContext false

        val running = RootShell.execAndRead(
            "pidof frida-server 2>/dev/null || pgrep -f '$SERVER_PATH' 2>/dev/null"
        ).trim()
        if (running.isNotEmpty()) return@withContext true

        RootShell.execAndRead("chmod 755 $SERVER_PATH && $SERVER_PATH -D >/dev/null 2>&1 & sleep 1 && echo ok")
        delay(500)
        RootShell.execAndRead("pidof frida-server 2>/dev/null || pgrep -f '$SERVER_PATH' 2>/dev/null")
            .trim().isNotEmpty()
    }

    private fun deployFridaServerIfNeeded(context: Context): Boolean {
        if (RootShell.execAndRead("test -x $SERVER_PATH && echo ok").trim() == "ok") {
            return true
        }
        val abi = resolveDownloadAbi()
        val url = "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/" +
            "frida-server-$FRIDA_VERSION-android-$abi.xz"
        val cacheXz = File(context.cacheDir, "frida-server-$abi.xz")
        val cacheBin = File(context.cacheDir, "frida-server-$abi")

        return try {
            downloadFile(url, cacheXz)
            RootShell.execAndRead(
                "which xz >/dev/null 2>&1 && xz -d -f ${cacheXz.absolutePath} || unxz -f ${cacheXz.absolutePath}"
            )
            if (!cacheBin.exists()) {
                lastError = "Не удалось распаковать frida-server"
                return false
            }
            RootShell.execAndRead(
                "cp ${cacheBin.absolutePath} $SERVER_PATH && chmod 755 $SERVER_PATH && echo ok"
            ).trim() == "ok"
        } catch (e: Exception) {
            lastError = "frida-server: ${e.message}"
            false
        }
    }

    fun clearInjection(packageName: String) {
        RootShell.execAndRead("setprop wrap.$packageName ''")
        stopInjector()
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
        FridaStatus.READY -> "Frida: готов (ручное подключение)"
        FridaStatus.INJECTED -> "Frida: хуки активны"
        FridaStatus.ERROR -> "Frida: ошибка (${lastError ?: "unknown"})"
    }
}
