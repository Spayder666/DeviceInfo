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

    /** Attach к уже запущенному процессу (без перезапуска). */
    suspend fun injectViaAttach(context: Context, pid: Int): Boolean = withContext(Dispatchers.IO) {
        if (injectViaGdbDlopen(pid)) {
            status = FridaStatus.INJECTED
            lastError = null
            return@withContext true
        }

        if (!ensureFridaServerRunning(context)) {
            lastError = lastError ?: "frida-server не запустился"
            return@withContext false
        }

        val result = RootShell.execAndRead(
            """
            if command -v frida >/dev/null 2>&1; then
              frida -H 127.0.0.1 -p $pid -l $HOOKS_PATH --runtime=v8 -q 2>&1 && echo FRIDA_OK
            else
              echo FRIDA_CLI_MISSING
            fi
            """.trimIndent(),
            timeoutSec = 25
        )

        when {
            result.contains("FRIDA_OK") -> {
                status = FridaStatus.INJECTED
                lastError = null
                true
            }
            result.contains("FRIDA_CLI_MISSING") -> {
                lastError = "Attach не удался. Попробуйте «Перезапуск с Frida» или установите frida-tools в Termux."
                false
            }
            else -> {
                lastError = "Attach: ${result.take(200)}"
                false
            }
        }
    }

    /** Загрузка gadget.so в работающий процесс через gdb+dlopen (root). */
    private fun injectViaGdbDlopen(pid: Int): Boolean {
        val gdbCandidates = listOf(
            "/system/bin/gdbserver",
            "/system/xbin/gdb",
            "/system/bin/gdb",
            "/data/local/tmp/gdb"
        )
        for (gdb in gdbCandidates) {
            if (gdb.contains("gdbserver")) continue
            val check = RootShell.execAndRead("test -x $gdb && echo ok").trim()
            if (check != "ok") continue

            val result = RootShell.execAndRead(
                """
                $gdb -batch -p $pid \
                  -ex 'set pagination off' \
                  -ex 'call (void*)dlopen("$GADGET_PATH", 2)' \
                  -ex detach -ex quit 2>&1
                """.trimIndent(),
                timeoutSec = 15
            )
            if (!result.contains("No such file") && !result.contains("can't attach")) {
                return true
            }
        }
        return false
    }

    /** Wrap+LD_PRELOAD — только по запросу пользователя; перезапускает приложение. */
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
        lastError = null
        true
    }

    /** Ручная инъекция: attach к PID или wrap+перезапуск. */
    suspend fun injectManual(context: Context, packageName: String, useWrap: Boolean): Boolean =
        withContext(Dispatchers.IO) {
            if (!useWrap) {
                val pid = RootShell.findPid(packageName)
                if (pid == null) {
                    lastError = "Приложение не запущено — сначала запустите его"
                    return@withContext false
                }
                return@withContext injectViaAttach(context, pid)
            }
            injectViaWrap(packageName)
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
