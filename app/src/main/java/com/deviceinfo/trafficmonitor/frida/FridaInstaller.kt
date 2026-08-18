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
    const val AMCORE_PATH = "$BASE_DIR/libamcore.so"
    const val AMCORE_CONFIG = "$BASE_DIR/libamcore.config.so"
    const val AMHOOKS_PATH = "$BASE_DIR/libamhooks.so"
    const val BOOT_META = "$BASE_DIR/boot.meta"
    const val HOOKS_PATH = "$BASE_DIR/identifier_hooks.js"
    const val BOOT_PATH = "$BASE_DIR/boot.js"
    const val EVENTS_PATH = "$BASE_DIR/events.jsonl"
    const val SERVER_PATH = "$BASE_DIR/frida-server"
    const val INJECT_PATH = "$BASE_DIR/frida-inject"
    const val KITTY_PATH = "$BASE_DIR/AndKittyInjector"
    const val INJECT_LOG = "$BASE_DIR/inject.log"
    const val HTTPS_LOG = "$BASE_DIR/https.jsonl"

    @Volatile
    var mitmEnabled: Boolean = false

    @Volatile
    var status: FridaStatus = FridaStatus.NOT_INSTALLED

    @Volatile
    var lastError: String? = null

    @Volatile
    var lastNonce: String = ""
        private set

    @Volatile
    private var lastTargetPackage: String = ""


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
        RootShell.execAndRead("mkdir -p $BASE_DIR && chmod 711 $BASE_DIR")
        RootShell.execAndRead("touch $EVENTS_PATH && chmod 666 $EVENTS_PATH")
    }

    private fun tightenEventFilePerms(packageName: String) {
        val uid = RootShell.getUid(packageName) ?: return
        RootShell.execAndRead(
            "touch $EVENTS_PATH $HTTPS_LOG && " +
                "chown $uid:$uid $EVENTS_PATH $HTTPS_LOG && " +
                "chmod 711 $BASE_DIR && chmod 666 $EVENTS_PATH $HTTPS_LOG"
        )
    }

    private fun copyAssetToDevice(context: Context, assetPath: String, devicePath: String) {
        val local = File(context.filesDir, assetPath.replace('/', '_'))
        context.assets.open(assetPath).use { input ->
            local.outputStream().use { output -> input.copyTo(output) }
        }
        RootShell.execAndRead("cp ${local.absolutePath} $devicePath && chmod 644 $devicePath")
    }

    fun prepareHooksForPackage(packageName: String, context: Context) {
        lastNonce = System.currentTimeMillis().toString()
        val template = context.assets.open("frida/identifier_hooks.js")
            .bufferedReader().readText()
            .replace("__TARGET_PACKAGE__", packageName)
            .replace("__INJECT_NONCE__", lastNonce)
            .replace("__MITM_ENABLED__", if (mitmEnabled) "true" else "false")
        val local = File(context.filesDir, "identifier_hooks_active.js")
        local.writeText(template)
        RootShell.execAndRead("cp ${local.absolutePath} $HOOKS_PATH && chmod 644 $HOOKS_PATH")
        writeBootScript(packageName)
        writeGadgetConfig(packageName)
        lastTargetPackage = packageName
        RootShell.execAndRead(
            "printf '%s %s\\n' ${RootShell.shellQuote(lastNonce)} " +
                "${RootShell.shellQuote(packageName)} > $BOOT_META"
        )
        RootShell.execAndRead("touch $HTTPS_LOG")
        prepareEventSink(packageName)
    }

    private fun writeGadgetConfig(packageName: String) {
        val uid = RootShell.getUid(packageName)
        val hookInApp = "/data/user/0/$packageName/cache/access_monitor_hooks.js"
        val bootInApp = "/data/user/0/$packageName/cache/access_monitor_boot.js"
        val mkdir = "mkdir -p /data/user/0/$packageName/cache"
        val copy = "cp $HOOKS_PATH $hookInApp && cp $BOOT_PATH $bootInApp && chmod 644 $hookInApp $bootInApp"
        val chown = if (uid != null) "chown $uid:$uid $hookInApp $bootInApp" else "true"
        RootShell.execAndRead("$mkdir && $copy && $chown")
        val json = """{"interaction":{"type":"script","path":"$bootInApp"}}"""
        val local = File.createTempFile("am_gadget", ".json")
        local.writeText(json)
        RootShell.execAndRead(
            "cp $GADGET_PATH $AMCORE_PATH && chmod 755 $AMCORE_PATH $GADGET_PATH && " +
                "cp ${local.absolutePath} $CONFIG_PATH && cp ${local.absolutePath} $AMCORE_CONFIG && " +
                "chmod 644 $CONFIG_PATH $AMCORE_CONFIG && " +
                "chcon u:object_r:apk_data_file:s0 $GADGET_PATH $AMCORE_PATH $CONFIG_PATH $AMCORE_CONFIG $hookInApp 2>/dev/null"
        )
        local.delete()
    }

    /** Короткий boot: только console.log. Полный скрипт хуков eval после старта цели. */
    private fun writeBootScript(packageName: String) {
        val hooksInApp = "/data/user/0/$packageName/cache/access_monitor_hooks.js"
        val js = """
            'use strict';
            var line = '{"identifierId":"frida.boot","action":"Frida: скрипт загружен","request":"$packageName","response":"boot","package":"$packageName","timestamp":' + Date.now() + ',"source":"frida","nonce":"$lastNonce"}';
            try { console.log('AMF ' + line); } catch (e) {}
            setTimeout(function () {
              try {
                var fopen = new NativeFunction(Module.findExportByName('libc.so', 'fopen'), 'pointer', ['pointer', 'pointer']);
                var fread = new NativeFunction(Module.findExportByName('libc.so', 'fread'), 'int', ['pointer', 'int', 'int', 'pointer']);
                var fclose = new NativeFunction(Module.findExportByName('libc.so', 'fclose'), 'int', ['pointer']);
                var fseek = new NativeFunction(Module.findExportByName('libc.so', 'fseek'), 'int', ['pointer', 'int64', 'int']);
                var ftell = new NativeFunction(Module.findExportByName('libc.so', 'ftell'), 'int64', ['pointer']);
                var path = Memory.allocUtf8String('$hooksInApp');
                var mode = Memory.allocUtf8String('rb');
                var fp = fopen(path, mode);
                if (fp.isNull()) return;
                fseek(fp, 0, 2);
                var sz = parseInt(ftell(fp), 10);
                fseek(fp, 0, 0);
                if (!(sz > 0) || sz > 2500000) { fclose(fp); return; }
                var buf = Memory.alloc(sz + 1);
                fread(buf, 1, sz, fp);
                fclose(fp);
                eval(buf.readUtf8String(sz));
              } catch (e) {}
            }, 2000);
        """.trimIndent()
        val local = File.createTempFile("am_boot", ".js")
        local.writeText(js)
        RootShell.execAndRead("cp ${local.absolutePath} $BOOT_PATH && chmod 644 $BOOT_PATH")
        local.delete()
    }

    fun eventFiles(packageName: String): List<String> = listOf(
        EVENTS_PATH,
        "/data/user/0/$packageName/cache/access_monitor_events.jsonl",
        "/data/data/$packageName/cache/access_monitor_events.jsonl"
    ).distinct()

    fun prepareEventSink(packageName: String) {
        val uid = RootShell.getUid(packageName)
        val cacheFiles = eventFiles(packageName).filter { it != EVENTS_PATH }
        val mkdirs = cacheFiles.map { it.substringBeforeLast('/') }.distinct()
            .joinToString(" ") { "mkdir -p $it" }
        val touches = eventFiles(packageName).joinToString(" ") { "touch $it" }
        val chmods = eventFiles(packageName).joinToString(" ") { "chmod 666 $it" }
        val chowns = if (uid != null) {
            cacheFiles.joinToString(" ") { "chown $uid:$uid $it" }
        } else {
            "true"
        }
        RootShell.execAndRead(
            "$mkdirs && $touches && chmod 711 $BASE_DIR && $chmods && $chowns && " +
                "chmod 666 $HTTPS_LOG 2>/dev/null"
        )
        tightenEventFilePerms(packageName)
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
     * Хуки через Zygisk: gadget грузится в цели при specialize, без ptrace.
     * frida-inject на Magisk + Android 13 здесь стабильно Aborted — больше не используем.
     * Перезапуск цели обязателен: модуль срабатывает только на старте процесса.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun injectManual(context: Context, packageName: String, restartApp: Boolean): Boolean =
        withContext(Dispatchers.IO) {
            if (!ensureReady(context)) return@withContext false
            prepareHooksForPackage(packageName, context)

            if (!ZygiskModule.hasMagiskTree()) {
                status = FridaStatus.ERROR
                lastError = "Нужен Magisk или KernelSU с Zygisk. ptrace-инъекция на этом устройстве не работает."
                return@withContext false
            }
            if (!ZygiskModule.isZygiskEnabled()) {
                status = FridaStatus.ERROR
                lastError = "Включите Zygisk в Magisk (Настройки → Zygisk) и перезагрузите телефон"
                return@withContext false
            }
            if (ZygiskModule.isOnDenyList(packageName)) {
                status = FridaStatus.ERROR
                lastError = "Уберите $packageName из DenyList Magisk — иначе Zygisk не загрузится в цель"
                return@withContext false
            }
            if (!ZygiskModule.install(context)) {
                status = FridaStatus.ERROR
                lastError = lastError ?: "Не удалось записать модуль Magisk в /data/adb/modules"
                return@withContext false
            }
            ZygiskModule.writePayload(packageName)
            if (ZygiskModule.needsReboot()) {
                status = FridaStatus.READY
                lastError = "Модуль Magisk установлен. Перезагрузите телефон один раз, затем снова нажмите + Frida"
                return@withContext false
            }

            spawnAndWait(packageName) ?: run {
                lastError = lastError ?: "Приложение не запустилось (PID не найден)"
                status = FridaStatus.ERROR
                return@withContext false
            }
            if (waitForScriptBoot()) {
                status = FridaStatus.INJECTED
                lastError = null
                return@withContext true
            }

            val zlog = ZygiskModule.readLog(packageName)
            val moduleStatus = RootShell.execAndRead(
                "cat /data/adb/modules/access_monitor/last_status 2>/dev/null"
            ).trim()
            val gadgetLog = stripAnsi(
                RootShell.execAndRead(
                    "logcat -d -v brief -t 200 -s AccessMonZygisk:I AccessMonFrida:I Gadget:I frida:I frida-gadget:I 2>/dev/null"
                )
            ).trim()
            status = FridaStatus.ERROR
            lastError = when {
                zlog.contains("dlopen=ok") ->
                    "Gadget в процессе есть, но скрипт не ответил. $zlog ${gadgetLog.take(160)}"
                "scheduled=1" in zlog ->
                    "Zygisk отложил загрузку, но скрипт не ответил. Перезапустите цель ещё раз. ${gadgetLog.take(160)}"
                zlog.isBlank() && moduleStatus.contains("gadget=0") ->
                    "В модуле нет frida-gadget. Нажмите + Frida ещё раз, затем перезагрузите телефон. $moduleStatus"
                zlog.isBlank() ->
                    "Zygisk не загрузился в цель. Zygisk включён? Приложение не в DenyList? После установки модуля была перезагрузка? $moduleStatus ${gadgetLog.take(160)}"
                else ->
                    "Zygisk: $zlog $moduleStatus ${gadgetLog.take(160)}"
            }
            false
        }

    private suspend fun waitForScriptBoot(): Boolean {
        val nonce = lastNonce
        if (nonce.isBlank()) return false
        val pkg = lastTargetPackage
        repeat(90) {
            val eventCats = if (pkg.isNotBlank()) {
                eventFiles(pkg).joinToString(" ")
            } else {
                EVENTS_PATH
            }
            val zlog = if (pkg.isNotBlank()) ZygiskModule.zygiskLogPath(pkg) else ""
            val dump = RootShell.execAndRead(
                "logcat -d -v threadtime -t 400 -s AccessMonFrida:I AccessMonZygisk:I frida:I Gadget:I frida-gadget:I 2>/dev/null; " +
                    "cat $eventCats $zlog 2>/dev/null",
                timeoutSec = 6
            )
            for (line in dump.lineSequence()) {
                val start = line.indexOf('{')
                if (start < 0) continue
                val json = runCatching { org.json.JSONObject(line.substring(start).trim()) }.getOrNull()
                    ?: continue
                if (json.optString("nonce") != nonce) continue
                if (json.optString("identifierId") == "frida.boot" ||
                    json.optString("identifierId") == "frida.init"
                ) {
                    return true
                }
            }
            delay(250)
        }
        return false
    }

    /** Перезапуск цели: Zygisk подхватывает процесс только на specialize. */
    private suspend fun spawnAndWait(packageName: String): List<Int>? {
        RootShell.execAndRead("am force-stop $packageName")
        delay(250)
        if (!RootShell.launchApp(packageName)) {
            lastError = "Не удалось запустить приложение"
            return null
        }
        repeat(40) {
            val live = RootShell.findAllPids(packageName)
            if (live.isNotEmpty()) {
                delay(400)
                return RootShell.findAllPids(packageName).ifEmpty { live }
            }
            delay(150)
        }
        lastError = "PID не найден после запуска"
        return null
    }

    private fun stripAnsi(text: String): String =
        text.replace(Regex("\u001B\\[[0-9;]*m"), "")

    fun clearInjection(packageName: String) {
        ZygiskModule.clearTarget()
        if (packageName.isNotBlank()) {
            RootShell.execAndRead("rm -f ${ZygiskModule.zygiskLogPath(packageName)}")
        }
        RootShell.execAndRead("am clear-debug-app 2>/dev/null")
        if (status == FridaStatus.INJECTED) {
            status = FridaStatus.READY
        }
    }

    fun clearEvents(packageName: String? = null) {
        val files = if (packageName.isNullOrBlank()) listOf(EVENTS_PATH) else eventFiles(packageName)
        for (path in files) {
            RootShell.execAndRead("truncate -s 0 $path 2>/dev/null || echo -n > $path")
        }
    }

    fun statusLabel(): String = when (status) {
        FridaStatus.NOT_INSTALLED -> "Frida: не установлен"
        FridaStatus.EXTRACTING -> "Frida: установка из APK…"
        FridaStatus.DOWNLOADING -> "Frida: загрузка…"
        FridaStatus.READY -> "Frida: Zygisk готов"
        FridaStatus.INJECTED -> "Frida: хуки активны"
        FridaStatus.ERROR -> "Frida: ошибка (${lastError ?: "unknown"})"
    }
}
