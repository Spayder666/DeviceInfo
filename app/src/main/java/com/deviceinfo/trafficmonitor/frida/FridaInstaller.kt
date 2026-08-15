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
    const val HTTPS_LOG = "$BASE_DIR/https.jsonl"
    const val SPAWN_WAIT = "$BASE_DIR/spawn_wait.sh"
    const val SPAWN_FLAG = "$BASE_DIR/spawn.ok"

    @Volatile
    var mitmEnabled: Boolean = false

    @Volatile
    var status: FridaStatus = FridaStatus.NOT_INSTALLED

    @Volatile
    var lastError: String? = null

    @Volatile
    var lastNonce: String = ""
        private set

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
        RootShell.execAndRead("touch $HTTPS_LOG")
        prepareEventSink(packageName)
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

            val pids = if (restartApp) {
                spawnAndInject(packageName) ?: run {
                    lastError = lastError ?: "Приложение не запустилось (PID не найден)"
                    return@withContext false
                }
            } else {
                val live = RootShell.findAllPids(packageName)
                if (live.isEmpty()) {
                    lastError = "Приложение не запущено — сначала запустите его"
                    return@withContext false
                }
                live
            }

            if (injectLogsFailed()) {
                stopInjector()
            }
            val injected = pids.take(6).count { startInjector(it, packageName) }
            if (injected == 0) {
                return@withContext false
            }

            if (!waitForScriptBoot()) {
                status = FridaStatus.ERROR
                if (lastError.isNullOrBlank()) {
                    lastError = "Frida зависла на процессе, но скрипт не шлёт события. Перехват не активен."
                }
                return@withContext false
            }

            status = FridaStatus.INJECTED
            lastError = null
            true
        }

    private suspend fun waitForScriptBoot(): Boolean {
        val nonce = lastNonce
        if (nonce.isBlank()) return false
        repeat(40) {
            val dump = RootShell.execAndRead(
                "logcat -d -v threadtime -t 400 -s AccessMonFrida:I 2>/dev/null; " +
                    "cat $INJECT_LOG $INJECT_LOG.* 2>/dev/null",
                timeoutSec = 6
            )
            for (line in dump.lineSequence()) {
                val start = line.indexOf('{')
                if (start < 0) continue
                val json = runCatching { org.json.JSONObject(line.substring(start).trim()) }.getOrNull()
                    ?: continue
                if (json.optString("nonce") == nonce && json.optString("identifierId") == "frida.boot") {
                    return true
                }
            }
            delay(200)
        }
        val injectLog = stripAnsi(
            RootShell.execAndRead("cat $INJECT_LOG $INJECT_LOG.* 2>/dev/null")
        ).trim()
        if (injectLog.isNotBlank()) {
            lastError = "Frida зависла на процессе, но скрипт не шлёт события. ${injectLog.take(240)}"
        }
        return false
    }

    /**
     * Ждём PID и конец specialize (не zygote). Инжект делает startInjector —
     * слишком ранний ptrace даёт только «Aborted».
     */
    private suspend fun spawnAndInject(packageName: String): List<Int>? {
        RootShell.execAndRead("am force-stop $packageName")
        delay(150)
        installSpawnWaiter()
        RootShell.execAndRead("rm -f $SPAWN_FLAG")
        RootShell.execDetached(
            "sh $SPAWN_WAIT ${RootShell.shellQuote(packageName)} $BASE_DIR"
        )
        delay(30)
        if (!RootShell.launchApp(packageName)) {
            lastError = "Не удалось запустить приложение"
            return null
        }
        repeat(100) {
            val flag = RootShell.execAndRead("cat $SPAWN_FLAG 2>/dev/null").trim()
            if (flag == "ok" || flag == "timeout") {
                return RootShell.findAllPids(packageName).takeIf { it.isNotEmpty() }
            }
            delay(100)
        }
        return RootShell.findAllPids(packageName).takeIf { it.isNotEmpty() }
    }

    private fun installSpawnWaiter() {
        val script = """
            #!/system/bin/sh
            pkg="${'$'}1"
            dir="${'$'}2"
            i=0
            while [ ${'$'}i -lt 400 ]; do
              pids=`pidof "${'$'}pkg" 2>/dev/null`
              if [ -n "${'$'}pids" ]; then
                for p in ${'$'}pids; do
                  n=0
                  while [ ${'$'}n -lt 200 ]; do
                    comm=`cat /proc/${'$'}p/comm 2>/dev/null`
                    case "${'$'}comm" in zygote|zygote64|"") n=$((n+1)); usleep 30000 2>/dev/null || sleep 0.03; continue ;; esac
                    if grep -q "/data/app/" /proc/${'$'}p/maps 2>/dev/null && grep -q "${'$'}pkg" /proc/${'$'}p/maps 2>/dev/null; then
                      usleep 200000 2>/dev/null || sleep 0.2
                      break
                    fi
                    ctx=`cat /proc/${'$'}p/attr/current 2>/dev/null`
                    case "${'$'}ctx" in *untrusted_app*|*priv_app*)
                      usleep 200000 2>/dev/null || sleep 0.2
                      break
                    ;; esac
                    if cat /proc/${'$'}p/task/*/comm 2>/dev/null | grep -q HeapTaskDaemon; then
                      usleep 200000 2>/dev/null || sleep 0.2
                      break
                    fi
                    n=$((n+1))
                    usleep 30000 2>/dev/null || sleep 0.03
                  done
                done
                echo ok > "${'$'}dir/spawn.ok"
                exit 0
              fi
              i=$((i+1))
              usleep 2000 2>/dev/null || sleep 0.01
            done
            echo timeout > "${'$'}dir/spawn.ok"
            exit 1
        """.trimIndent()
        val local = File.createTempFile("spawn_wait", ".sh")
        local.writeText(script)
        RootShell.execAndRead("cp ${local.absolutePath} $SPAWN_WAIT && chmod 755 $SPAWN_WAIT")
        local.delete()
    }

    private fun preparePtrace() {
        RootShell.execAndRead("setenforce 0 2>/dev/null")
        RootShell.execAndRead("echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        RootShell.execAndRead("chmod 711 $BASE_DIR && chmod 644 $HOOKS_PATH 2>/dev/null")
    }

    /**
     * libart.so is already mapped in zygote children — that is not "ready".
     * Wait until the app finished specialize (apk mapped / app SELinux / ART threads).
     */
    private fun isProcessReady(pid: Int, packageName: String): Boolean {
        val comm = RootShell.execAndRead("cat /proc/$pid/comm 2>/dev/null").trim()
        if (comm.isEmpty() || comm.startsWith("zygote")) return false
        val maps = RootShell.execAndRead("grep -E '/data/app/|$packageName' /proc/$pid/maps 2>/dev/null | head -n 3")
        if (maps.contains("/data/app/") && maps.contains(packageName)) return true
        val ctx = RootShell.execAndRead("cat /proc/$pid/attr/current 2>/dev/null")
        if (ctx.contains("untrusted_app") || ctx.contains("priv_app")) return true
        val threads = RootShell.execAndRead("cat /proc/$pid/task/*/comm 2>/dev/null")
        return threads.contains("HeapTaskDaemon") || threads.contains("Jit thread pool")
    }

    private fun waitForProcessReady(pid: Int, packageName: String): Boolean {
        repeat(100) {
            if (isProcessReady(pid, packageName)) {
                Thread.sleep(200)
                return true
            }
            Thread.sleep(80)
        }
        return RootShell.execAndRead("kill -0 $pid 2>/dev/null && echo ok").trim() == "ok"
    }

    private fun injectLogsFailed(): Boolean {
        val log = RootShell.execAndRead("cat $INJECT_LOG $INJECT_LOG.* 2>/dev/null")
        return looksLikeInjectFailure(log)
    }

    private fun startInjector(pid: Int, packageName: String): Boolean {
        if (!waitForProcessReady(pid, packageName)) {
            lastError = "Процесс $pid ещё не специализирован (zygote) — инжект прерван"
            return false
        }
        val log = "$INJECT_LOG.$pid"
        RootShell.execAndRead("echo -n > $log")
        // -e = eternalize AND EXIT. That teardown prints "Aborted" and kills console.log.
        // Keep frida-inject resident so the session and inject.log stay alive.
        val cmd = "$INJECT_PATH -p $pid -s $HOOKS_PATH"
        RootShell.execDetached("$cmd > $log 2>&1")

        var lastLog = ""
        repeat(20) {
            Thread.sleep(150)
            lastLog = stripAnsi(RootShell.execAndRead("cat $log 2>/dev/null")).trim()
            if (looksLikeInjectFailure(lastLog) && !logHasBoot(lastLog)) {
                lastError = "frida-inject: ${lastLog.take(220)}"
                return false
            }
            val running = RootShell.execAndRead(
                "pgrep -f '$INJECT_PATH' 2>/dev/null"
            ).trim().isNotEmpty()
            if (running || looksLikeInjectSuccess(lastLog) || logHasBoot(lastLog)) {
                return true
            }
        }

        lastError = if (lastLog.isNotBlank()) {
            "frida-inject: ${lastLog.take(220)}"
        } else {
            "frida-inject не запустился (проверьте root / SELinux)"
        }
        return false
    }

    private fun stripAnsi(text: String): String =
        text.replace(Regex("\u001B\\[[0-9;]*m"), "")

    private fun logHasBoot(log: String): Boolean =
        log.contains("\"identifierId\":\"frida.boot\"") || log.contains("frida.boot")

    private fun looksLikeInjectFailure(log: String): Boolean {
        if (log.isBlank()) return false
        val lower = stripAnsi(log).lowercase()
        return listOf(
            "unable to", "failed", "error:", "permission denied", "not found", "cannot",
            "process terminated", "connection terminated", "device lost"
        ).any { it in lower }
    }

    private fun looksLikeInjectSuccess(log: String): Boolean {
        if (log.isBlank()) return false
        val lower = stripAnsi(log).lowercase()
        return listOf("script", "loaded", "injected", "connected", "resumed").any { it in lower }
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
        stopInjector()
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
        FridaStatus.READY -> "Frida: готов (ручное подключение)"
        FridaStatus.INJECTED -> "Frida: хуки активны"
        FridaStatus.ERROR -> "Frida: ошибка (${lastError ?: "unknown"})"
    }
}
