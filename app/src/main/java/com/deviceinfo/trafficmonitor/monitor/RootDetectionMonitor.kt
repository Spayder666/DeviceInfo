package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Ловит проверки root / LSPosed / Frida / инжектов в память
 * даже без Frida: logcat + maps/smaps, потоки, порты, unix-сокеты.
 */
class RootDetectionMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var pollJob: Job? = null
    private var logJob: Job? = null
    private val seen = ConcurrentHashMap<String, Long>()
    @Volatile
    private var pid: Int = -1

    fun start() {
        pollJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pid = RootShell.findPid(packageName) ?: pid
                pollMaps()
                pollRwx()
                pollThreads()
                pollPorts()
                pollUnix()
                pollTracer()
                pollFds()
                delay(2800)
            }
        }
        logJob = scope.launch(Dispatchers.IO) {
            val uidFilter = if (uid > 0) "--uid=$uid" else ""
            val cmd = "logcat -v threadtime $uidFilter -T 1 2>&1"
            try {
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) scope.launch { parseLog(line) }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun stop() {
        pollJob?.cancel()
        logJob?.cancel()
        pollJob = null
        logJob = null
    }

    private suspend fun pollMaps() {
        if (pid <= 0) return
        val maps = RootShell.execAndRead(
            "grep -E -i '$MAPS_GREP' /proc/$pid/maps 2>/dev/null | head -n 16",
            timeoutSec = 6
        )
        if (maps.isBlank()) return
        emit(classifyMaps(maps), "maps: hook/inject", "/proc/$pid/maps", maps.lineSequence().take(8).joinToString("\n"), maps)
    }

    private suspend fun pollRwx() {
        if (pid <= 0) return
        val rwx = RootShell.execAndRead(
            "awk '\$2 ~ /rwx/ {print}' /proc/$pid/maps 2>/dev/null | grep -vE 'system/|apex/|jit-cache|dalvik|anonymous:libc' | head -n 8",
            timeoutSec = 6
        )
        if (rwx.isBlank()) return
        emit("root.inject", "maps: rwxp", "/proc/$pid/maps", rwx.take(400), rwx)
    }

    private suspend fun pollThreads() {
        if (pid <= 0) return
        val comm = RootShell.execAndRead(
            "cat /proc/$pid/task/*/comm 2>/dev/null | grep -E -i 'gum-js|gmain|gdbus|pool-frida|linjector|lsposed|lspd|xposed|frida' | head -n 12",
            timeoutSec = 6
        )
        if (comm.isBlank()) return
        val id = if (comm.contains("gum", ignoreCase = true) || comm.contains("frida", ignoreCase = true) ||
            comm.contains("linjector", ignoreCase = true)
        ) "root.threads" else "root.lsposed"
        emit(id, "task comm", "/proc/$pid/task/*/comm", comm.take(300), comm)
    }

    private suspend fun pollPorts() {
        if (pid <= 0) return
        val tcp = RootShell.execAndRead(
            "cat /proc/$pid/net/tcp /proc/$pid/net/tcp6 2>/dev/null | grep -E -i '$FRIDA_PORTS_HEX' | head -n 8",
            timeoutSec = 6
        )
        if (tcp.isBlank()) return
        emit("root.ports", "net/tcp Frida ports", "/proc/$pid/net/tcp", tcp.take(400), tcp)
    }

    private suspend fun pollUnix() {
        if (pid <= 0) return
        val unix = RootShell.execAndRead(
            "cat /proc/$pid/net/unix 2>/dev/null | grep -E -i 'frida|gum|lsposed|lspd|magisk|zygisk|riru|xposed' | head -n 8",
            timeoutSec = 6
        )
        if (unix.isBlank()) return
        emit("root.ports", "unix socket", "/proc/$pid/net/unix", unix.take(400), unix)
    }

    private suspend fun pollTracer() {
        if (pid <= 0) return
        val status = RootShell.execAndRead("grep -E 'TracerPid|State:' /proc/$pid/status 2>/dev/null")
        val tracer = Regex("TracerPid:\\s*(\\d+)").find(status)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        if (tracer > 0) {
            emit("root.debugger", "TracerPid", "pid=$pid", "tracer=$tracer", status)
        }
    }

    private suspend fun pollFds() {
        if (pid <= 0) return
        val fds = RootShell.execAndRead(
            "ls -l /proc/$pid/fd 2>/dev/null | grep -E -i 'su|magisk|xposed|lsposed|lspd|frida|pipe:|qemu_pipe|goldfish' | head -n 12",
            timeoutSec = 6
        )
        if (fds.isBlank()) return
        emit(classifyMaps(fds), "fd: inject/root", "/proc/$pid/fd", fds.take(400), fds)
    }

    private suspend fun parseLog(line: String) {
        if (line.isBlank() || line.startsWith("-----")) return
        val mentionsPkg = line.contains(packageName) || (uid > 0 && line.contains("uid=$uid"))
        val hit = ROOT_LOG.find(line) ?: return
        if (!mentionsPkg && !GLOBAL_TAGS.containsMatchIn(line)) return
        emit(classifyLog(line), hit.value, "logcat", line.substringAfter(": ").take(280), line.trim())
    }

    private fun classifyMaps(text: String): String {
        val t = text.lowercase()
        return when {
            "lsposed" in t || "lspd" in t || "lsplant" in t -> "root.lsposed"
            "lspatch" in t || "virtualxposed" in t -> "root.lspatch"
            "frida" in t || "gadget" in t || "gum-js" in t -> "root.frida_detect"
            "xposed" in t -> "root.xposed"
            "memfd" in t || "rwxp" in t || "sandhook" in t || "dobby" in t || "yahfa" in t -> "root.inject"
            "magisk" in t || "zygisk" in t -> "root.magisk"
            else -> "root.inject"
        }
    }

    private fun classifyLog(line: String): String {
        val t = line.lowercase()
        return when {
            "lsposed" in t || "lspd" in t || "lsplant" in t || "lsphooker" in t -> "root.lsposed"
            "lspatch" in t || "virtualxposed" in t || "taichi" in t -> "root.lspatch"
            "handlehookedmethod" in t || "invokeoriginalmethod" in t -> "root.stack"
            "rootbeer" in t || "isrooted" in t -> "root.rootbeer"
            "meets_device" in t || "meets_strong" in t || "meets_basic" in t ||
                "ctsprofile" in t || "devicerecognitionverdict" in t -> "ent.verdict"
            "playintegrity" in t || "integrityservice" in t || "integritytoken" in t ||
                "standardintegrity" in t -> "ent.integrity"
            "safetynet" in t -> "ent.safetynet"
            "talsec" in t || "freerasp" in t || "jailmonkey" in t -> "root.talsec"
            "shamiko" in t || "denylist" in t -> "root.hide"
            "attestation" in t || "keymint" in t -> "attest.key"
            "frida" in t || "27042" in t || "27043" in t || "gum-js" in t || "linjector" in t -> "root.frida_detect"
            "xposed" in t -> "root.xposed"
            "sandhook" in t || "yahfa" in t || "dobby" in t || "memfd" in t || "rwxp" in t -> "root.inject"
            "magisk" in t || "zygisk" in t -> "root.magisk"
            "kernelsu" in t || "apatch" in t -> "root.ksu"
            "qemu" in t || "goldfish" in t || "ranchu" in t -> "root.emulator"
            "getenforce" in t || "selinux" in t -> "root.selinux"
            "adb_enabled" in t || "development_settings" in t -> "root.adb"
            "tracerpid" in t || "debugger" in t -> "root.debugger"
            "test-keys" in t || "ro.secure" in t || "ro.debuggable" in t -> "root.props"
            else -> "root.su"
        }
    }

    private suspend fun emit(id: String, action: String, request: String, response: String, raw: String) {
        val key = "$id|$action|${raw.hashCode()}"
        val now = System.currentTimeMillis()
        val prev = seen.put(key, now)
        if (prev != null && now - prev < 4000) return
        if (repository.isDuplicate(packageName, action, raw, sinceMs = 2500)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.SECURITY,
                source = EventSource.LOGCAT,
                action = action,
                requestDetails = request,
                responseDetails = response.take(400),
                rawData = raw.take(1500),
                processId = pid.takeIf { it > 0 },
                identifierName = id,
                identifierGroup = if (id.startsWith("attest") || id.startsWith("ent.")) "ATTESTATION" else "ROOT"
            )
        )
    }

    companion object {
        private const val MAPS_GREP =
            "magisk|zygisk|riru|xposed|lsposed|lspd|lsplant|lspatch|frida|gadget|libsubstrate|" +
                "libmemtrack_real|sandhook|yahfa|dobby|libwhale|epic|memfd:|linjector"
        // 27040=69A0 … 27050=69AA, 23946=5D8A
        private const val FRIDA_PORTS_HEX = ":69A[0-9A]|:5D8A"

        private val ROOT_LOG = Regex(
            "(?i)RootBeer|isRooted|SafetyNet|PlayIntegrity|IntegrityService|IntegrityToken|" +
                "StandardIntegrity|MEETS_DEVICE_INTEGRITY|MEETS_STRONG_INTEGRITY|ctsProfileMatch|" +
                "Magisk|Zygisk|KernelSU|APatch|XposedBridge|XposedHelpers|LSPosed|LSPosedBridge|" +
                "EdXposed|LSPatch|VirtualXposed|TaiChi|handleHookedMethod|LSPHooker|" +
                "frida-server|frida-agent|gum-js-loop|LIBFRIDA|linjector|27042|27043|" +
                "which su|/system/bin/su|/system/xbin/su|su binary|SuperSU|Superuser|" +
                "getenforce|test-keys|ro\\.secure|ro\\.debuggable|verifiedboot|" +
                "KeyAttestation|goldfish|ranchu|qemu_pipe|TracerPid|adb_enabled|" +
                "sandhook|yahfa|dobby|liblspd|lsplant|memfd|" +
                "Shamiko|DenyList|Talsec|freeRASP|JailMonkey|CertificatePinner|SSLPeerUnverified"
        )
        private val GLOBAL_TAGS = Regex(
            "(?i)RootBeer|SafetyNet|PlayIntegrity|IntegrityService|Magisk|Xposed|LSPosed|" +
                "frida-server|LSPatch|handleHookedMethod|Talsec|Shamiko|MEETS_DEVICE"
        )
    }
}
