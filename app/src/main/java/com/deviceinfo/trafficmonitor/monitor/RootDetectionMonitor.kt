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
 * Ловит проверки root / Magisk / Frida / эмулятора / Play Integrity
 * даже без инъекции Frida: logcat + /proc maps/status/fd.
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
                pollTracer()
                pollFds()
                delay(2500)
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
            "grep -E -i 'magisk|zygisk|riru|xposed|lsposed|frida|gadget|libsubstrate|libmemtrack_real' /proc/$pid/maps 2>/dev/null | head -n 12",
            timeoutSec = 6
        )
        if (maps.isBlank()) return
        val id = when {
            maps.contains("frida", ignoreCase = true) || maps.contains("gadget", ignoreCase = true) -> "root.frida_detect"
            maps.contains("xposed", ignoreCase = true) || maps.contains("lsposed", ignoreCase = true) -> "root.xposed"
            else -> "root.maps"
        }
        emit(id, "maps: модули root/hook", "/proc/$pid/maps", maps.lineSequence().take(6).joinToString("\n"), maps)
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
            "ls -l /proc/$pid/fd 2>/dev/null | grep -E -i 'su|magisk|xposed|frida|qemu_pipe|goldfish' | head -n 12",
            timeoutSec = 6
        )
        if (fds.isBlank()) return
        emit("root.su", "fd: su/magisk/frida", "/proc/$pid/fd", fds.take(400), fds)
    }

    private suspend fun parseLog(line: String) {
        if (line.isBlank() || line.startsWith("-----")) return
        val mentionsPkg = line.contains(packageName) || (uid > 0 && line.contains("uid=$uid"))
        val hit = ROOT_LOG.find(line) ?: return
        if (!mentionsPkg && !GLOBAL_TAGS.containsMatchIn(line)) return
        val id = classifyLog(line)
        emit(id, hit.value, "logcat", line.substringAfter(": ").take(280), line.trim())
    }

    private fun classifyLog(line: String): String {
        val t = line.lowercase()
        return when {
            "rootbeer" in t || "isrooted" in t -> "root.rootbeer"
            "playintegrity" in t || "integrityservice" in t || "integritytoken" in t -> "ent.integrity"
            "safetynet" in t -> "ent.safetynet"
            "attestation" in t || "keymint" in t -> "attest.key"
            "frida" in t || "27042" in t || "gum-js" in t -> "root.frida_detect"
            "xposed" in t || "lsposed" in t -> "root.xposed"
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
        private val ROOT_LOG = Regex(
            "(?i)RootBeer|isRooted|SafetyNet|PlayIntegrity|IntegrityService|IntegrityToken|" +
                "Magisk|Zygisk|KernelSU|APatch|XposedBridge|LSPosed|EdXposed|" +
                "frida-server|gum-js-loop|LIBFRIDA|27042|" +
                "which su|/system/bin/su|/system/xbin/su|su binary|SuperSU|Superuser|" +
                "getenforce|test-keys|ro\\.secure|ro\\.debuggable|verifiedboot|" +
                "KeyAttestation|goldfish|ranchu|qemu_pipe|TracerPid|adb_enabled"
        )
        private val GLOBAL_TAGS = Regex(
            "(?i)RootBeer|SafetyNet|PlayIntegrity|IntegrityService|Magisk|Xposed|LSPosed|frida-server"
        )
    }
}
