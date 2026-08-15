package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierMatcher
import com.deviceinfo.trafficmonitor.identifiers.toAccessCategory
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class ProcMonitor(
    private val packageName: String,
    private val pid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val knownFds = ConcurrentHashMap<String, String>()
    private val knownConnections = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollFileDescriptors()
                pollNetworkConnections()
                delay(2000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollFileDescriptors() {
        val output = RootShell.execAndRead("ls -la /proc/$pid/fd 2>/dev/null")
        for (line in output.lines()) {
            if (!line.contains(" -> ")) continue
            val parts = line.split(" -> ")
            if (parts.size < 2) continue
            val fd = parts[0].trim().substringAfterLast(' ')
            val target = parts[1].trim()
            if (isNoisePath(target)) continue

            val key = "$fd:$target"
            if (knownFds.put(key, target) != null) continue

            val category = classifyPath(target)
            if (category == AccessCategory.OTHER) {
                IdentifierMatcher.matchPath(target)?.let { def ->
                    recordIdentifier(def, line.trim(), target)
                }
                continue
            }

            record(
                category = category,
                action = "fd:$fd",
                request = "Открытый дескриптор: $target",
                response = target,
                raw = line.trim()
            )
        }
    }

    private fun isNoisePath(path: String): Boolean {
        val lower = path.lowercase()
        return lower in NOISE_PATHS ||
            lower.startsWith("/dev/ashmem") ||
            lower.startsWith("/dev/__properties__") ||
            "anon_inode" in lower ||
            lower.endsWith("/loader") ||
            lower.startsWith("/system/framework/") ||
            lower.startsWith("/apex/") ||
            lower.startsWith("/system/app/") ||
            lower.startsWith("/system/priv-app/") ||
            lower.startsWith("/product/app/") ||
            lower.startsWith("/product/framework/") ||
            lower.endsWith(".jar") ||
            lower.endsWith(".apk") ||
            lower.endsWith(".odex") ||
            lower.endsWith(".vdex") ||
            lower.endsWith(".art") ||
            lower.endsWith(".so")
    }

    companion object {
        private val NOISE_PATHS = setOf(
            "/dev/null",
            "/dev/zero",
            "/dev/urandom",
            "/dev/random",
            "/dev/tty",
            "/dev/log",
            "/dev/console",
            "/dev/kmsg",
            "/dev/ptmx",
            "/dev/binder",
            "/dev/hwbinder",
            "/dev/vndbinder",
            "/dev/ion",
            "/dev/dmabuf",
            "/dev/eventfd",
            "/dev/inotify",
            "/dev/alarm",
            "/dev/rtc0",
            "/dev/uinput",
            "/dev/input/event0",
            "/dev/input/event1",
            "/dev/input/event2",
            "/dev/input/event3",
            "/dev/input/event4",
            "/dev/input/event5",
            "/dev/graphics/fb0",
            "/sys/kernel/debug/tracing/trace_marker"
        )
    }

    private suspend fun pollNetworkConnections() {
        val tcpOutput = RootShell.execAndRead(
            "cat /proc/$pid/net/tcp /proc/$pid/net/tcp6 /proc/$pid/net/udp /proc/$pid/net/udp6 2>/dev/null"
        )
        for (line in tcpOutput.lines()) {
            if (line.startsWith("sl")) continue
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size < 3) continue

            val local = decodeAddress(parts[1])
            val remote = decodeAddress(parts[2])
            val state = if (parts.size > 3) tcpStateName(parts[3]) else "UDP"
            val key = "$local->$remote:$state"
            if (knownConnections.put(key, state) != null) continue

            if (isNoiseConnection(local, remote, state)) continue

            val dest = "$local $remote".lowercase()
            val locationNet = listOf(":7275", ":7276", ":1883", ":8883", ":5683", "supl").any { it in dest }
            record(
                category = if (locationNet) AccessCategory.LOCATION else AccessCategory.NETWORK,
                action = if (locationNet) "Location/MQTT/SUPL $state" else "TCP/UDP $state",
                request = "Соединение $local → $remote",
                response = "Состояние: $state",
                raw = line.trim()
            )
        }
    }

    private fun classifyPath(path: String): AccessCategory {
        val lower = path.lowercase()
        return when {
            "camera" in lower -> AccessCategory.CAMERA
            lower.endsWith("/su") || "/su/" in lower || "magisk" in lower || "xposed" in lower ||
                "lsposed" in lower || "lspd" in lower || "frida" in lower || "memfd" in lower ||
                "qemu_pipe" in lower || "goldfish" in lower -> AccessCategory.SECURITY
            "gps" in lower || "location" in lower || "gnss" in lower -> AccessCategory.LOCATION
            "audio" in lower || "mic" in lower -> AccessCategory.MICROPHONE
            "bluetooth" in lower -> AccessCategory.BLUETOOTH
            "radio" in lower || "telephony" in lower -> AccessCategory.TELEPHONY
            "contacts" in lower -> AccessCategory.CONTACTS
            "sms" in lower -> AccessCategory.SMS
            "socket:" in lower -> AccessCategory.NETWORK
            "anon_inode" in lower && "sync" in lower -> AccessCategory.SYSTEM_API
            "/dev/" in lower -> AccessCategory.SYSTEM_API
            "/data/" in lower || "/storage/" in lower -> AccessCategory.STORAGE
            else -> AccessCategory.OTHER
        }
    }

    private fun isNoiseConnection(local: String, remote: String, state: String): Boolean {
        if (state.startsWith("UNKNOWN")) return true
        val r = remote.substringBefore('%')
        val wildcard = r.startsWith("0.0.0.0:") || r.startsWith("[::]:") ||
            r.startsWith(":::0") || r == "0.0.0.0:0" || r.endsWith(":0") && r.startsWith("0.")
        if (wildcard && state != "LISTEN") return true
        if (state == "CLOSE" || state == "CLOSING") return true
        return false
    }

    private fun decodeAddress(hex: String): String {
        val parts = hex.split(":")
        if (parts.size != 2) return hex
        val port = parts[1].toIntOrNull(16) ?: return hex
        val ipHex = parts[0]
        if (ipHex.length == 8) {
            val b = ipHex.chunked(2).map { it.toInt(16) }
            return "${b[3]}.${b[2]}.${b[1]}.${b[0]}:$port"
        }
        return "$hex:$port"
    }

    private fun tcpStateName(hex: String): String = when (hex) {
        "01" -> "ESTABLISHED"
        "02" -> "SYN_SENT"
        "03" -> "SYN_RECV"
        "04" -> "FIN_WAIT1"
        "05" -> "FIN_WAIT2"
        "06" -> "CLOSE_WAIT"
        "07" -> "CLOSE"
        "08" -> "LAST_ACK"
        "09" -> "LISTEN"
        "0A" -> "CLOSING"
        else -> "UNKNOWN($hex)"
    }

    private suspend fun recordIdentifier(
        def: com.deviceinfo.trafficmonitor.identifiers.IdentifierDefinition,
        raw: String,
        path: String
    ) {
        if (repository.isDuplicate(packageName, def.displayName, raw)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = def.toAccessCategory(),
                source = EventSource.PROC,
                action = def.displayName,
                permission = def.permission,
                requestDetails = "Открытый дескриптор: $path",
                responseDetails = def.api?.let { "API: $it" },
                rawData = raw,
                processId = pid,
                identifierName = def.id,
                identifierGroup = def.group.name
            )
        )
    }

    private suspend fun record(
        category: AccessCategory,
        action: String,
        request: String?,
        response: String?,
        raw: String
    ) {
        if (repository.isDuplicate(packageName, action, raw)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.PROC,
                action = action,
                requestDetails = request,
                responseDetails = response,
                rawData = raw,
                processId = pid
            )
        )
    }
}
