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
            val key = "$fd:$target"
            if (knownFds.put(key, target) != null) continue

            val category = classifyPath(target)
            if (category == AccessCategory.OTHER) continue

            record(
                category = category,
                action = "fd:$fd",
                request = "Открытый дескриптор: $target",
                response = "FD=$fd",
                raw = line.trim()
            )
        }
    }

    private suspend fun pollNetworkConnections() {
        val tcpOutput = RootShell.execAndRead("cat /proc/$pid/net/tcp /proc/$pid/net/tcp6 2>/dev/null")
        for (line in tcpOutput.lines()) {
            if (line.startsWith("sl")) continue
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size < 3) continue

            val local = decodeAddress(parts[1])
            val remote = decodeAddress(parts[2])
            val state = tcpStateName(parts[3])
            val key = "$local->$remote:$state"
            if (knownConnections.put(key, state) != null) continue

            record(
                category = AccessCategory.NETWORK,
                action = "TCP $state",
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
            "gps" in lower || "location" in lower || "gnss" in lower -> AccessCategory.LOCATION
            "audio" in lower || "mic" in lower -> AccessCategory.MICROPHONE
            "bluetooth" in lower -> AccessCategory.BLUETOOTH
            "radio" in lower || "telephony" in lower -> AccessCategory.TELEPHONY
            "contacts" in lower -> AccessCategory.CONTACTS
            "sms" in lower -> AccessCategory.SMS
            "socket:" -> AccessCategory.NETWORK
            "anon_inode" in lower && "sync" in lower -> AccessCategory.SYSTEM_API
            "/dev/" in lower -> AccessCategory.SYSTEM_API
            "/data/" in lower || "/storage/" in lower -> AccessCategory.STORAGE
            else -> AccessCategory.OTHER
        }
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
