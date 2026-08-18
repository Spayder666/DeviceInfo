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
 * statsd atoms: location, camera, appops, network — системные счётчики AOSP,
 * которые приложение само не логирует.
 */
class StatsdMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            var index = 0
            while (isActive) {
                when (index % 4) {
                    0 -> pollDumpsysStats()
                    1 -> pollCmdStats()
                    2 -> pollPulled()
                    else -> pollUidMap()
                }
                index++
                delay(3500)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollDumpsysStats() {
        val dump = RootShell.execAndRead(
            "dumpsys stats 2>/dev/null | grep -E -i " +
                "'$packageName|uid=$uid|location|gps|camera|app.?ops|audio|bluetooth|network' | head -n 50",
            timeoutSec = 12
        )
        emit("dumpsys stats", dump)
    }

    private suspend fun pollCmdStats() {
        val dump = RootShell.execAndRead(
            "cmd stats print-logs 2>/dev/null | grep -E -i '$packageName|uid=$uid|location|camera' | head -n 40",
            timeoutSec = 10
        )
        if (dump.isBlank()) {
            val alt = RootShell.execAndRead(
                "cmd statsd print-logs 2>/dev/null | grep -E -i '$packageName|location' | head -n 30",
                timeoutSec = 8
            )
            emit("cmd statsd", alt)
        } else {
            emit("cmd stats print-logs", dump)
        }
    }

    private suspend fun pollPulled() {
        val dump = RootShell.execAndRead(
            "dumpsys stats --proto 2>/dev/null | strings | " +
                "grep -E -i '$packageName|Atom|location_manager|gps_stats|camera|app_ops' | head -n 40",
            timeoutSec = 12
        )
        emit("stats proto atoms", dump)
    }

    private suspend fun pollUidMap() {
        val dump = RootShell.execAndRead(
            "cmd stats print-uid-map 2>/dev/null | grep -E '$uid|$packageName' | head -n 20",
            timeoutSec = 8
        )
        emit("stats uid-map", dump)
    }

    private suspend fun emit(action: String, dump: String) {
        if (dump.isBlank()) return
        val snippet = dump.lineSequence().filter { it.isNotBlank() }.take(10).joinToString("\n")
        if (snippet.isBlank()) return
        val key = "$action:${snippet.hashCode()}"
        if (seen.put(key, "1") != null) return
        val category = classify(snippet)
        if (repository.isDuplicate(packageName, action, snippet, sinceMs = 10000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.STATSD,
                action = action,
                requestDetails = "statsd atom / $action",
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = when (category) {
                    AccessCategory.LOCATION -> "location.gps"
                    AccessCategory.NETWORK -> "net.http"
                    else -> null
                },
                identifierGroup = if (category == AccessCategory.LOCATION) "LOCATION" else null
            )
        )
    }

    private fun classify(text: String): AccessCategory = when {
        LOCATION.containsMatchIn(text) -> AccessCategory.LOCATION
        text.contains("camera", ignoreCase = true) -> AccessCategory.CAMERA
        text.contains("audio", ignoreCase = true) -> AccessCategory.MICROPHONE
        text.contains("bluetooth", ignoreCase = true) -> AccessCategory.BLUETOOTH
        text.contains("appops", ignoreCase = true) || text.contains("app_ops", ignoreCase = true) ->
            AccessCategory.PERMISSION
        text.contains("network", ignoreCase = true) -> AccessCategory.NETWORK
        else -> AccessCategory.SYSTEM_API
    }

    companion object {
        private val LOCATION = Regex("(?i)location|gps|gnss|fused|geofence")
    }
}
