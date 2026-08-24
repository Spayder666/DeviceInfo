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

/** FGS-типы (location/camera/mic), индикаторы приватности, оверлеи и virtual display. */
class PrivacyFgsMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            var i = 0
            while (isActive) {
                when (i % 4) {
                    0 -> pollFgs()
                    1 -> pollPrivacy()
                    2 -> pollOverlay()
                    else -> pollSensorPrivacy()
                }
                i++
                delay(2500)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollFgs() {
        val dump = RootShell.execAndRead(
            "dumpsys activity services $packageName 2>/dev/null | " +
                "grep -E -i 'isForeground|foregroundId|fgsType|location|camera|microphone|specialUse|dataSync' | head -n 25",
            timeoutSec = 8
        )
        val category = when {
            dump.contains("location", ignoreCase = true) -> AccessCategory.LOCATION
            dump.contains("camera", ignoreCase = true) -> AccessCategory.CAMERA
            dump.contains("microphone", ignoreCase = true) || dump.contains("mic", ignoreCase = true) ->
                AccessCategory.MICROPHONE
            else -> AccessCategory.SYSTEM_API
        }
        emit(category, "FGS type", dump, if (category == AccessCategory.LOCATION) "location.gps" else null)
    }

    private suspend fun pollPrivacy() {
        val dump = RootShell.execAndRead(
            "dumpsys privacy 2>/dev/null | grep -A4 -F '$packageName' | head -n 24; " +
                "dumpsys location_time_zone_manager 2>/dev/null | head -c 2000",
            timeoutSec = 8
        )
        emit(AccessCategory.PERMISSION, "Privacy indicators", dump, null)
    }

    private suspend fun pollOverlay() {
        val dump = RootShell.execAndRead(
            "dumpsys window windows 2>/dev/null | grep -A3 -E '$packageName|TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT' | head -n 30; " +
                "dumpsys display 2>/dev/null | grep -A3 -E 'VirtualDisplay|$packageName' | head -n 20",
            timeoutSec = 10
        )
        emit(AccessCategory.SYSTEM_API, "Overlay / VirtualDisplay", dump, null)
    }

    private suspend fun pollSensorPrivacy() {
        val dump = RootShell.execAndRead(
            "dumpsys sensor_privacy 2>/dev/null | head -c 4000; " +
                "cmd sensor_privacy 2>/dev/null | head -n 20",
            timeoutSec = 8
        )
        emit(AccessCategory.PERMISSION, "Sensor privacy", dump, null)
    }

    private suspend fun emit(category: AccessCategory, action: String, dump: String, id: String?) {
        if (dump.isBlank() || isUselessDump(dump) || !dumpMentionsTarget(dump, packageName)) return
        val snippet = dump.lineSequence().filter { it.isNotBlank() }.take(10).joinToString("\n")
        if (snippet.isBlank()) return
        val key = "$action:${snippet.hashCode()}"
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, snippet, sinceMs = 8000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = action,
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = id,
                identifierGroup = if (id?.startsWith("location") == true) "LOCATION" else null
            )
        )
    }
}
