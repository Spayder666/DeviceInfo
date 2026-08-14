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
 * `am trace-ipc` — кто с кем говорит по Binder (LMS, camera, telephony),
 * плюс dumpsys binder для целевого UID.
 */
class BinderIpcMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()
    private val dumpFile = "${MonitorPaths.BASE}/ipc.txt"

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            RootShell.execAndRead("mkdir -p ${MonitorPaths.BASE}")
            while (isActive) {
                runTrace()
                pollBinderStats()
                delay(12000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        RootShell.execAndRead("am trace-ipc stop 2>/dev/null")
    }

    private suspend fun runTrace() {
        RootShell.execAndRead("am trace-ipc start 2>/dev/null", timeoutSec = 6)
        delay(4000)
        val stop = RootShell.execAndRead(
            "am trace-ipc stop --dump-file $dumpFile 2>&1",
            timeoutSec = 8
        )
        val dump = RootShell.execAndRead(
            "grep -E -i '$packageName|location|gnss|gps|camera|audio|telephony|iphonesubinfo|isub|phone|clipboard' $dumpFile 2>/dev/null | head -n 40",
            timeoutSec = 6
        )
        val text = dump.ifBlank { stop }
        emit("am trace-ipc", text)
    }

    private suspend fun pollBinderStats() {
        val dump = RootShell.execAndRead(
            "dumpsys binder 2>/dev/null | grep -A4 -E '$packageName|uid=$uid' | head -n 30",
            timeoutSec = 8
        )
        emit("dumpsys binder", dump)
    }

    private suspend fun emit(action: String, dump: String) {
        if (dump.isBlank() || dump.contains("Unknown command", ignoreCase = true)) return
        val snippet = dump.lineSequence().filter { it.isNotBlank() }.take(12).joinToString("\n")
        if (snippet.isBlank()) return
        val key = "$action:${snippet.hashCode()}"
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, snippet, sinceMs = 15000)) return
        val category = when {
            LOCATION.containsMatchIn(snippet) -> AccessCategory.LOCATION
            snippet.contains("camera", ignoreCase = true) -> AccessCategory.CAMERA
            snippet.contains("audio", ignoreCase = true) -> AccessCategory.MICROPHONE
            TELEPHONY.containsMatchIn(snippet) -> AccessCategory.TELEPHONY
            else -> AccessCategory.SYSTEM_API
        }
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = "Binder IPC",
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = if (category == AccessCategory.LOCATION) "location.gps" else null,
                identifierGroup = if (category == AccessCategory.LOCATION) "LOCATION" else null
            )
        )
    }

    companion object {
        private val LOCATION = Regex("(?i)location|gnss|gps|fused|geofence")
        private val TELEPHONY = Regex("(?i)telephony|iphonesubinfo|isub|phoneinterface|siminfo|ril")
    }
}
