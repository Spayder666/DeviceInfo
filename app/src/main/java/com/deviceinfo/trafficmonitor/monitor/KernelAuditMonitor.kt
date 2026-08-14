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

/**
 * Ядро и SELinux: AVC denials, binder failures, audit.
 * Пишутся в kernel/dmesg, а не в PID-logcat приложения.
 */
class KernelAuditMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var streamJob: Job? = null
    private var pollJob: Job? = null

    fun start() {
        streamJob = scope.launch(Dispatchers.IO) {
            try {
                RootShell.execStreaming("logcat -v threadtime -b kernel -T 1 2>&1") { line ->
                    if (isActive) scope.launch { parse(line) }
                }
            } catch (_: Exception) {
            }
        }
        pollJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollDmesg()
                delay(4000)
            }
        }
    }

    fun stop() {
        streamJob?.cancel()
        pollJob?.cancel()
        streamJob = null
        pollJob = null
    }

    private suspend fun pollDmesg() {
        val grep = buildString {
            append("dmesg -T 2>/dev/null | grep -E 'avc:|denied|binder:|audit:' | tail -n 30")
        }
        val dump = RootShell.execAndRead(grep, timeoutSec = 6)
        for (line in dump.lines()) {
            parse(line)
        }
    }

    private suspend fun parse(line: String) {
        if (line.isBlank()) return
        val interesting = INTERESTING.containsMatchIn(line)
        if (!interesting) return
        val appId = if (uid > 0) "u0a${uid % 100000}" else ""
        val mentions = line.contains(packageName) ||
            (uid > 0 && line.contains("uid=$uid")) ||
            (appId.isNotEmpty() && line.contains(appId))
        if (!mentions && !line.contains("avc:")) return
        if (!mentions && line.contains("avc:") && !AVC_HINT.containsMatchIn(line)) return

        val category = when {
            LOCATION_HINT.containsMatchIn(line) -> AccessCategory.LOCATION
            line.contains("camera", ignoreCase = true) -> AccessCategory.CAMERA
            line.contains("audio", ignoreCase = true) || line.contains("mic", ignoreCase = true) ->
                AccessCategory.MICROPHONE
            else -> AccessCategory.SYSTEM_API
        }
        if (repository.isDuplicate(packageName, "kernel/avc", line, sinceMs = 4000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.LOGCAT,
                action = if (line.contains("avc:")) "SELinux AVC" else "kernel / binder",
                requestDetails = "logcat -b kernel / dmesg",
                responseDetails = line.substringAfter(": ").take(280).ifBlank { line.take(280) },
                rawData = line.trim()
            )
        )
    }

    companion object {
        private val INTERESTING = Regex("(?i)avc:|denied|binder:|audit:|selinux")
        private val AVC_HINT = Regex(
            "(?i)location|gnss|gps|camera|audio|radio|telephony|clipboard|" +
                "contacts|sms|bluetooth|nfc|sensor|inet|connect"
        )
        private val LOCATION_HINT = Regex("(?i)location|gnss|gps|geofence")
    }
}
