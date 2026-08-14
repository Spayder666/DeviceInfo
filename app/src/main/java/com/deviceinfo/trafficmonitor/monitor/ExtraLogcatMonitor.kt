package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Буферы events / radio / crash — туда пишут RIL, AMS и система, не процесс приложения. */
class ExtraLogcatMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            val cmd = "logcat -v threadtime -b events -b radio -b crash -T 1 2>&1"
            try {
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) scope.launch { parse(line) }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun parse(line: String) {
        if (line.isBlank()) return
        val mentions = line.contains(packageName) || (uid > 0 && line.contains("uid=$uid"))
        val radio = line.contains("RIL") || line.contains("GSM") || line.contains("UMTS") ||
            line.contains("LTE") || line.contains("NR_") || line.contains("IMS")
        val sim = Regex("(?i)sim.?state|imsi|iccid|operator|mccmnc|subscriber|iphonesubinfo|getSim").containsMatchIn(line)
        val loc = line.contains("location", ignoreCase = true) || line.contains("gps", ignoreCase = true)
        if (!mentions && !radio && !loc && !sim) return
        if (!mentions && radio && !sim && !line.contains("imei", ignoreCase = true) &&
            !line.contains("cell", ignoreCase = true)
        ) return

        val category = when {
            loc -> AccessCategory.LOCATION
            radio || line.contains("RIL") -> AccessCategory.TELEPHONY
            line.contains("am_crash") || line.contains("force_finish") -> AccessCategory.SYSTEM_API
            else -> AccessCategory.SYSTEM_API
        }
        if (repository.isDuplicate(packageName, "events/radio", line, sinceMs = 2000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.LOGCAT,
                action = if (radio) "radio buffer" else "events buffer",
                requestDetails = "logcat -b events/radio/crash",
                responseDetails = line.substringAfter(": ").take(280),
                rawData = line.trim()
            )
        )
    }
}
