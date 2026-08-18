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

/** OEM-локация (IZat / HMS / SEM / MIUI) и indoor: Wi‑Fi RTT, UWB, Wi‑Fi Aware. */
class OemIndoorMonitor(
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
                    0 -> pollOem()
                    1 -> pollRtt()
                    2 -> pollUwb()
                    else -> pollAware()
                }
                i++
                delay(3000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollOem() {
        val dump = RootShell.execAndRead(
            "logcat -d -t 50 -s IZat:V QLocation:V izat:V HwLocation:V HmsLocation:V " +
                "SemLocation:V MiuiLocation:V QLP:V 2>/dev/null | " +
                "grep -E -i '$packageName|Location\\[|lat=|request' | tail -n 16; " +
                "dumpsys vendor.qti.gnss 2>/dev/null | grep -A3 -F '$packageName' | head -n 16",
            timeoutSec = 10
        )
        if (dumpMentionsTarget(dump, packageName)) {
            emit("OEM location (IZat/HMS/SEM)", dump, "location.gms")
        }
    }

    private suspend fun pollRtt() {
        val dump = RootShell.execAndRead(
            "dumpsys wifirtt 2>/dev/null | head -c 5000; " +
                "dumpsys wifi 2>/dev/null | grep -A4 -E -i 'RTT|ranging|$packageName' | head -n 20",
            timeoutSec = 10
        )
        if (!dumpMentionsTarget(dump, packageName)) return
        if (isUselessDump(dump)) return
        emit("Wi‑Fi RTT / ranging", dump, "location.wifi_rtt")
    }

    private suspend fun pollUwb() {
        val dump = RootShell.execAndRead(
            "dumpsys uwb 2>/dev/null | grep -A4 -E '$packageName|ranging|session' | head -n 24; " +
                "cmd uwb 2>/dev/null | head -n 15",
            timeoutSec = 8
        )
        if (dumpMentionsTarget(dump, packageName)) {
            emit("UWB ranging", dump, "location.uwb")
        }
    }

    private suspend fun pollAware() {
        val dump = RootShell.execAndRead(
            "dumpsys wifiaware 2>/dev/null | grep -A4 -F '$packageName' | head -n 20; " +
                "dumpsys wifiscanner 2>/dev/null | grep -A3 -F '$packageName' | head -n 16",
            timeoutSec = 8
        )
        if (dumpMentionsTarget(dump, packageName)) {
            emit("Wi‑Fi Aware / scanner", dump, "location.wifi_scan")
        }
    }

    private suspend fun emit(action: String, dump: String, id: String) {
        if (dump.isBlank() || isUselessDump(dump)) return
        val snippet = dump.lineSequence().filter { it.isNotBlank() }.take(10).joinToString("\n")
        if (snippet.isBlank()) return
        val key = "$action:${snippet.hashCode()}"
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, snippet, sinceMs = 8000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.LOCATION,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = action,
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = id,
                identifierGroup = "LOCATION"
            )
        )
    }
}
