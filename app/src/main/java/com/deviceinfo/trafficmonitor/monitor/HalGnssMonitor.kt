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

/** HIDL/AIDL GNSS HAL, /dev/gnss*, vendor gps.conf и кэш /data/vendor/gps. */
class HalGnssMonitor(
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
                    0 -> pollLshal()
                    1 -> pollHalDump()
                    2 -> pollDevNodes()
                    else -> pollVendorFiles()
                }
                i++
                delay(2800)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollLshal() {
        val dump = RootShell.execAndRead(
            "lshal 2>/dev/null | grep -E -i 'gnss|gps|geofence|measurement' | head -n 25",
            timeoutSec = 8
        )
        if (dumpMentionsTarget(dump, packageName)) {
            emit("GNSS HAL (lshal)", dump)
        }
    }

    private suspend fun pollHalDump() {
        val dump = RootShell.execAndRead(
            "dumpsys android.hardware.gnss.IGnss/default 2>/dev/null; " +
                "dumpsys android.hardware.gnss.IGnss_V2 2>/dev/null; " +
                "dumpsys vendor.qti.gnss 2>/dev/null | head -c 6000",
            timeoutSec = 10
        )
        if (dumpMentionsTarget(dump, packageName)) {
            emit("GNSS HAL dumpsys", dump)
        }
    }

    private suspend fun pollDevNodes() {
        val dump = RootShell.execAndRead(
            "ls -l /dev/gnss* /dev/gps* /dev/ttyGPS* /dev/ttyGNSS* 2>/dev/null; " +
                "lsof /dev/gnss0 /dev/gps 2>/dev/null | head -n 15",
            timeoutSec = 8
        )
        if (dumpMentionsTarget(dump, packageName)) {
            emit("GNSS /dev", dump)
        }
    }

    private suspend fun pollVendorFiles() {
        val dump = RootShell.execAndRead(
            "ls -l /data/vendor/gps /data/vendor/location /data/system/location " +
                "/vendor/etc/gps.conf /vendor/etc/gnss 2>/dev/null | head -n 30; " +
                "find /data/vendor/gps /data/system/location -type f -mmin -3 2>/dev/null | head -n 20",
            timeoutSec = 8
        )
        if (dumpMentionsTarget(dump, packageName)) {
            emit("vendor GPS files", dump)
        }
    }

    private suspend fun emit(action: String, dump: String) {
        if (dump.isBlank()) return
        val snippet = dump.lineSequence().filter { it.isNotBlank() }.take(12).joinToString("\n")
        if (snippet.isBlank()) return
        val key = "$action:${snippet.hashCode()}"
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, snippet, sinceMs = 10000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.LOCATION,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = "GNSS HAL / vendor",
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = "location.hal",
                identifierGroup = "LOCATION"
            )
        )
    }
}
