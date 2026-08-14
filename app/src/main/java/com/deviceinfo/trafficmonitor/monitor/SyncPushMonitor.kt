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

/** SyncManager, FCM/GCM (часто будит GPS) и wakelock'и пакета. */
class SyncPushMonitor(
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
                when (i % 3) {
                    0 -> pollSync()
                    1 -> pollFcm()
                    else -> pollWake()
                }
                i++
                delay(3200)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollSync() {
        val dump = RootShell.execAndRead(
            "dumpsys content 2>/dev/null | grep -A6 -F '$packageName' | head -n 30; " +
                "dumpsys sync 2>/dev/null | grep -A4 -F '$packageName' | head -n 24",
            timeoutSec = 10
        )
        emit(AccessCategory.SYSTEM_API, "SyncAdapter", dump, null)
    }

    private suspend fun pollFcm() {
        val dump = RootShell.execAndRead(
            "logcat -d -t 60 -s FirebaseMessaging:V FCM:V GCM:V GcmReceiver:V GcmService:V 2>/dev/null | " +
                "grep -F '$packageName' | tail -n 15; " +
                "dumpsys activity services com.google.android.gms/.gcm 2>/dev/null | " +
                "grep -A3 -F '$packageName' | head -n 16",
            timeoutSec = 10
        )
        emit(AccessCategory.NETWORK, "FCM / GCM", dump, "net.http")
    }

    private suspend fun pollWake() {
        val dump = RootShell.execAndRead(
            "dumpsys power 2>/dev/null | grep -A1 -F '$packageName' | head -n 20; " +
                "dumpsys batterystats $packageName 2>/dev/null | grep -E -i 'wake|gps|wifi' | head -n 16",
            timeoutSec = 10
        )
        val category = if (dump.contains("gps", ignoreCase = true)) AccessCategory.LOCATION else AccessCategory.SYSTEM_API
        emit(category, "Wakelock", dump, if (category == AccessCategory.LOCATION) "location.gps" else null)
    }

    private suspend fun emit(category: AccessCategory, action: String, dump: String, id: String?) {
        if (dump.isBlank()) return
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
                identifierGroup = when {
                    id?.startsWith("location") == true -> "LOCATION"
                    id?.startsWith("net") == true -> "NETWORK"
                    else -> null
                }
            )
        )
    }
}
