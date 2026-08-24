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
 * Внутренности GMS: Fused / NLP / Geofence / Activity Recognition /
 * сервисы com.google.android.gms, которые отдают координаты приложению.
 */
class GmsInternalsMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            var index = 0
            while (isActive) {
                when (index % 5) {
                    0 -> pollGmsServices()
                    1 -> pollLocationGms()
                    2 -> pollGmsLogcat()
                    3 -> pollPlayServicesDump()
                    else -> pollActivityRecognition()
                }
                index++
                delay(2200)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollGmsServices() {
        val dump = RootShell.execAndRead(
            "dumpsys activity services com.google.android.gms 2>/dev/null | " +
                "grep -E -i 'location|fused|geofence|nlp|activityrec|flp|izat|$packageName' | head -n 30",
            timeoutSec = 10
        )
        emit(AccessCategory.LOCATION, "GMS services", dump, "location.gms")
    }

    private suspend fun pollLocationGms() {
        val dump = RootShell.execAndRead(
            "dumpsys location 2>/dev/null | grep -A6 -E -i " +
                "'$packageName|Fused|GCoreFlp|NLP|Geofence|GoogleLocation' | head -n 40",
            timeoutSec = 10
        )
        emit(AccessCategory.LOCATION, "GMS location dump", dump, "location.fused")
    }

    private suspend fun pollGmsLogcat() {
        val dump = RootShell.execAndRead(
            "logcat -d -t 80 -s GmsCore:V GCoreFlp:V GoogleLocationManager:V " +
                "GeofencerStateMachine:V NlpService:V FusedLocationProvider:V " +
                "LocationReceiver:V IZat:V 2>/dev/null | " +
                "grep -E -i '$packageName|Location\\[|lat=|requestLocation' | tail -n 20",
            timeoutSec = 8
        )
        emit(AccessCategory.LOCATION, "GMS logcat", dump, "location.gms")
    }

    private suspend fun pollPlayServicesDump() {
        val dump = RootShell.execAndRead(
            "dumpsys activity provider com.google.android.gms 2>/dev/null | " +
                "grep -A3 -F '$packageName' | head -n 20",
            timeoutSec = 8
        )
        emit(AccessCategory.IDENTIFIER, "GMS provider", dump, "account.google")
    }

    private suspend fun pollActivityRecognition() {
        val dump = RootShell.execAndRead(
            "dumpsys activity broadcasts 2>/dev/null | grep -A2 -E " +
                "'ActivityRecognition|DetectedActivity|$packageName' | head -n 24",
            timeoutSec = 8
        )
        emit(AccessCategory.LOCATION, "Activity Recognition", dump, "location.activity")
    }

    private suspend fun emit(category: AccessCategory, action: String, dump: String, identifierId: String) {
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
                requestDetails = "GMS / Play services",
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = identifierId,
                identifierGroup = if (identifierId.startsWith("location")) "LOCATION" else "ACCOUNT"
            )
        )
    }
}
