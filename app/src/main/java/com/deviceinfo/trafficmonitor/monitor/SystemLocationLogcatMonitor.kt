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

/**
 * Системный logcat (system_server + GMS + GNSS), не ограниченный PID трекера.
 * Fused Location пишет логи в com.google.android.gms, а не в процесс приложения.
 */
class SystemLocationLogcatMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            val tags = listOf(
                "LocationManagerService:V",
                "LocationProviderManager:V",
                "GnssLocationProvider:V",
                "GnssLocationProviderExt:V",
                "GnssManagerService:V",
                "GpsLocationProvider:V",
                "FusedLocationProvider:V",
                "FusedLocation:V",
                "GCoreFlp:V",
                "FLP:V",
                "NetworkLocationService:V",
                "NlpService:V",
                "NlpLocationHelper:V",
                "GeofencerStateMachine:V",
                "GeofenceManager:V",
                "GnssVisibilityControl:V",
                "SUPL:V",
                "IZat:V",
                "QLocation:V",
                "GoogleLocationManager:V",
                "GmsLocation:V",
                "Places:V",
                "ActivityRecognition:V",
                "WifiScanningService:V"
            ).joinToString(" ")
            val cmd = "logcat -v threadtime -T 1 $tags *:S 2>&1"
            try {
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) scope.launch { parseLine(line) }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun parseLine(line: String) {
        if (line.isBlank()) return
        val mentionsPkg = line.contains(packageName)
        val loc = LOCATION_FIX.find(line)
        val interesting = mentionsPkg || loc != null ||
            line.contains("LocationRequest", ignoreCase = true) ||
            line.contains("requestLocation", ignoreCase = true) ||
            line.contains("delivering", ignoreCase = true) ||
            line.contains("onLocation", ignoreCase = true)

        if (!interesting) return

        val latLon = loc?.let { "lat=${it.groupValues[2]} lon=${it.groupValues[3]}" }
            ?: LATLON.find(line)?.let { "lat=${it.groupValues[1]} lon=${it.groupValues[2]}" }

        val action = when {
            loc != null -> "Фикс ${(loc.groupValues[1])}"
            line.contains("Fused", ignoreCase = true) || line.contains("GCoreFlp") -> "Fused / GMS"
            line.contains("SUPL", ignoreCase = true) -> "SUPL / AGPS"
            line.contains("Geofence", ignoreCase = true) -> "Geofence"
            line.contains("Nlp", ignoreCase = true) || line.contains("network", ignoreCase = true) -> "Network Location"
            line.contains("WifiScan", ignoreCase = true) -> "Wi‑Fi scan (локация)"
            else -> "Location log"
        }

        if (repository.isDuplicate(packageName, action, line, sinceMs = 1500)) return

        val id = when {
            action.startsWith("Fused") -> "location.fused"
            action.startsWith("SUPL") -> "location.supl"
            action.startsWith("Geofence") -> "location.geofence"
            action.startsWith("Network") -> "location.network"
            action.startsWith("Wi") -> "location.wifi_scan"
            else -> "location.gps"
        }

        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.LOCATION,
                source = EventSource.LOGCAT,
                action = action,
                permission = "ACCESS_FINE_LOCATION",
                requestDetails = if (mentionsPkg) "Упоминание $packageName в системном логе" else "Системный location log (GMS / LMS / GNSS)",
                responseDetails = latLon ?: line.substringAfter(": ").take(240),
                rawData = line.trim(),
                identifierName = id,
                identifierGroup = "LOCATION"
            )
        )
    }

    companion object {
        private val LOCATION_FIX = Regex(
            """Location\[(\w+)\s+(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)"""
        )
        private val LATLON = Regex(
            """(?i)(?:lat(?:itude)?|latitude)\s*[=:]\s*(-?\d+\.\d+).{0,40}(?:lon(?:gitude)?|longitude)\s*[=:]\s*(-?\d+\.\d+)"""
        )
    }
}
