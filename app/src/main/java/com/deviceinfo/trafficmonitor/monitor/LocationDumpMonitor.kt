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
 * Перехват локации через AOSP LocationManagerService / GNSS / Activity,
 * а не через PID приложения. GPS-трекеры почти всегда получают координаты
 * из system_server / GMS (Fused), а не читая /dev/gps сами.
 */
class LocationDumpMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                if (TargetPresence.isAliveNow()) {
                    pollLocationService()
                    pollGnss()
                    pollAppLocationOps()
                    pollForegroundService()
                }
                delay(2000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    fun resetForNewProcess() {
        seen.clear()
    }

    private suspend fun pollLocationService() {
        val dump = RootShell.execAndRead("dumpsys location 2>/dev/null", timeoutSec = 12)
        if (dump.isBlank()) return

        parseLastLocations(dump)
        parseRegistrations(dump)
        parseRecentRequests(dump)
    }

    private suspend fun parseLastLocations(dump: String) {
        if (!dump.contains(packageName)) return
        val regex = Regex(
            """(?i)last (?:coarse )?location=Location\[(\w+)\s+(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)([^\]]*)]"""
        )
        for (match in regex.findAll(dump)) {
            val provider = match.groupValues[1]
            val lat = match.groupValues[2]
            val lon = match.groupValues[3]
            val extra = match.groupValues[4]
            val acc = Regex("hAcc=([^\\s\\]]+)").find(extra)?.groupValues?.get(1)
            val key = "last:$provider:$lat:$lon"
            if (key in seen) continue

            val id = when (provider.lowercase()) {
                "gps", "gnss" -> "location.gps"
                "fused" -> "location.fused"
                "network" -> "location.network"
                "passive" -> "location.passive"
                else -> "location.gps"
            }
            val ok = record(
                action = "Последняя координата ($provider)",
                request = "LocationManagerService / provider=$provider",
                response = buildString {
                    append("lat=$lat lon=$lon")
                    if (acc != null) append(" hAcc=$acc")
                    append("  (это то, что система отдаёт клиентам)")
                },
                raw = match.value,
                identifierId = id
            )
            if (ok) seen[key] = lat
        }
    }

    private suspend fun parseRegistrations(dump: String) {
        val pkgIdx = dump.indexOf(packageName)
        if (pkgIdx < 0) return

        val window = dump.substring((pkgIdx - 400).coerceAtLeast(0), (pkgIdx + 800).coerceAtMost(dump.length))
        val request = Regex("LocationRequest\\[[^]]+]").find(window)?.value
            ?: Regex("ProviderRequest\\[[^]]+]").find(window)?.value
            ?: Regex("interval[=:]\\s*\\S+").find(window)?.value
        val provider = Regex("(?i)(gps|fused|network|passive|gnss)\\s+provider").find(window)?.groupValues?.get(1)
            ?: Regex("(?i)provider[=:]\\s*(\\w+)").find(window)?.groupValues?.get(1)

        val key = "reg:$packageName:${request ?: window.hashCode()}"
        if (key in seen) return

        val ok = record(
            action = "Приложение подписано на локацию",
            request = "Пакет $packageName зарегистрирован в LocationManagerService" +
                (provider?.let { " (provider=$it)" } ?: ""),
            response = request ?: window.replace(Regex("\\s+"), " ").take(300),
            raw = window.take(500),
            identifierId = when (provider?.lowercase()) {
                "fused" -> "location.fused"
                "network" -> "location.network"
                "passive" -> "location.passive"
                else -> "location.gps"
            }
        )
        if (ok) seen[key] = request ?: "reg"
    }

    private suspend fun parseRecentRequests(dump: String) {
        val recent = Regex("(?i)Last Several Location Requests:([\\s\\S]{0,2500})").find(dump)?.groupValues?.get(1)
            ?: return
        for (line in recent.lines()) {
            if (!line.contains(packageName) && !line.contains("fused", ignoreCase = true) &&
                !line.contains("gps", ignoreCase = true) && !line.contains("network", ignoreCase = true)
            ) continue
            if (!line.contains(packageName) && !line.contains("request")) continue
            val key = "hist:${line.trim()}"
            if (key in seen) continue
            if (!line.contains(packageName)) continue
            val ok = record(
                action = "Запрос локации (история LMS)",
                request = line.trim(),
                response = "LocationManagerService зафиксировал запрос от $packageName",
                raw = line.trim(),
                identifierId = "location.gps"
            )
            if (ok) seen[key] = "1"
        }
    }

    private suspend fun pollGnss() {
        val dump = RootShell.execAndRead("dumpsys gnss 2>/dev/null | head -c 6000", timeoutSec = 8)
        if (dump.isBlank()) return

        val started = Regex("(?i)mStarted\\s*=\\s*(true|false)").find(dump)?.groupValues?.get(1)
        val interval = Regex("(?i)(?:mFixInterval|interval)\\s*=\\s*(\\d+)").find(dump)?.groupValues?.get(1)
        val ttff = Regex("(?i)TTFF\\s*[=:]\\s*(\\S+)").find(dump)?.groupValues?.get(1)
        val summary = listOfNotNull(
            started?.let { "GNSS started=$it" },
            interval?.let { "interval=${it}ms" },
            ttff?.let { "TTFF=$it" }
        ).joinToString(" ")
        if (summary.isBlank() || !dump.contains(packageName)) return
        val key = "gnss:$summary"
        if (key in seen) return
        val ok = record(
            action = "GNSS HAL",
            request = "dumpsys gnss",
            response = summary,
            raw = dump.take(400),
            identifierId = "location.hal"
        )
        if (ok) seen[key] = summary
    }

    private suspend fun pollAppLocationOps() {
        val dump = RootShell.execAndRead("dumpsys appops $packageName 2>/dev/null", timeoutSec = 10)
        val locationOps = listOf(
            "FINE_LOCATION", "COARSE_LOCATION", "GPS",
            "MONITOR_LOCATION", "MONITOR_HIGH_POWER_LOCATION",
            "NEARBY_WIFI_DEVICES", "ACTIVITY_RECOGNITION"
        )
        for (op in locationOps) {
            val block = Regex("""$op[\s\S]{0,400}""").find(dump)?.value ?: continue
            val access = Regex("""Access:\s*\[([^\]]+)]\s*([^\n]*)""").find(block)
            val inline = Regex("""$op:\s*\[([^\]]+)]\s*([^\n]*)""").find(block)
            val stamp = access?.groupValues?.get(2)?.trim()
                ?: inline?.groupValues?.get(2)?.trim()
                ?: continue
            if (stamp.isBlank() || !isRecentAccessStamp(stamp)) continue
            val key = "op:$op"
            if (key in seen) continue
            val delivered = op.startsWith("MONITOR")
            val ok = record(
                action = if (delivered) "Доставка локации ($op)" else "Доступ к $op",
                request = "AppOps $op",
                response = if (delivered) {
                    "Система зафиксировала получение координат приложением: $stamp"
                } else {
                    "Приложение обращалось к $op: $stamp"
                },
                raw = block.take(300),
                identifierId = if (op.contains("WIFI")) "location.wifi_scan" else "location.gps"
            )
            if (ok) seen[key] = stamp
        }
    }

    private suspend fun pollForegroundService() {
        val dump = RootShell.execAndRead(
            "dumpsys activity services $packageName 2>/dev/null | head -c 8000",
            timeoutSec = 8
        )
        if (dump.isBlank()) return
        val hasLocationFgs = dump.contains("location", ignoreCase = true) &&
            (dump.contains("foreground", ignoreCase = true) || dump.contains("isForeground"))
        if (!hasLocationFgs) return
        val snippet = dump.lines().filter {
            it.contains("location", ignoreCase = true) ||
                it.contains("ServiceRecord") ||
                it.contains("isForeground")
        }.joinToString("\n").take(400)
        if (snippet.isBlank()) return
        val fgsKey = "fgs:$packageName:${snippet.take(80)}"
        if (fgsKey in seen) return
        val ok = record(
            action = "Foreground service (location)",
            request = "dumpsys activity services $packageName",
            response = snippet.replace(Regex("\\s+"), " ").take(300),
            raw = snippet,
            identifierId = "location.gps"
        )
        if (ok) seen[fgsKey] = "1"
    }

    private suspend fun record(
        action: String,
        request: String?,
        response: String?,
        raw: String,
        identifierId: String? = "location.gps"
    ): Boolean {
        if (repository.isDuplicate(packageName, action, raw, sinceMs = 4000)) return true
        return repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.LOCATION,
                source = EventSource.DUMPSYS,
                action = action,
                permission = "ACCESS_FINE_LOCATION",
                requestDetails = request,
                responseDetails = response,
                rawData = raw,
                identifierName = identifierId,
                identifierGroup = "LOCATION"
            )
        ) > 0
    }
}
