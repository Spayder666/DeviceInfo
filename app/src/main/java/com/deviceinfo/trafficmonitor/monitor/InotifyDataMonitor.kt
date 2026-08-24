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
 * Следит за записью в /data/data/<pkg>: кэш GPS, prefs, sqlite.
 * inotifywait если есть, иначе периодический find по mtime.
 */
class InotifyDataMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            val base = "/data/data/$packageName"
            val hasInotify = RootShell.execAndRead(
                "command -v inotifywait >/dev/null && echo ok"
            ).contains("ok")
            if (hasInotify) {
                try {
                    val cmd = "inotifywait -m -r -e modify,create,moved_to --format '%e %w%f' $base 2>/dev/null"
                    RootShell.execStreaming(cmd) { line ->
                        if (isActive) scope.launch { onPath(line.substringAfter(' ').trim(), line) }
                    }
                } catch (_: Exception) {
                    pollLoop(base)
                }
            } else {
                pollLoop(base)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollLoop(base: String) {
        while (scope.isActive) {
            val listing = RootShell.execAndRead(
                "find $base -type f \\( -name '*.db' -o -name '*.xml' -o -name '*loc*' " +
                    "-o -name '*gps*' -o -name '*track*' -o -name '*coord*' -o -name '*cache*' \\) " +
                    "-mmin -2 2>/dev/null | head -n 30",
                timeoutSec = 8
            )
            for (path in listing.lines()) {
                if (path.isBlank()) continue
                onPath(path.trim(), "find $path")
            }
            delay(3000)
        }
    }

    private suspend fun onPath(path: String, raw: String) {
        if (path.isBlank() || path.endsWith(".lock") || path.endsWith("-journal") ||
            path.endsWith("-wal") || path.endsWith("-shm")
        ) return
        val lower = path.lowercase()
        if (!INTERESTING.containsMatchIn(lower) &&
            !lower.endsWith(".db") && !lower.endsWith(".xml")
        ) return

        val key = path
        if (seen.put(key, raw) != null && !INTERESTING.containsMatchIn(lower)) return

        val category = when {
            LOCATION_HINT.containsMatchIn(lower) -> AccessCategory.LOCATION
            lower.contains("contact") -> AccessCategory.CONTACTS
            lower.contains("sms") || lower.contains("mms") -> AccessCategory.SMS
            lower.contains("clipboard") -> AccessCategory.CLIPBOARD
            else -> AccessCategory.STORAGE
        }
        if (repository.isDuplicate(packageName, "inotify", path, sinceMs = 5000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.PROC,
                action = "Запись в данные приложения",
                requestDetails = path,
                responseDetails = path.substringAfterLast('/'),
                rawData = raw.take(400),
                identifierName = if (category == AccessCategory.LOCATION) "location.gps" else null,
                identifierGroup = if (category == AccessCategory.LOCATION) "LOCATION" else null
            )
        )
    }

    companion object {
        private val INTERESTING = Regex(
            "(?i)loc|gps|gnss|track|coord|lat|lon|pref|setting|cache|imei|android_id|device"
        )
        private val LOCATION_HINT = Regex("(?i)loc|gps|gnss|track|coord|lat|lon")
    }
}
