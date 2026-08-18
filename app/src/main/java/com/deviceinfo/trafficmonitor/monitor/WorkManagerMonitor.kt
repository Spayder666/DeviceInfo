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

/** JobScheduler, AlarmManager и androidx WorkManager DB — фоновые GPS/синк задачи. */
class WorkManagerMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollJobs()
                pollAlarms()
                pollWorkDb()
                delay(4000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollJobs() {
        val dump = RootShell.execAndRead(
            "dumpsys jobscheduler $packageName 2>/dev/null | head -c 8000",
            timeoutSec = 10
        )
        if (!dump.contains(packageName) && !dump.contains("JobStatus")) return
        val interesting = dump.lineSequence().filter { line ->
            line.contains(packageName) || JOB_HINT.containsMatchIn(line)
        }.take(12).joinToString("\n")
        if (interesting.isBlank()) return
        val category = if (LOCATION.containsMatchIn(interesting)) AccessCategory.LOCATION else AccessCategory.SYSTEM_API
        emit(category, "JobScheduler", interesting, if (category == AccessCategory.LOCATION) "location.gps" else null)
    }

    private suspend fun pollAlarms() {
        val dump = RootShell.execAndRead(
            "dumpsys alarm 2>/dev/null | grep -A3 -F '$packageName' | head -n 30",
            timeoutSec = 8
        )
        if (dump.isBlank()) return
        emit(AccessCategory.SYSTEM_API, "AlarmManager", dump, null)
    }

    private suspend fun pollWorkDb() {
        val listing = RootShell.execAndRead(
            "ls /data/data/$packageName/no_backup /data/data/$packageName/databases 2>/dev/null",
            timeoutSec = 6
        )
        val db = listing.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.contains("work", ignoreCase = true) && it.endsWith(".db") }
            ?: return
        val path = when {
            db.startsWith("/") -> db
            listing.contains("no_backup") -> "/data/data/$packageName/no_backup/$db"
            else -> "/data/data/$packageName/databases/$db"
        }
        val rows = RootShell.execAndRead(
            "sqlite3 -header -column ${RootShell.shellQuote(path)} " +
                "\"select id, state, worker_class_name from WorkSpec limit 8\" 2>/dev/null",
            timeoutSec = 6
        ).trim()
        if (rows.isBlank()) return
        val category = if (LOCATION.containsMatchIn(rows)) AccessCategory.LOCATION else AccessCategory.SYSTEM_API
        emit(category, "WorkManager DB", rows, if (category == AccessCategory.LOCATION) "location.activity" else null)
    }

    private suspend fun emit(category: AccessCategory, action: String, raw: String, identifierId: String?) {
        val snippet = raw.take(600)
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
                rawData = snippet,
                identifierName = identifierId,
                identifierGroup = if (identifierId?.startsWith("location") == true) "LOCATION" else null
            )
        )
    }

    companion object {
        private val JOB_HINT = Regex("(?i)periodic|persisted|location|gps|sync|work|foreground")
        private val LOCATION = Regex("(?i)location|gps|gnss|fused|geofence|track")
    }
}
