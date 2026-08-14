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
 * Короткие сессии Perfetto / atrace: таймлайн AM/WM/camera/audio/binder
 * для целевого пакета. Не держит трейс постоянно — 3.5 с каждые ~8 с.
 */
class PerfettoMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()
    private var announced = false

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            RootShell.execAndRead("mkdir -p ${MonitorPaths.BASE}")
            writeConfig()
            val hasPerfetto = RootShell.resolveBinary("perfetto") != null
            val hasAtrace = RootShell.resolveBinary("atrace") != null
            if (!hasPerfetto && !hasAtrace) {
                recordOnce(
                    AccessCategory.SYSTEM_API,
                    "Perfetto недоступен",
                    "на устройстве нет perfetto/atrace",
                    "пропуск трейсов"
                )
                return@launch
            }
            while (isActive) {
                if (hasPerfetto) runPerfetto() else runAtrace()
                delay(8000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        RootShell.execAndRead("pkill -f 'perfetto -c ${MonitorPaths.PERFETTO_CFG}' 2>/dev/null")
    }

    private fun writeConfig() {
        val cfg = """
            buffers { size_kb: 6144 }
            duration_ms: 3500
            data_sources {
              config {
                name: "linux.ftrace"
                ftrace_config {
                  atrace_categories: "am"
                  atrace_categories: "wm"
                  atrace_categories: "view"
                  atrace_categories: "camera"
                  atrace_categories: "audio"
                  atrace_categories: "dalvik"
                  atrace_categories: "binder_driver"
                  atrace_apps: "$packageName"
                  ftrace_events: "binder/binder_transaction"
                }
              }
            }
            data_sources { config { name: "android.packages_list" } }
        """.trimIndent()
        RootShell.execAndRead(
            "printf %s ${RootShell.shellQuote(cfg)} > ${MonitorPaths.PERFETTO_CFG}"
        )
    }

    private suspend fun runPerfetto() {
        RootShell.execAndRead(
            "perfetto -c ${MonitorPaths.PERFETTO_CFG} -o ${MonitorPaths.PERFETTO_OUT} 2>/dev/null",
            timeoutSec = 12
        )
        val extracted = RootShell.execAndRead(
            "strings ${MonitorPaths.PERFETTO_OUT} 2>/dev/null | " +
                "grep -E -i 'location|gps|gnss|fused|camera|audio|record|binder|$packageName|geofence' | " +
                "head -n 40",
            timeoutSec = 8
        )
        emitTrace("perfetto", extracted)
    }

    private suspend fun runAtrace() {
        val dump = RootShell.execAndRead(
            "atrace -t 3 -b 2048 am wm view camera audio dalvik binder_driver 2>/dev/null | " +
                "grep -E -i 'location|gps|camera|audio|$packageName|binder' | head -n 40",
            timeoutSec = 12
        )
        emitTrace("atrace", dump)
    }

    private suspend fun emitTrace(tool: String, dump: String) {
        if (dump.isBlank()) return
        val lines = dump.lineSequence().filter { it.isNotBlank() }.take(12).joinToString("\n")
        if (lines.isBlank()) return
        val key = "$tool:${lines.hashCode()}"
        if (seen.put(key, "1") != null) return
        val category = when {
            LOCATION.containsMatchIn(lines) -> AccessCategory.LOCATION
            lines.contains("camera", ignoreCase = true) -> AccessCategory.CAMERA
            lines.contains("audio", ignoreCase = true) -> AccessCategory.MICROPHONE
            else -> AccessCategory.SYSTEM_API
        }
        if (!announced) {
            announced = true
            recordOnce(
                AccessCategory.SYSTEM_API,
                "Perfetto/atrace запущен",
                tool,
                "короткие трейсы am/wm/camera/audio/binder"
            )
        }
        if (repository.isDuplicate(packageName, tool, lines, sinceMs = 10000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.PERFETTO,
                action = if (category == AccessCategory.LOCATION) "trace GPS" else "trace $tool",
                requestDetails = "$tool 3.5s atrace cats + $packageName",
                responseDetails = lines.take(400),
                rawData = lines.take(1500),
                identifierName = if (category == AccessCategory.LOCATION) "location.gps" else null,
                identifierGroup = if (category == AccessCategory.LOCATION) "LOCATION" else null
            )
        )
    }

    private suspend fun recordOnce(category: AccessCategory, action: String, request: String, response: String) {
        if (repository.isDuplicate(packageName, action, response, sinceMs = 60_000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.PERFETTO,
                action = action,
                requestDetails = request,
                responseDetails = response,
                rawData = response
            )
        )
    }

    companion object {
        private val LOCATION = Regex("(?i)location|gps|gnss|fused|geofence")
    }
}
