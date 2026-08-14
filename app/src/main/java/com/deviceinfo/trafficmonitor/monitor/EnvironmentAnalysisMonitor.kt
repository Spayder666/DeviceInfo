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
 * Не наш чекер root, а ответ на вопрос «что увидит целевое приложение, если спросит»:
 * su в его mount-ns, isolated helper, libc .text диск≠RAM.
 */
class EnvironmentAnalysisMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, Long>()
    @Volatile
    private var pid: Int = -1

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pid = RootShell.findPid(packageName) ?: pid
                compareHide()
                checkDenylist()
                checkIsolated()
                checkTextMismatch()
                delay(12_000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun compareHide() {
        if (pid <= 0) return
        val paths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/adb/magisk", "/data/adb/modules/zygisk_shamiko",
            "/debug_ramdisk/su"
        )
        val rootView = paths.map { p ->
            p to RootShell.execAndRead("test -e $p && echo yes || echo no", timeoutSec = 4).trim()
        }
        val appView = paths.map { p ->
            p to RootShell.execAndRead(
                "test -e /proc/$pid/root$p && echo yes || echo no",
                timeoutSec = 4
            ).trim()
        }
        val hidden = paths.indices.filter { rootView[it].second == "yes" && appView[it].second == "no" }
        val visible = paths.indices.filter { appView[it].second == "yes" }
        val summary = buildString {
            append("root: ")
            append(rootView.joinToString(" ") { "${it.first.substringAfterLast('/')}=${it.second}" })
            append(" | app-ns: ")
            append(appView.joinToString(" ") { "${it.first.substringAfterLast('/')}=${it.second}" })
        }
        val id = when {
            hidden.isNotEmpty() -> "root.hide"
            visible.isNotEmpty() -> "root.su"
            else -> "root.hide"
        }
        val action = when {
            hidden.isNotEmpty() -> "Hide: app не видит su (${hidden.size})"
            visible.isNotEmpty() -> "Hide нет: app видит su"
            else -> "Hide: su нет ни у root, ни у app"
        }
        emit(id, action, "ns /proc/$pid/root vs host", summary, summary)
    }

    private suspend fun checkDenylist() {
        val deny = RootShell.execAndRead(
            "(/data/adb/magisk/magisk --denylist ls 2>/dev/null || magisk --denylist ls 2>/dev/null || true) | head -n 40",
            timeoutSec = 6
        )
        val shamiko = RootShell.execAndRead(
            "ls -ld /data/adb/modules/zygisk_shamiko /data/adb/modules/shamiko 2>&1 | head -n 6",
            timeoutSec = 5
        )
        val onList = deny.contains(packageName)
        val shamikoOn = shamiko.contains("zygisk_shamiko") || shamiko.contains("shamiko") && !shamiko.contains("No such")
        if (!onList && !shamikoOn && deny.isBlank()) return
        emit(
            if (onList || shamikoOn) "root.hide" else "root.magisk",
            when {
                onList && shamikoOn -> "DenyList + Shamiko"
                onList -> "Magisk DenyList"
                shamikoOn -> "Shamiko module"
                else -> "magisk --denylist"
            },
            packageName,
            "denylist=${if (onList) "yes" else "no"} shamiko=${if (shamikoOn) "yes" else "no"}\n${deny.take(300)}",
            deny + "\n" + shamiko
        )
    }

    private suspend fun checkIsolated() {
        val pids = RootShell.findAllPids(packageName)
        if (pids.isEmpty()) return
        val procs = pids.take(12).joinToString("\n") { appPid ->
            val cmd = RootShell.execAndRead(
                "tr '\\0' ' ' < /proc/$appPid/cmdline 2>/dev/null",
                timeoutSec = 3
            ).trim()
            val st = RootShell.execAndRead(
                "grep -E 'NSpid|NoNewPrivs|Seccomp' /proc/$appPid/status 2>/dev/null | tr '\\n' ' '",
                timeoutSec = 3
            ).trim()
            "$appPid $cmd $st"
        }
        if (procs.isBlank()) return
        val isolated = procs.lineSequence().filter {
            it.contains(":isolated") || it.contains("isolated_app") || Regex("""\s$packageName:""").containsMatchIn(it)
        }.toList()
        if (isolated.isEmpty() && !procs.contains(":")) return
        val isoPid = isolated.firstOrNull()?.trim()?.substringBefore(' ')?.toIntOrNull()
        val isoSu = if (isoPid != null && isoPid > 0) {
            RootShell.execAndRead(
                "test -e /proc/$isoPid/root/system/bin/su && echo yes || echo no",
                timeoutSec = 4
            ).trim()
        } else ""
        emit(
            "root.isolated",
            if (isolated.isNotEmpty()) "Isolated process" else "Процессы пакета",
            packageName,
            buildString {
                append((isolated.ifEmpty { procs.lines().take(4) }).joinToString("\n").take(320))
                if (isoSu.isNotBlank()) append("\nisolated-ns su=$isoSu")
            },
            procs
        )
    }

    private suspend fun checkTextMismatch() {
        if (pid <= 0) return
        val line = RootShell.execAndRead(
            "awk '/r-xp/ && /libc\\.so/ {print; exit}' /proc/$pid/maps",
            timeoutSec = 5
        ).trim()
        if (line.isBlank()) return
        val parts = line.split(Regex("\\s+"))
        if (parts.size < 6) return
        val range = parts[0].split('-')
        if (range.size != 2) return
        val start = range[0].toLongOrNull(16) ?: return
        val fileOff = parts[2].toLongOrNull(16) ?: 0L
        val path = parts.last()
        if (!path.startsWith("/")) return
        val mem = RootShell.execAndRead(
            "dd if=/proc/$pid/mem bs=1 skip=$start count=64 2>/dev/null | xxd -p -c 64",
            timeoutSec = 6
        ).trim()
        val disk = RootShell.execAndRead(
            "dd if=$path bs=1 skip=$fileOff count=64 2>/dev/null | xxd -p -c 64",
            timeoutSec = 6
        ).trim()
        if (mem.isBlank() || disk.isBlank()) return
        val mismatch = mem.take(128) != disk.take(128)
        if (!mismatch) return
        emit(
            "root.text",
            "libc .text диск≠RAM (inline hook?)",
            path,
            "mem=${mem.take(40)} disk=${disk.take(40)}",
            "$line\nmem=$mem\ndisk=$disk"
        )
    }

    private suspend fun emit(id: String, action: String, request: String, response: String, raw: String) {
        val key = "$id|$action"
        val now = System.currentTimeMillis()
        val prev = seen.put(key, now)
        if (prev != null && now - prev < 20_000) return
        if (repository.isDuplicate(packageName, action, raw.take(200), sinceMs = 15_000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.SECURITY,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = request,
                responseDetails = response.take(500),
                rawData = raw.take(1500),
                processId = pid.takeIf { it > 0 },
                identifierName = id,
                identifierGroup = "ROOT"
            )
        )
    }
}
