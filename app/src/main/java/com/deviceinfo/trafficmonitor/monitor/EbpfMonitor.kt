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
 * eBPF / cgroup / qtaguid: карты netd и счётчики UID.
 * Свой .o не грузим — читаем уже загруженные Android BPF maps и xt_qtaguid.
 */
class EbpfMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            discoverOnce()
            while (isActive) {
                pollQtaguid()
                pollBpftool()
                pollCgroup()
                delay(4000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun discoverOnce() {
        val maps = RootShell.execAndRead(
            "ls /sys/fs/bpf 2>/dev/null; find /sys/fs/bpf -maxdepth 3 -type f 2>/dev/null | head -n 40",
            timeoutSec = 8
        )
        val kernel = RootShell.execAndRead("uname -r; ls /sys/fs/bpf/netd* 2>/dev/null | head", timeoutSec = 5)
        val bpftool = RootShell.resolveBinary("bpftool")
        val text = buildString {
            append(kernel.trim())
            append('\n')
            append(if (bpftool != null) "bpftool=$bpftool" else "bpftool отсутствует")
            append('\n')
            append(maps.take(500))
        }
        emit(
            AccessCategory.NETWORK,
            "eBPF maps",
            "/sys/fs/bpf",
            text,
            "discover"
        )
    }

    private suspend fun pollQtaguid() {
        val stats = RootShell.execAndRead(
            "cat /proc/net/xt_qtaguid/stats 2>/dev/null | awk 'NR==1 || \$4==$uid || \$3==$uid' | head -n 20",
            timeoutSec = 6
        )
        val uidStat = if (uid > 0) {
            RootShell.execAndRead(
                "cat /proc/uid_stat/$uid/tcp_snd /proc/uid_stat/$uid/tcp_rcv 2>/dev/null",
                timeoutSec = 4
            )
        } else ""
        val netstats = RootShell.execAndRead(
            "dumpsys netstats detail 2>/dev/null | grep -A8 -E 'uid=$uid|ident=\\[.*$packageName' | head -n 24",
            timeoutSec = 10
        )
        val combined = listOf(stats, uidStat, netstats).filter { it.isNotBlank() }.joinToString("\n")
        if (combined.isBlank()) return
        emit(AccessCategory.NETWORK, "qtaguid / netstats", "uid=$uid", combined.take(500), "qtag:${combined.hashCode()}")
    }

    private suspend fun pollBpftool() {
        val bpftool = RootShell.resolveBinary("bpftool") ?: return
        val progs = RootShell.execAndRead("$bpftool prog show 2>/dev/null | head -n 30", timeoutSec = 8)
        val maps = RootShell.execAndRead(
            "$bpftool map show 2>/dev/null | grep -E -i 'uid|cookie|stats|netd|sock' | head -n 20",
            timeoutSec = 8
        )
        val dump = RootShell.execAndRead(
            "$bpftool map list 2>/dev/null | head -n 20",
            timeoutSec = 6
        )
        val text = listOf(progs, maps, dump).filter { it.isNotBlank() }.joinToString("\n")
        if (text.isBlank()) return
        emit(AccessCategory.NETWORK, "bpftool", bpftool, text.take(500), "bpftool:${text.hashCode()}")
    }

    private suspend fun pollCgroup() {
        val pids = RootShell.findAllPids(packageName).take(4)
        if (pids.isEmpty()) return
        val text = buildString {
            for (pid in pids) {
                val cg = RootShell.execAndRead("cat /proc/$pid/cgroup 2>/dev/null", timeoutSec = 4)
                val sock = RootShell.execAndRead(
                    "ls -l /proc/$pid/fd 2>/dev/null | grep socket | wc -l",
                    timeoutSec = 4
                ).trim()
                if (cg.isNotBlank()) {
                    append("pid=$pid sockets=$sock\n")
                    append(cg.lines().take(6).joinToString("\n"))
                    append('\n')
                }
            }
        }
        if (text.isBlank()) return
        emit(AccessCategory.SYSTEM_API, "cgroup / sock", "pid cgroup", text.take(400), "cg:${text.hashCode()}")
    }

    private suspend fun emit(
        category: AccessCategory,
        action: String,
        request: String,
        response: String,
        key: String
    ) {
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, response, sinceMs = 12000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.EBPF,
                action = action,
                requestDetails = request,
                responseDetails = response.take(400),
                rawData = response.take(1500),
                identifierName = "net.link_addresses",
                identifierGroup = "NETWORK"
            )
        )
    }
}
