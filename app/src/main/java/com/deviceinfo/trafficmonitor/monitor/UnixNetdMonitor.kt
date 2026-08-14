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

/** Unix-сокеты приложения, DnsResolver/netd и ip6tables/nft UID. */
class UnixNetdMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()
    private var ip6Ready = false

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            setupIp6()
            while (isActive) {
                pollUnix()
                pollDns()
                pollIp6Nft()
                delay(3000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        if (ip6Ready && uid > 0) {
            RootShell.execAndRead(
                "ip6tables -D OUTPUT -m owner --uid-owner $uid -j LOG --log-prefix 'AM6NET ' 2>/dev/null"
            )
        }
    }

    private fun setupIp6() {
        if (uid <= 0) return
        val add = RootShell.execAndRead(
            "ip6tables -C OUTPUT -m owner --uid-owner $uid -j LOG --log-prefix 'AM6NET ' 2>/dev/null || " +
                "ip6tables -I OUTPUT -m owner --uid-owner $uid -j LOG --log-prefix 'AM6NET ' && echo ok"
        )
        ip6Ready = add.contains("ok") || add.isBlank()
    }

    private suspend fun pollUnix() {
        val pids = RootShell.findAllPids(packageName).take(5)
        if (pids.isEmpty()) return
        val dump = RootShell.execAndRead(
            pids.joinToString("; ") { "cat /proc/$it/net/unix 2>/dev/null" } +
                " | awk 'NR==1 || /socket|@/' | head -n 40",
            timeoutSec = 8
        )
        val interesting = dump.lineSequence().filter { line ->
            UNIX_HINT.any { it in line.lowercase() } || line.contains("@")
        }.take(15).joinToString("\n")
        emit(AccessCategory.NETWORK, "unix socket", interesting, "net.hostname")
    }

    private suspend fun pollDns() {
        val dump = RootShell.execAndRead(
            "dumpsys dnsresolver 2>/dev/null | grep -A3 -E '$packageName|uid=$uid' | head -n 30; " +
                "dumpsys netd 2>/dev/null | grep -A2 -E '$packageName|uid=$uid' | head -n 20",
            timeoutSec = 10
        )
        emit(AccessCategory.NETWORK, "DnsResolver / netd", dump, "net.dns")
    }

    private suspend fun pollIp6Nft() {
        if (ip6Ready) {
            val log = RootShell.execAndRead("dmesg -T 2>/dev/null | grep AM6NET | tail -n 15", timeoutSec = 6)
            emit(AccessCategory.NETWORK, "ip6tables UID LOG", log, "net.inet6")
        }
        val nft = RootShell.execAndRead(
            "nft list ruleset 2>/dev/null | grep -A2 -E 'skuid $uid|uid $uid' | head -n 20",
            timeoutSec = 8
        )
        emit(AccessCategory.NETWORK, "nftables UID", nft, "net.link_addresses")
    }

    private suspend fun emit(category: AccessCategory, action: String, dump: String, id: String) {
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
                source = EventSource.PROC,
                action = action,
                requestDetails = action,
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = id,
                identifierGroup = "NETWORK"
            )
        )
    }

    companion object {
        private val UNIX_HINT = listOf("dns", "netd", "gps", "gnss", "location", "ril", "qmux", "izat")
    }
}
