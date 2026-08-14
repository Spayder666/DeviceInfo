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
 * Метаданные пакетов (заголовки, snaplen 96) + DNS QNAME.
 * HTTPS не расшифровывается — только IP/порт/DNS-имя и pcap на диске.
 */
class TcpdumpMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var streamJob: Job? = null
    private var pollJob: Job? = null
    private val seen = ConcurrentHashMap<String, String>()
    private val appRemotes = ConcurrentHashMap.newKeySet<String>()

    fun start() {
        RootShell.execAndRead("mkdir -p ${MonitorPaths.BASE}")
        val bin = RootShell.resolveBinary("tcpdump")
        if (bin != null) {
            startPcapWriter(bin)
            streamJob = scope.launch(Dispatchers.IO) {
                try {
                    RootShell.execStreaming(
                        "$bin -nn -l -i any -s 200 " +
                            "port 53 or port 7275 or port 7276 or port 1883 or " +
                            "port 8883 or port 5228 or port 5229 or port 5683 2>/dev/null"
                    ) { line ->
                        if (isActive) scope.launch { parsePacket(line) }
                    }
                } catch (_: Exception) {
                }
            }
        }
        pollJob = scope.launch(Dispatchers.IO) {
            if (bin == null) {
                record(
                    AccessCategory.NETWORK,
                    "tcpdump не найден",
                    "fallback nf_conntrack / xt_qtaguid",
                    "pcap недоступен, читаем conntrack",
                    "no-tcpdump"
                )
            } else {
                record(
                    AccessCategory.NETWORK,
                    "pcap заголовки",
                    MonitorPaths.PCAP,
                    "snaplen=96, без тела HTTPS",
                    "pcap-init"
                )
            }
            while (isActive) {
                refreshAppRemotes()
                pollConntrack()
                delay(2500)
            }
        }
    }

    fun stop() {
        streamJob?.cancel()
        pollJob?.cancel()
        streamJob = null
        pollJob = null
        val pid = RootShell.execAndRead("cat ${MonitorPaths.TCPDUMP_PID} 2>/dev/null").trim()
        if (pid.toIntOrNull() != null) {
            RootShell.execAndRead("kill $pid 2>/dev/null")
        }
        RootShell.execAndRead("pkill -f ${RootShell.shellQuote(MonitorPaths.PCAP)} 2>/dev/null")
    }

    private fun startPcapWriter(bin: String) {
        RootShell.execAndRead("rm -f ${MonitorPaths.TCPDUMP_PID}")
        RootShell.execAndRead(
            "setsid $bin -nn -i any -s 96 -C 1 -W 3 -w ${MonitorPaths.PCAP} " +
                "</dev/null >/dev/null 2>&1 & echo \$! > ${MonitorPaths.TCPDUMP_PID}",
            timeoutSec = 5
        )
    }

    private fun refreshAppRemotes() {
        val pids = RootShell.findAllPids(packageName)
        val cmd = buildString {
            if (pids.isNotEmpty()) {
                append("cat ")
                pids.take(6).forEach { append("/proc/$it/net/tcp /proc/$it/net/tcp6 ") }
                append("2>/dev/null")
            } else {
                append("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
            }
        }
        val dump = RootShell.execAndRead(cmd, timeoutSec = 6)
        for (line in dump.lines()) {
            if (line.startsWith("sl") || line.isBlank()) continue
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size < 8) continue
            val lineUid = parts.getOrNull(7)?.toIntOrNull()
            if (uid > 0 && lineUid != null && lineUid != uid && pids.isEmpty()) continue
            decodeRemote(parts[2])?.let { appRemotes.add(it) }
        }
        while (appRemotes.size > 80) {
            appRemotes.firstOrNull()?.let { appRemotes.remove(it) }
        }
    }

    private suspend fun parsePacket(line: String) {
        if (line.isBlank() || line.startsWith("tcpdump")) return
        val dns = DNS_NAME.find(line)
        val dest = DEST.find(line)?.value
        val locPort = LOC_PORTS.any { it in line }
        val dnsPort = ".53:" in line || ".53 " in line
        val matchesApp = dest != null && appRemotes.any {
            dest.startsWith(it) || it.startsWith(dest.substringBeforeLast('.'))
        }
        if (dns == null && !dnsPort && !locPort && !matchesApp) return

        val host = dns?.groupValues?.get(1) ?: dest ?: line
        val category = when {
            LOCATION_HOST.containsMatchIn(line) || listOf("7275", "7276", "supl").any { it in line } ->
                AccessCategory.LOCATION
            else -> AccessCategory.NETWORK
        }
        val key = "${dns?.value ?: dest}:${line.takeLast(24)}"
        record(
            category,
            if (dns != null) "DNS" else "пакет",
            host,
            line.trim().take(300),
            key,
            if (category == AccessCategory.LOCATION) "location.supl" else "net.http"
        )
    }

    private suspend fun pollConntrack() {
        val dump = RootShell.execAndRead(
            "cat /proc/net/nf_conntrack /proc/net/ip_conntrack 2>/dev/null | head -c 40000",
            timeoutSec = 6
        )
        if (dump.isBlank()) return
        val uidToken = if (uid > 0) "uid=$uid" else packageName
        for (line in dump.lines()) {
            if (uid > 0 && "uid=$uid" !in line && uidToken !in line) continue
            if (line.isBlank()) continue
            val dst = Regex("dst=(\\S+)").findAll(line).map { it.groupValues[1] }.toList().getOrNull(1)
            val dport = Regex("dport=(\\d+)").findAll(line).map { it.groupValues[1] }.toList().getOrNull(1)
            val proto = Regex("^(ipv\\d+)\\s+(\\S+)").find(line)?.groupValues?.get(2) ?: ""
            record(
                if (dport in setOf("7275", "7276", "1883", "8883")) AccessCategory.LOCATION else AccessCategory.NETWORK,
                "conntrack",
                "$proto $dst:$dport uid=$uid",
                line.trim().take(300),
                "ct:$dst:$dport:$proto"
            )
        }
    }

    private suspend fun record(
        category: AccessCategory,
        action: String,
        request: String?,
        response: String?,
        key: String,
        identifierId: String? = null
    ) {
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, key, sinceMs = 4000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.TCPDUMP,
                action = action,
                requestDetails = request,
                responseDetails = response,
                rawData = response?.take(800),
                identifierName = identifierId,
                identifierGroup = if (identifierId?.startsWith("location") == true) "LOCATION" else "NETWORK"
            )
        )
    }

    private fun decodeRemote(hex: String): String? {
        val parts = hex.split(":")
        if (parts.size != 2) return null
        val ipHex = parts[0]
        if (ipHex.length != 8) return hex.lowercase()
        val b = ipHex.chunked(2).map { it.toInt(16) }
        return "${b[3]}.${b[2]}.${b[1]}.${b[0]}"
    }

    companion object {
        private val DNS_NAME = Regex("""\?\s+([A-Za-z0-9._-]+\.[A-Za-z]{2,})\.?""")
        private val DEST = Regex("""\d+\.\d+\.\d+\.\d+\.\d+""")
        private val LOC_PORTS = listOf(".7275", ".7276", ".1883", ".8883", ".5683", ".5228", ".5229")
        private val LOCATION_HOST = Regex(
            "(?i)supl|googleapis.com/.*location|gpsonextra|nlp|izat|lbs\\.|maps\\.|" +
                "location.googleapis|geolocation"
        )
    }
}
