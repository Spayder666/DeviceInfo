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

/** VPN / proxy / user CA / SSL pin fail — dumpsys + logcat. */
class NetworkEnvMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var pollJob: Job? = null
    private var logJob: Job? = null
    private val seen = ConcurrentHashMap<String, Long>()

    fun start() {
        pollJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollVpn()
                pollProxy()
                pollUserCa()
                delay(10_000)
            }
        }
        logJob = scope.launch(Dispatchers.IO) {
            val uidFilter = if (uid > 0) "--uid=$uid" else ""
            val cmd = "logcat -v threadtime $uidFilter -T 1 " +
                "OkHttp:V CertificatePinner:V Conscrypt:V NativeCrypto:V " +
                "X509Util:V WebView:V chromium:V SSL:V *:S 2>&1"
            try {
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) scope.launch { parseLog(line) }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun stop() {
        pollJob?.cancel()
        logJob?.cancel()
    }

    private suspend fun pollVpn() {
        val dump = RootShell.execAndRead(
            "dumpsys connectivity 2>/dev/null | grep -i -E 'TRANSPORT_VPN|type: VPN|VPN connected|NetworkAgentInfo.*VPN|always-on VPN' | head -n 16",
            timeoutSec = 8
        )
        val links = RootShell.execAndRead(
            "ip -o link show 2>/dev/null | grep -E ' tun| tap| ppp| wg' | head -n 8",
            timeoutSec = 5
        )
        if (dump.isBlank() && links.isBlank()) return
        if (!Regex("(?i)CONNECTED|TRANSPORT_VPN| tun| tap| ppp| wg").containsMatchIn(dump + links)) return
        emit("net.vpn", "VPN / TRANSPORT_VPN", "dumpsys + ip link", (dump + "\n" + links).take(400), dump + "\n" + links)
    }

    private suspend fun pollProxy() {
        val proxy = RootShell.execAndRead(
            "settings get global http_proxy; settings get global global_http_proxy_host; " +
                "settings get global global_http_proxy_port",
            timeoutSec = 6
        ).trim()
        if (proxy.isBlank() || proxy.lines().all { it == "null" || it.isBlank() }) return
        emit("net.proxy", "HTTP proxy", "settings global", proxy, proxy)
    }

    private suspend fun pollUserCa() {
        val cas = RootShell.execAndRead(
            "ls /data/misc/user/0/cacerts-added /data/misc/keychain/cacerts-added 2>/dev/null | wc -l; " +
                "ls /data/misc/user/0/cacerts-added /data/misc/keychain/cacerts-added 2>/dev/null | head -n 8",
            timeoutSec = 6
        )
        val count = cas.lineSequence().firstOrNull()?.trim()?.toIntOrNull() ?: 0
        if (count <= 0) return
        emit("net.user_ca", "User CA ($count)", "/data/misc/user/0/cacerts-added", cas.take(300), cas)
    }

    private suspend fun parseLog(line: String) {
        if (line.isBlank()) return
        val pin = Regex("(?i)CertificatePinner|SSLPeerUnverified|Trust anchor|CertPathValidator|pinning|CLEARTEXT|ERR_CERT").containsMatchIn(line)
        val vpn = Regex("(?i)TRANSPORT_VPN|VpnService|tun0").containsMatchIn(line)
        if (!pin && !vpn) return
        val id = if (pin) "net.pin_fail" else "net.vpn"
        emit(id, if (pin) "SSL / pinning fail" else "VPN log", "logcat", line.substringAfter(": ").take(280), line)
    }

    private suspend fun emit(id: String, action: String, request: String, response: String, raw: String) {
        val key = "$id|$action|${raw.hashCode()}"
        val now = System.currentTimeMillis()
        val prev = seen.put(key, now)
        if (prev != null && now - prev < 8000) return
        if (repository.isDuplicate(packageName, action, raw, sinceMs = 6000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = if (id == "net.pin_fail") AccessCategory.SECURITY else AccessCategory.NETWORK,
                source = EventSource.LOGCAT,
                action = action,
                requestDetails = request,
                responseDetails = response.take(400),
                rawData = raw.take(1200),
                identifierName = id,
                identifierGroup = "NETWORK"
            )
        )
    }
}
