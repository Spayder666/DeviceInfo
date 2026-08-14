package com.deviceinfo.trafficmonitor.mitm

import android.content.Context
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

object HttpsMitmController {
    @Volatile
    var active: Boolean = false
        private set

    @Volatile
    var lastError: String? = null

    private var proxy: HttpsMitmProxy? = null
    private var targetUid: Int = -1
    private val seen = ConcurrentHashMap<String, Long>()

    suspend fun start(
        context: Context,
        packageName: String,
        uid: Int,
        repository: CaptureRepository
    ): Boolean = withContext(Dispatchers.IO) {
        if (active) return@withContext true
        lastError = null
        if (!MitmCaManager.ensureCa(context)) {
            lastError = "Не удалось создать CA: ${MitmCaManager.lastError ?: "unknown"}"
            return@withContext false
        }
        MitmCaManager.installAsSystemCa()
        targetUid = uid
        val p = HttpsMitmProxy { host, direction, text ->
            record(packageName, repository, host, direction, text)
        }
        try {
            p.start()
        } catch (e: Exception) {
            lastError = e.message
            return@withContext false
        }
        proxy = p
        setupIptables(uid)
        FridaInstaller.mitmEnabled = true
        FridaInstaller.prepareHooksForPackage(packageName, context)
        val injected = FridaInstaller.injectManual(context, packageName, restartApp = false)
        if (!injected) {
            FridaInstaller.injectManual(context, packageName, restartApp = true)
        }
        active = true
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.NETWORK,
                source = EventSource.MITM,
                action = "MITM HTTPS включён",
                requestDetails = "CA + iptables REDIRECT :443/:80 → ${MitmCaManager.PORT} + Frida SSL",
                responseDetails = "plaintext OkHttp/SSL_read; pinning снимается только в этом процессе",
                rawData = "ca=${FridaInstaller.BASE_DIR}/mitm-ca.pem",
                identifierName = "net.https",
                identifierGroup = "NETWORK"
            )
        )
        true
    }

    fun stop() {
        if (!active && proxy == null) return
        proxy?.stop()
        proxy = null
        teardownIptables(targetUid)
        MitmCaManager.uninstallBind()
        FridaInstaller.mitmEnabled = false
        active = false
    }

    private fun setupIptables(uid: Int) {
        if (uid <= 0) return
        val port = MitmCaManager.PORT
        listOf(
            "iptables -t nat -C OUTPUT -p tcp -m owner --uid-owner $uid --dport 443 -j REDIRECT --to-ports $port 2>/dev/null || " +
                "iptables -t nat -I OUTPUT -p tcp -m owner --uid-owner $uid --dport 443 -j REDIRECT --to-ports $port",
            "iptables -t nat -C OUTPUT -p tcp -m owner --uid-owner $uid --dport 80 -j REDIRECT --to-ports $port 2>/dev/null || " +
                "iptables -t nat -I OUTPUT -p tcp -m owner --uid-owner $uid --dport 80 -j REDIRECT --to-ports $port",
            "ip6tables -t nat -C OUTPUT -p tcp -m owner --uid-owner $uid --dport 443 -j REDIRECT --to-ports $port 2>/dev/null || " +
                "ip6tables -t nat -I OUTPUT -p tcp -m owner --uid-owner $uid --dport 443 -j REDIRECT --to-ports $port"
        ).forEach { RootShell.execAndRead(it) }
    }

    private fun teardownIptables(uid: Int) {
        if (uid <= 0) return
        val port = MitmCaManager.PORT
        listOf(
            "iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner $uid --dport 443 -j REDIRECT --to-ports $port",
            "iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner $uid --dport 80 -j REDIRECT --to-ports $port",
            "ip6tables -t nat -D OUTPUT -p tcp -m owner --uid-owner $uid --dport 443 -j REDIRECT --to-ports $port"
        ).forEach { RootShell.execAndRead("$it 2>/dev/null") }
    }

    private fun record(
        packageName: String,
        repository: CaptureRepository,
        host: String,
        direction: String,
        text: String
    ) {
        val key = "$host:$direction:${text.hashCode()}"
        val now = System.currentTimeMillis()
        val prev = seen.put(key, now)
        if (prev != null && now - prev < 1500) return
        val first = text.lineSequence().firstOrNull { it.isNotBlank() }?.take(180) ?: host
        kotlinx.coroutines.runBlocking {
            repository.insert(
                CaptureEvent(
                    targetPackage = packageName,
                    category = AccessCategory.NETWORK,
                    source = EventSource.MITM,
                    action = "HTTPS $direction",
                    requestDetails = host,
                    responseDetails = first,
                    rawData = text.take(1500),
                    identifierName = "net.https",
                    identifierGroup = "NETWORK"
                )
            )
        }
    }
}
