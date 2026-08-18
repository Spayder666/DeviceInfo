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
 * Канал `cmd` (shell API AOSP) — не dumpsys.
 * Location/Wi‑Fi/BT/phone/connectivity отдают текущее состояние системы,
 * даже если приложение ходит через GMS, а не через свой PID.
 */
class CmdApiMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            var index = 0
            while (isActive) {
                val batch = COMMANDS.subList(index, (index + 3).coerceAtMost(COMMANDS.size))
                for (cmd in batch) {
                    poll(cmd)
                }
                index = if (index + 3 >= COMMANDS.size) 0 else index + 3
                delay(1500)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun poll(cmd: CmdTarget) {
        val raw = RootShell.execAndRead(cmd.command, timeoutSec = 8).trim()
        if (raw.isBlank()) return
        if (isUselessDump(raw)) return

        val mentions = raw.contains(packageName) ||
            (uid > 0 && (raw.contains("uid=$uid") || raw.contains("u0a${uid % 100000}")))
        if (cmd.requirePackage && !mentions) return

        val snippet = raw.lineSequence()
            .filter { it.isNotBlank() }
            .take(8)
            .joinToString("\n")
            .take(600)
        if (snippet.isBlank()) return

        val digest = "${cmd.action}:${snippet.hashCode()}"
        val previous = seen.keys.firstOrNull { it.startsWith("${cmd.action}:") }
        if (previous == digest) return
        seen.keys.filter { it.startsWith("${cmd.action}:") }.forEach { seen.remove(it) }
        seen[digest] = snippet
        if (previous == null && cmd.skipBaseline && !mentions) return
        if (repository.isDuplicate(packageName, cmd.action, snippet, sinceMs = 8000)) return

        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = cmd.category,
                source = EventSource.DUMPSYS,
                action = cmd.action,
                requestDetails = cmd.command,
                responseDetails = snippet.take(400),
                rawData = snippet,
                identifierName = cmd.identifierId,
                identifierGroup = cmd.identifierGroup
            )
        )
    }

    private data class CmdTarget(
        val command: String,
        val action: String,
        val category: AccessCategory,
        val identifierId: String? = null,
        val identifierGroup: String? = null,
        val requirePackage: Boolean = false,
        val skipBaseline: Boolean = true
    )

    private val COMMANDS = listOf(
        CmdTarget(
            "cmd location is-location-enabled 2>/dev/null",
            "cmd location enabled",
            AccessCategory.LOCATION,
            "location.gps",
            "LOCATION",
            requirePackage = true
        ),
        CmdTarget(
            "cmd location get-last-location 2>/dev/null",
            "cmd location last",
            AccessCategory.LOCATION,
            "location.gps",
            "LOCATION",
            requirePackage = true
        ),
        CmdTarget(
            "cmd location providers 2>/dev/null || cmd location list-providers 2>/dev/null",
            "cmd location providers",
            AccessCategory.LOCATION,
            "location.gps",
            "LOCATION",
            requirePackage = true
        ),
        CmdTarget(
            "cmd wifi status 2>/dev/null",
            "cmd wifi status",
            AccessCategory.NETWORK,
            "wifi.ssid",
            "WIFI",
            requirePackage = true
        ),
        CmdTarget(
            "cmd wifi get-ipaddress 2>/dev/null",
            "cmd wifi IP",
            AccessCategory.NETWORK,
            "net.link_addresses",
            "NETWORK",
            requirePackage = true
        ),
        CmdTarget(
            "cmd bluetooth_manager get-address 2>/dev/null",
            "cmd bluetooth address",
            AccessCategory.BLUETOOTH,
            "bt.local_mac",
            "BLUETOOTH",
            requirePackage = true
        ),
        CmdTarget(
            "cmd bluetooth_manager get-name 2>/dev/null",
            "cmd bluetooth name",
            AccessCategory.BLUETOOTH,
            "bt.local_name",
            "BLUETOOTH",
            requirePackage = true
        ),
        CmdTarget(
            "cmd connectivity get-active-network 2>/dev/null",
            "cmd connectivity",
            AccessCategory.NETWORK,
            "net.link_addresses",
            "NETWORK",
            requirePackage = true
        ),
        CmdTarget(
            "cmd phone has-icc-card 2>/dev/null",
            "cmd phone SIM",
            AccessCategory.TELEPHONY,
            "tel.imei",
            "TELEPHONY",
            requirePackage = true
        ),
        CmdTarget(
            "cmd appops get $packageName 2>/dev/null | head -n 40",
            "cmd appops",
            AccessCategory.PERMISSION,
            requirePackage = true
        ),
        CmdTarget(
            "cmd activity get-uid-state $packageName 2>/dev/null",
            "cmd uid-state",
            AccessCategory.SYSTEM_API
        ),
        CmdTarget(
            "cmd jobscheduler get-job-state $packageName 2>/dev/null | head -n 20",
            "cmd jobs",
            AccessCategory.SYSTEM_API
        ),
        CmdTarget(
            "cmd device_policy list-owners 2>/dev/null | head -n 20",
            "cmd device_policy",
            AccessCategory.IDENTIFIER,
            "ent.esid",
            "ENTERPRISE",
            requirePackage = true
        )
    )
}
