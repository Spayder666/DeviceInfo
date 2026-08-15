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
 * SIM / оператор без привилегированных AppOps: getSimState, getNetworkOperator и т.п.
 * не пишут READ_PHONE_STATE. Пишем только свежий AppOps и logcat с именем API.
 */
class TelephonyAccessMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var pollJob: Job? = null
    private var logJob: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        pollJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollDumps()
                delay(2000)
            }
        }
        logJob = scope.launch(Dispatchers.IO) {
            val uidFilter = if (uid > 0) "--uid=$uid" else ""
            val cmd = "logcat -v threadtime $uidFilter -T 1 " +
                "TelephonyManager:V PhoneInterfaceManager:V TelephonyPermissions:V " +
                "SubscriptionManager:V SubscriptionController:V ISub:V IPhoneSubInfo:V " +
                "IccProvider:V GsmCdmaPhone:V *:S 2>&1"
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
        pollJob = null
        logJob = null
    }

    fun resetForNewProcess() {
        seen.clear()
    }

    private suspend fun pollDumps() {
        if (!TargetPresence.isAliveNow()) return
        val appops = RootShell.execAndRead(
            "cmd appops get $packageName 2>/dev/null | grep -i -E 'PHONE|SMS|CALL|ICC'",
            timeoutSec = 6
        )
        emitRecentPhoneOps(appops)
    }

    private suspend fun parseLog(line: String) {
        if (line.isBlank() || line.startsWith("-----")) return
        val id = when {
            Regex("(?i)getSimState|SIM_STATE").containsMatchIn(line) -> "tel.sim_state"
            Regex("(?i)getSimOperatorName|carrier.?name").containsMatchIn(line) -> "tel.sim_operator_name"
            Regex("(?i)getSimOperator|gsm.sim.operator").containsMatchIn(line) -> "tel.sim_operator"
            Regex("(?i)getNetworkOperatorName").containsMatchIn(line) -> "tel.network_operator_name"
            Regex("(?i)getNetworkOperator|MCCMNC").containsMatchIn(line) -> "tel.network_operator"
            Regex("(?i)getNetworkCountryIso|getSimCountryIso").containsMatchIn(line) -> "tel.network_country"
            Regex("(?i)getSubscriberId|IMSI").containsMatchIn(line) -> "tel.subscriber_id"
            Regex("(?i)getSimSerial|ICCID|icc_id").containsMatchIn(line) -> "tel.sim_serial"
            Regex("(?i)getImei|getDeviceId").containsMatchIn(line) -> "tel.imei"
            Regex("(?i)getLine1Number|MSISDN").containsMatchIn(line) -> "tel.line1_number"
            Regex("(?i)getPhoneType").containsMatchIn(line) -> "tel.phone_type"
            Regex("(?i)getActiveSubscription|getDefaultSubscription|SubscriptionInfo").containsMatchIn(line) ->
                "sub.subscription_id"
            else -> return
        }
        emit(
            action = line.substringAfterLast("/").substringBefore(":").ifBlank { "TelephonyManager" },
            request = "logcat telephony uid=$uid",
            response = line.substringAfter(": ").take(280),
            raw = line,
            identifierId = id,
            source = EventSource.LOGCAT
        )
    }

    private suspend fun emitRecentPhoneOps(dump: String) {
        if (dump.isBlank() || isUselessDump(dump)) return
        for (line in dump.lineSequence()) {
            if (line.isBlank() || !isRecentAccessStamp(line)) continue
            val op = Regex("""([A-Z_]+)""").find(line)?.groupValues?.get(1) ?: continue
            val id = when {
                op.contains("DEVICE_IDENTIFIER") || op.contains("IMEI") -> "tel.imei"
                op.contains("PHONE_NUMBER") -> "tel.line1_number"
                op.contains("ICC") -> "tel.sim_serial"
                else -> "tel.phone_interface"
            }
            emit(
                action = op,
                request = "AppOps $op",
                response = line.trim().take(200),
                raw = line.trim(),
                identifierId = id,
                source = EventSource.DUMPSYS
            )
        }
    }

    private suspend fun emit(
        action: String,
        request: String,
        response: String,
        raw: String,
        identifierId: String,
        source: EventSource = EventSource.DUMPSYS
    ) {
        val key = "$action:${raw.hashCode()}"
        if (seen.containsKey(key)) return
        if (repository.isDuplicate(packageName, action, raw, sinceMs = 4000)) {
            seen[key] = "1"
            return
        }
        val id = repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.TELEPHONY,
                source = source,
                action = action,
                permission = "READ_PHONE_STATE",
                requestDetails = request,
                responseDetails = response,
                rawData = raw.take(1200),
                identifierName = identifierId,
                identifierGroup = "TELEPHONY"
            )
        )
        if (id > 0) seen[key] = "1"
    }
}
