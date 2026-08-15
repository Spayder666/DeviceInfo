package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.toAccessCategory
import com.deviceinfo.trafficmonitor.probe.IdentifierReader
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class AppOpsMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val lastState = ConcurrentHashMap<String, String>()
    private var seeded = false

    private val opCategoryMap = mapOf(
        "COARSE_LOCATION" to AccessCategory.LOCATION,
        "FINE_LOCATION" to AccessCategory.LOCATION,
        "GPS" to AccessCategory.LOCATION,
        "MONITOR_LOCATION" to AccessCategory.LOCATION,
        "MONITOR_HIGH_POWER_LOCATION" to AccessCategory.LOCATION,
        "NEARBY_WIFI_DEVICES" to AccessCategory.LOCATION,
        "CAMERA" to AccessCategory.CAMERA,
        "RECORD_AUDIO" to AccessCategory.MICROPHONE,
        "READ_PHONE_STATE" to AccessCategory.TELEPHONY,
        "READ_PHONE_NUMBERS" to AccessCategory.TELEPHONY,
        "CALL_PHONE" to AccessCategory.TELEPHONY,
        "READ_CALL_LOG" to AccessCategory.TELEPHONY,
        "WRITE_CALL_LOG" to AccessCategory.TELEPHONY,
        "READ_CONTACTS" to AccessCategory.CONTACTS,
        "WRITE_CONTACTS" to AccessCategory.CONTACTS,
        "GET_ACCOUNTS" to AccessCategory.IDENTIFIER,
        "READ_SMS" to AccessCategory.SMS,
        "RECEIVE_SMS" to AccessCategory.SMS,
        "SEND_SMS" to AccessCategory.SMS,
        "READ_CALENDAR" to AccessCategory.CALENDAR,
        "WRITE_CALENDAR" to AccessCategory.CALENDAR,
        "READ_EXTERNAL_STORAGE" to AccessCategory.STORAGE,
        "WRITE_EXTERNAL_STORAGE" to AccessCategory.STORAGE,
        "MANAGE_EXTERNAL_STORAGE" to AccessCategory.STORAGE,
        "READ_CLIPBOARD" to AccessCategory.CLIPBOARD,
        "WRITE_CLIPBOARD" to AccessCategory.CLIPBOARD,
        "BLUETOOTH_SCAN" to AccessCategory.BLUETOOTH,
        "BLUETOOTH_CONNECT" to AccessCategory.BLUETOOTH,
        "ACTIVITY_RECOGNITION" to AccessCategory.SENSOR,
        "BODY_SENSORS" to AccessCategory.SENSOR,
        "WIFI_SCAN" to AccessCategory.NETWORK,
        "INTERNET" to AccessCategory.NETWORK,
        "READ_DEVICE_IDENTIFIERS" to AccessCategory.IDENTIFIER,
        "READ_MEDIA_IMAGES" to AccessCategory.STORAGE,
        "READ_MEDIA_VIDEO" to AccessCategory.STORAGE,
        "READ_MEDIA_AUDIO" to AccessCategory.STORAGE,
        "READ_MEDIA_VISUAL_USER_SELECTED" to AccessCategory.STORAGE,
        "ACCESS_MEDIA_LOCATION" to AccessCategory.LOCATION,
        "PHONE_CALL_CAMERA" to AccessCategory.CAMERA,
        "PHONE_CALL_MICROPHONE" to AccessCategory.MICROPHONE,
        "RECORD_AUDIO_HOTWORD" to AccessCategory.MICROPHONE,
        "PROJECT_MEDIA" to AccessCategory.SYSTEM_API,
        "SYSTEM_ALERT_WINDOW" to AccessCategory.SYSTEM_API,
        "START_FOREGROUND" to AccessCategory.SYSTEM_API,
        "WAKE_LOCK" to AccessCategory.SYSTEM_API,
        "VIBRATE" to AccessCategory.SENSOR,
        "BLUETOOTH_ADVERTISE" to AccessCategory.BLUETOOTH,
        "USE_BIOMETRIC" to AccessCategory.SYSTEM_API,
        "GET_USAGE_STATS" to AccessCategory.SYSTEM_API,
        "POST_NOTIFICATION" to AccessCategory.SYSTEM_API,
        "ACTIVATE_VPN" to AccessCategory.NETWORK,
        "CHANGE_WIFI_STATE" to AccessCategory.NETWORK,
        "RECEIVE_MMS" to AccessCategory.SMS,
        "PROCESS_OUTGOING_CALLS" to AccessCategory.TELEPHONY,
        "ANSWER_PHONE_CALLS" to AccessCategory.TELEPHONY,
        "MOCK_LOCATION" to AccessCategory.LOCATION
    )

    private val opIdentifierMap = mapOf(
        "READ_DEVICE_IDENTIFIERS" to "build.serial",
        "READ_PHONE_STATE" to "tel.imei",
        "READ_PHONE_NUMBERS" to "tel.line1_number",
        "GET_ACCOUNTS" to "account.list",
        "WIFI_SCAN" to "wifi.scan_results",
        "BLUETOOTH_CONNECT" to "bt.local_mac",
        "BLUETOOTH_SCAN" to "bt.local_mac"
    )

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollAppOps()
                delay(1500)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollAppOps() {
        val output = RootShell.execAndRead("dumpsys appops $packageName", timeoutSec = 15)
        parseAppOps(output)
    }

    private suspend fun parseAppOps(output: String) {
        val lines = output.lines()
        var currentOp: String? = null
        val emit = seeded

        for (line in lines) {
            val opMatch = Regex("^\\s*([A-Z_]+):").find(line)
            if (opMatch != null) {
                currentOp = opMatch.groupValues[1]
            }

            if (currentOp == null) continue

            val accessMatch = Regex("Access:\\s*\\[([^\\]]+)]\\s*(.*)").find(line)
            if (accessMatch != null) {
                val accessTime = accessMatch.groupValues[2].trim().ifBlank { accessMatch.groupValues[1] }
                val stateKey = "$currentOp:$accessTime"
                if (lastState.put(stateKey, accessTime) == null && (emit || isRecentAccess(accessTime))) {
                    val category = opCategoryMap[currentOp] ?: AccessCategory.PERMISSION
                    val identifierId = opIdentifierMap[currentOp]
                    val value = identifierId
                        ?.let { IdentifierCatalog.findById(it) }
                        ?.let { IdentifierReader.readDefinition(it)?.value }
                    record(
                        category = category,
                        action = currentOp,
                        permission = currentOp,
                        requestDetails = "AppOps: доступ к $currentOp",
                        responseDetails = value?.let { "Значение: $it" }
                            ?: "Статус: разрешено, время=$accessTime",
                        raw = line.trim(),
                        identifierId = identifierId
                    )
                }
            }

            val rejectMatch = Regex("Reject:\\s*\\[(\\w+)\\]").find(line)
            if (rejectMatch != null) {
                val rejectTime = rejectMatch.groupValues[1]
                val stateKey = "reject:$currentOp:$rejectTime"
                if (lastState.put(stateKey, rejectTime) == null && (emit || isRecentAccess(rejectTime))) {
                    record(
                        category = AccessCategory.PERMISSION,
                        action = "$currentOp (отклонено)",
                        permission = currentOp,
                        requestDetails = "AppOps: запрос $currentOp",
                        responseDetails = "Статус: отклонено, время=$rejectTime",
                        raw = line.trim()
                    )
                }
            }
        }
        seeded = true
    }

    private fun isRecentAccess(accessTime: String): Boolean = isRecentAccessStamp(accessTime)

    private suspend fun record(
        category: AccessCategory,
        action: String,
        permission: String?,
        requestDetails: String?,
        responseDetails: String?,
        raw: String,
        identifierId: String? = null
    ) {
        if (repository.isDuplicate(packageName, action, raw)) return
        val def = identifierId?.let { IdentifierCatalog.findById(it) }
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = def?.toAccessCategory() ?: category,
                source = EventSource.APPOPS,
                action = def?.displayName ?: action,
                permission = permission,
                requestDetails = requestDetails,
                responseDetails = responseDetails,
                rawData = raw,
                identifierName = def?.id,
                identifierGroup = def?.group?.name
            )
        )
    }
}
