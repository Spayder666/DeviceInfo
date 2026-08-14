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

class AppOpsMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val lastState = ConcurrentHashMap<String, String>()

    private val opCategoryMap = mapOf(
        "COARSE_LOCATION" to AccessCategory.LOCATION,
        "FINE_LOCATION" to AccessCategory.LOCATION,
        "GPS" to AccessCategory.LOCATION,
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
        "READ_MEDIA_AUDIO" to AccessCategory.STORAGE
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

        for (line in lines) {
            val opMatch = Regex("^\\s*([A-Z_]+):").find(line)
            if (opMatch != null) {
                currentOp = opMatch.groupValues[1]
            }

            if (currentOp == null) continue

            val accessMatch = Regex("Access:\\s*\\[(\\w+)\\]").find(line)
            if (accessMatch != null) {
                val accessTime = accessMatch.groupValues[1]
                val stateKey = "$currentOp:$accessTime"
                if (lastState.put(stateKey, accessTime) == null) {
                    val category = opCategoryMap[currentOp] ?: AccessCategory.PERMISSION
                    record(
                        category = category,
                        action = currentOp,
                        permission = currentOp,
                        requestDetails = "AppOps: доступ к $currentOp",
                        responseDetails = "Статус: разрешено, время=$accessTime",
                        raw = line.trim()
                    )
                }
            }

            val rejectMatch = Regex("Reject:\\s*\\[(\\w+)\\]").find(line)
            if (rejectMatch != null) {
                val rejectTime = rejectMatch.groupValues[1]
                val stateKey = "reject:$currentOp:$rejectTime"
                if (lastState.put(stateKey, rejectTime) == null) {
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
    }

    private suspend fun record(
        category: AccessCategory,
        action: String,
        permission: String?,
        requestDetails: String?,
        responseDetails: String?,
        raw: String
    ) {
        if (repository.isDuplicate(packageName, action, raw)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.APPOPS,
                action = action,
                permission = permission,
                requestDetails = requestDetails,
                responseDetails = responseDetails,
                rawData = raw
            )
        )
    }
}
