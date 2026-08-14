package com.deviceinfo.trafficmonitor.frida

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.categoryForIdentifierId
import com.deviceinfo.trafficmonitor.identifiers.toAccessCategory
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

class FridaEventPoller(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private var lastSize = 0L

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollEvents()
                delay(400)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun pollEvents() {
        val sizeStr = RootShell.execAndRead(
            "wc -c < ${FridaInstaller.EVENTS_PATH} 2>/dev/null"
        ).trim().toLongOrNull() ?: return

        if (sizeStr <= lastSize) return

        val newContent = RootShell.execAndRead(
            "tail -c +${lastSize + 1} ${FridaInstaller.EVENTS_PATH} 2>/dev/null",
            timeoutSec = 5
        )
        lastSize = sizeStr

        for (line in newContent.lines()) {
            if (line.isBlank()) continue
            parseLine(line.trim())
        }
    }

    private suspend fun parseLine(line: String) {
        try {
            val json = JSONObject(line)
            val identifierId = json.optString("identifierId", "")
            if (identifierId == "frida.init") return

            val def = IdentifierCatalog.findById(identifierId)
            val action = json.optString("action", identifierId)
            val request = json.optString("request", null)
            val response = json.optString("response", null)
            val permission = json.optString("permission", null).takeIf { it.isNotEmpty() }
            val timestamp = json.optLong("timestamp", System.currentTimeMillis())

            if (repository.isDuplicate(packageName, action, line, sinceMs = 800)) return

            repository.insert(
                CaptureEvent(
                    timestamp = timestamp,
                    targetPackage = packageName,
                    category = def?.toAccessCategory()
                        ?: categoryForIdentifierId(identifierId)
                        ?: categoryFor(action, permission, def?.group?.name),
                    source = EventSource.FRIDA,
                    action = def?.displayName ?: action,
                    permission = permission ?: def?.permission,
                    requestDetails = request?.takeIf { it.isNotEmpty() } ?: def?.api,
                    responseDetails = response?.takeIf { it.isNotEmpty() },
                    rawData = line,
                    identifierName = def?.id ?: identifierId.takeIf { it.isNotEmpty() },
                    identifierGroup = def?.group?.name
                )
            )
        } catch (_: Exception) {
            // malformed line
        }
    }

    fun resetOffset() {
        lastSize = 0L
    }

    private fun categoryFor(action: String, permission: String?, group: String?): AccessCategory {
        val text = "$action ${permission.orEmpty()} ${group.orEmpty()}".lowercase()
        return when {
            "camera" in text -> AccessCategory.CAMERA
            "audio" in text || "record" in text || "microphone" in text || "mediarecorder" in text -> AccessCategory.MICROPHONE
            "location" in text || "gnss" in text || "gps" in text || "fused" in text || "geofence" in text -> AccessCategory.LOCATION
            "sms" in text || "mms" in text -> AccessCategory.SMS
            "contact" in text -> AccessCategory.CONTACTS
            "calendar" in text -> AccessCategory.CALENDAR
            "clipboard" in text -> AccessCategory.CLIPBOARD
            "sensor" in text -> AccessCategory.SENSOR
            "bluetooth" in text || "bt." in text -> AccessCategory.BLUETOOTH
            "wifi" in text || "http" in text || "url." in text || "okhttp" in text ||
                "webview" in text || "cronet" in text || "volley" in text || "retrofit" in text ||
                "sni" in text || "getaddrinfo" in text || "https" in text || "ssl_read" in text ||
                "ssl_write" in text || "mitm" in text || "connectivity" in text || "socket" in text ->
                AccessCategory.NETWORK
            "telephony" in text || "imei" in text || "sim" in text || "phone" in text -> AccessCategory.TELEPHONY
            "storage" in text || "file" in text || "sqlite" in text || "sharedpref" in text ||
                "media/" in text -> AccessCategory.STORAGE
            "biometric" in text || "fingerprint" in text || "projection" in text -> AccessCategory.SYSTEM_API
            "root" in text || "magisk" in text || "safetynet" in text || "integrity" in text ||
                "xposed" in text || "frida" in text || "selinux" in text || "emulator" in text ||
                "debugger" in text || "attest" in text -> AccessCategory.SECURITY
            group == "LOCATION" -> AccessCategory.LOCATION
            group == "ROOT" || group == "ATTESTATION" -> AccessCategory.SECURITY
            group == "TELEPHONY" || group == "SUBSCRIPTION" -> AccessCategory.TELEPHONY
            group == "NETWORK" || group == "WIFI" -> AccessCategory.NETWORK
            else -> AccessCategory.IDENTIFIER
        }
    }
}
