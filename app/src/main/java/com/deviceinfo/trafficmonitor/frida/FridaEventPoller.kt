package com.deviceinfo.trafficmonitor.frida

import com.deviceinfo.trafficmonitor.analysis.IntegrityVerdict
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
    private var pending = ""

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

        if (sizeStr < lastSize) {
            lastSize = 0L
            pending = ""
        }
        if (sizeStr <= lastSize) return

        val newContent = RootShell.execAndRead(
            "tail -c +${lastSize + 1} ${FridaInstaller.EVENTS_PATH} 2>/dev/null",
            timeoutSec = 5
        )
        lastSize = sizeStr
        val combined = pending + newContent
        val lastNl = combined.lastIndexOf('\n')
        if (lastNl < 0) {
            pending = combined
            return
        }
        pending = combined.substring(lastNl + 1)
        for (line in combined.substring(0, lastNl).split('\n')) {
            if (line.isBlank()) continue
            parseLine(line.trim())
        }
    }

    private suspend fun parseLine(line: String) {
        try {
            val json = JSONObject(line)
            val pkg = json.optString("package", "")
            if (pkg.isNotEmpty() && pkg != packageName) return
            val identifierId = json.optString("identifierId", "")
            val cached = json.optBoolean("cached", false)

            val action = json.optString("action", identifierId)
            val request = json.optString("request").ifBlank { action }.takeIf { it.isNotEmpty() }
            val response = json.optString("response").ifBlank { "(пусто)" }
            val permission = json.optString("permission").takeIf { it.isNotEmpty() }
            val timestamp = json.optLong("timestamp", System.currentTimeMillis())
            val verdict = IntegrityVerdict.summarize(
                listOfNotNull(request, response, line).joinToString(" ")
            )
            val resolvedId = when {
                verdict != null && (
                    identifierId == "ent.integrity" ||
                        identifierId == "ent.safetynet" ||
                        identifierId == "ent.verdict"
                    ) -> "ent.verdict"
                else -> identifierId
            }
            val def = IdentifierCatalog.findById(resolvedId)
            val enriched = listOfNotNull(
                response.takeIf { it.isNotEmpty() && it != "(пусто)" } ?: response,
                verdict
            ).joinToString(" · ").ifBlank { "(пусто)" }

            if (repository.isDuplicate(packageName, action, line, sinceMs = 800)) return

            val category = when {
                resolvedId == "frida.init" -> AccessCategory.SYSTEM_API
                else -> def?.toAccessCategory()
                    ?: categoryForIdentifierId(resolvedId)
                    ?: categoryFor(action, permission, def?.group?.name)
            }

            repository.insert(
                CaptureEvent(
                    timestamp = timestamp,
                    targetPackage = packageName,
                    category = category,
                    source = EventSource.FRIDA,
                    action = when {
                        resolvedId == "frida.init" -> "Frida: хуки Java API включены"
                        verdict != null && resolvedId == "ent.verdict" -> "Integrity verdict: $verdict"
                        else -> def?.displayName ?: action
                    },
                    permission = permission ?: def?.permission,
                    requestDetails = when {
                        cached -> listOfNotNull(
                            request?.takeIf { it.isNotEmpty() } ?: def?.api,
                            "уже в памяти процесса"
                        ).joinToString(" · ")
                        !request.isNullOrEmpty() -> request
                        else -> def?.api
                    },
                    responseDetails = enriched,
                    rawData = line,
                    identifierName = def?.id ?: resolvedId.takeIf { it.isNotEmpty() },
                    identifierGroup = def?.group?.name
                )
            )
        } catch (_: Exception) {
            // malformed line
        }
    }

    fun resetOffset() {
        lastSize = 0L
        pending = ""
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
            "usage" in text || "installed" in text || "queryintent" in text || "appops" in text ||
                "permission" in text -> AccessCategory.SYSTEM_API
            "nfc" in text || "usb" in text || "display" in text || "battery" in text ||
                "locale" in text || "biometric" in text -> AccessCategory.SYSTEM_API
            "storage" in text || "file" in text || "sqlite" in text || "sharedpref" in text ||
                "media/" in text || "mediastore" in text -> AccessCategory.STORAGE
            "biometric" in text || "fingerprint" in text || "projection" in text -> AccessCategory.SYSTEM_API
            "root" in text || "magisk" in text || "safetynet" in text || "integrity" in text ||
                "xposed" in text || "frida" in text || "selinux" in text || "emulator" in text ||
                "debugger" in text || "attest" in text || "talsec" in text || "shamiko" in text ||
                "pin_fail" in text || "pinning" in text -> AccessCategory.SECURITY
            group == "LOCATION" -> AccessCategory.LOCATION
            group == "ROOT" || group == "ATTESTATION" -> AccessCategory.SECURITY
            group == "TELEPHONY" || group == "SUBSCRIPTION" -> AccessCategory.TELEPHONY
            group == "NETWORK" || group == "WIFI" -> AccessCategory.NETWORK
            else -> AccessCategory.IDENTIFIER
        }
    }
}
