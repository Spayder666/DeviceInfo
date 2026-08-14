package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.IdentifierDefinition
import com.deviceinfo.trafficmonitor.identifiers.IdentifierMatcher
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.regex.Pattern

class LogcatMonitor(
    private val packageName: String,
    private val pid: Int,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null

    private data class PatternRule(
        val regex: Regex,
        val category: AccessCategory,
        val action: String,
        val permission: String? = null
    )

    private val rules = listOf(
        PatternRule(Regex("(?i)getLastKnownLocation|requestLocationUpdates|LocationManager"), AccessCategory.LOCATION, "GPS/Location API", "ACCESS_FINE_LOCATION"),
        PatternRule(Regex("(?i)GnssLocationProvider|FusedLocation"), AccessCategory.LOCATION, "GNSS/Fused Location"),
        PatternRule(Regex("(?i)openCamera|CameraDevice|CameraManager|CameraService"), AccessCategory.CAMERA, "Camera API", "CAMERA"),
        PatternRule(Regex("(?i)AudioRecord|MediaRecorder|RECORD_AUDIO"), AccessCategory.MICROPHONE, "Microphone API", "RECORD_AUDIO"),
        PatternRule(Regex("(?i)ContactsProvider|ContactsContract|query.*contacts"), AccessCategory.CONTACTS, "Contacts API", "READ_CONTACTS"),
        PatternRule(Regex("(?i)SmsManager|Telephony\\.Sms|content://sms"), AccessCategory.SMS, "SMS API", "READ_SMS"),
        PatternRule(Regex("(?i)checkPermission|requestPermissions|PermissionController|grantRuntimePermission"), AccessCategory.PERMISSION, "Permission Check/Request"),
        PatternRule(Regex("(?i)ClipboardManager|getPrimaryClip|setPrimaryClip"), AccessCategory.CLIPBOARD, "Clipboard API"),
        PatternRule(Regex("(?i)BluetoothLeScanner|startScan"), AccessCategory.BLUETOOTH, "Bluetooth Scan", "BLUETOOTH_SCAN"),
        PatternRule(Regex("(?i)SensorManager|registerListener|TYPE_ACCELEROMETER|TYPE_GYROSCOPE"), AccessCategory.SENSOR, "Sensor API"),
        PatternRule(Regex("(?i)CalendarContract|content://com\\.android\\.calendar"), AccessCategory.CALENDAR, "Calendar API"),
        PatternRule(Regex("(?i)openFile|FileInputStream|content://media|Environment\\.getExternalStorage"), AccessCategory.STORAGE, "Storage/File API"),
        PatternRule(Regex("(?i)HttpURLConnection|OkHttp|Retrofit|Volley|api\\.|/v[0-9]+/"), AccessCategory.NETWORK, "HTTP/API Request"),
        PatternRule(Regex("(?i)connect\\(|Socket\\(|InetAddress|DNS|getaddrinfo"), AccessCategory.NETWORK, "Network Connection"),
        PatternRule(Regex("(?i)getInstalledPackages|getRunningAppProcesses|queryIntentActivities"), AccessCategory.SYSTEM_API, "Package Manager Query"),
        PatternRule(Regex("(?i)BiometricPrompt|FingerprintManager|FaceManager"), AccessCategory.SYSTEM_API, "Biometric API"),
        PatternRule(Regex("(?i)NfcAdapter|NFC"), AccessCategory.SYSTEM_API, "NFC API"),
        PatternRule(Regex("(?i)UsageStatsManager|queryUsageStats"), AccessCategory.SYSTEM_API, "Usage Stats API"),
        PatternRule(Regex("(?i)AccessibilityService|AccessibilityNodeInfo"), AccessCategory.SYSTEM_API, "Accessibility API"),
        PatternRule(Regex("(?i)NotificationListener|NotificationManager"), AccessCategory.SYSTEM_API, "Notification API"),
        PatternRule(Regex("(?i)MediaStore|ImageReader|ContentResolver"), AccessCategory.STORAGE, "Media/Content API")
    )

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            try {
                val cmd = "logcat -v threadtime --pid=$pid -T 1 *:V 2>&1"
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) scope.launch { parseLine(line) }
                }
            } catch (_: Exception) {
                // PID may change; service will restart monitor
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun parseLine(line: String) {
        if (line.isBlank()) return

        if (parseLibcPropertyLine(line)) return

        IdentifierMatcher.matchLogcat(line)?.let { def ->
            recordIdentifier(def, line)
            return
        }

        for (rule in rules) {
            if (rule.regex.containsMatchIn(line)) {
                recordGeneric(rule.category, rule.action, rule.permission, line)
                return
            }
        }
    }

    private suspend fun parseLibcPropertyLine(line: String): Boolean {
        val denied = Regex("Access denied finding property \"([^\"]+)\"").find(line)
        if (denied != null) {
            val property = denied.groupValues[1]
            val def = IdentifierMatcher.matchLogcat(line)
                ?: IdentifierCatalog.all.firstOrNull { it.systemProperty == property }
            recordPropertyAccess(
                property = property,
                def = def,
                response = "ОТКЛОНЕНО (Access denied) — приложение не получило значение",
                line = line
            )
            return true
        }

        val found = Regex("(?:read|access|found) property \"([^\"]+)\"(?:[=:]\\s*\"?([^\"\\n]+)\"?)?", RegexOption.IGNORE_CASE)
            .find(line)
        if (found != null) {
            val property = found.groupValues[1]
            val value = found.groupValues.getOrNull(2)?.trim()?.takeIf { it.isNotEmpty() }
            val def = IdentifierCatalog.all.firstOrNull { it.systemProperty == property }
            recordPropertyAccess(
                property = property,
                def = def,
                response = value ?: "(значение не показано в logcat)",
                line = line
            )
            return true
        }
        return false
    }

    private suspend fun recordPropertyAccess(
        property: String,
        def: IdentifierDefinition?,
        response: String,
        line: String
    ) {
        val action = def?.displayName ?: "System property: $property"
        if (repository.isDuplicate(packageName, action, line, sinceMs = 1000)) return

        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.IDENTIFIER,
                source = EventSource.LOGCAT,
                action = action,
                permission = def?.permission,
                requestDetails = "Property: $property",
                responseDetails = response,
                rawData = line.trim(),
                processId = pid,
                identifierName = def?.id ?: "getprop.shell",
                identifierGroup = def?.group?.name ?: "SYSTEM_PROPERTY"
            )
        )
    }

    private suspend fun recordIdentifier(def: IdentifierDefinition, line: String) {
        val action = def.displayName
        if (repository.isDuplicate(packageName, action, line, sinceMs = 1000)) return

        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.IDENTIFIER,
                source = EventSource.LOGCAT,
                action = action,
                permission = def.permission,
                requestDetails = buildIdentifierRequest(def),
                responseDetails = extractResponse(line),
                rawData = line.trim(),
                processId = pid,
                identifierName = def.id,
                identifierGroup = def.group.name
            )
        )
    }

    private suspend fun recordGeneric(
        category: AccessCategory,
        action: String,
        permission: String?,
        line: String
    ) {
        if (repository.isDuplicate(packageName, action, line, sinceMs = 1000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.LOGCAT,
                action = action,
                permission = permission,
                requestDetails = extractRequest(line) ?: "Запрос через $action",
                responseDetails = extractResponse(line),
                rawData = line.trim(),
                processId = pid
            )
        )
    }

    private fun buildIdentifierRequest(def: IdentifierDefinition): String {
        val parts = buildList {
            def.api?.let { add("API: $it") }
            def.systemProperty?.let { add("Property: $it") }
            def.filePath?.let { add("File: $it") }
            def.description?.let { add(it) }
        }
        return parts.joinToString(" | ").ifEmpty { "Доступ к ${def.displayName}" }
    }

    private fun extractRequest(line: String): String? {
        val patterns = listOf(
            Pattern.compile("request(?:ing|ed)?:\\s*(.+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("call(?:ing|ed)?\\s+(\\w+\\([^)]*\\))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("checkPermission:\\s*(\\S+)", Pattern.CASE_INSENSITIVE)
        )
        for (p in patterns) {
            val m = p.matcher(line)
            if (m.find()) return m.group(1)?.trim()
        }
        return null
    }

    private fun extractResponse(line: String): String? {
        val patterns = listOf(
            Pattern.compile("result(?:=|:)?\\s*(.+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("return(?:ed|ing)?:\\s*(.+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("granted(?:=|:)?\\s*(\\w+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("denied(?:=|:)?\\s*(\\w+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("value(?:=|:)?\\s*(.+)", Pattern.CASE_INSENSITIVE)
        )
        for (p in patterns) {
            val m = p.matcher(line)
            if (m.find()) return m.group(1)?.trim()
        }
        return null
    }
}
