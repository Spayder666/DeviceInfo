package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
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
        PatternRule(Regex("(?i)getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getLine1Number|TelephonyManager"), AccessCategory.TELEPHONY, "Telephony/SIM API", "READ_PHONE_STATE"),
        PatternRule(Regex("(?i)getAndroidId|Settings\\.Secure|AdvertisingId|getSerial|getMacAddress|WifiInfo"), AccessCategory.IDENTIFIER, "Device Identifier API"),
        PatternRule(Regex("(?i)ContactsProvider|ContactsContract|query.*contacts"), AccessCategory.CONTACTS, "Contacts API", "READ_CONTACTS"),
        PatternRule(Regex("(?i)SmsManager|Telephony\\.Sms|content://sms"), AccessCategory.SMS, "SMS API", "READ_SMS"),
        PatternRule(Regex("(?i)checkPermission|requestPermissions|PermissionController|grantRuntimePermission"), AccessCategory.PERMISSION, "Permission Check/Request"),
        PatternRule(Regex("(?i)ClipboardManager|getPrimaryClip|setPrimaryClip"), AccessCategory.CLIPBOARD, "Clipboard API"),
        PatternRule(Regex("(?i)BluetoothAdapter|BluetoothLeScanner|startScan"), AccessCategory.BLUETOOTH, "Bluetooth API", "BLUETOOTH_SCAN"),
        PatternRule(Regex("(?i)SensorManager|registerListener|TYPE_ACCELEROMETER|TYPE_GYROSCOPE"), AccessCategory.SENSOR, "Sensor API"),
        PatternRule(Regex("(?i)CalendarContract|content://com\\.android\\.calendar"), AccessCategory.CALENDAR, "Calendar API"),
        PatternRule(Regex("(?i)openFile|FileInputStream|content://media|Environment\\.getExternalStorage"), AccessCategory.STORAGE, "Storage/File API"),
        PatternRule(Regex("(?i)HttpURLConnection|OkHttp|Retrofit|Volley|api\\.|/v[0-9]+/"), AccessCategory.NETWORK, "HTTP/API Request"),
        PatternRule(Regex("(?i)connect\\(|Socket\\(|InetAddress|DNS|getaddrinfo"), AccessCategory.NETWORK, "Network Connection"),
        PatternRule(Regex("(?i)getInstalledPackages|getRunningAppProcesses|queryIntentActivities"), AccessCategory.SYSTEM_API, "Package Manager Query"),
        PatternRule(Regex("(?i)getAccounts|AccountManager"), AccessCategory.IDENTIFIER, "Account/Identifier API"),
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
                val cmd = buildString {
                    append("logcat -v threadtime --pid=$pid ")
                    append("-T 1 ")
                    append("*:V 2>&1")
                }
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) {
                        scope.launch { parseLine(line) }
                    }
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

        for (rule in rules) {
            if (rule.regex.containsMatchIn(line)) {
                val requestPart = extractRequest(line)
                val responsePart = extractResponse(line)

                if (repository.isDuplicate(packageName, rule.action, line, sinceMs = 1000)) return

                repository.insert(
                    CaptureEvent(
                        targetPackage = packageName,
                        category = rule.category,
                        source = EventSource.LOGCAT,
                        action = rule.action,
                        permission = rule.permission,
                        requestDetails = requestPart ?: "Запрос через ${rule.action}",
                        responseDetails = responsePart,
                        rawData = line.trim(),
                        processId = pid
                    )
                )
                return
            }
        }
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
            Pattern.compile("denied(?:=|:)?\\s*(\\w+)", Pattern.CASE_INSENSITIVE)
        )
        for (p in patterns) {
            val m = p.matcher(line)
            if (m.find()) return m.group(1)?.trim()
        }
        return null
    }
}
