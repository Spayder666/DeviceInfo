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

/** Системный logcat по всем чувствительным тегам AOSP / GMS / OEM (не только PID приложения). */
class SystemLogcatMonitor(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            val tags = TAGS.joinToString(" ")
            val cmd = "logcat -v threadtime -T 1 $tags *:S 2>&1"
            try {
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) scope.launch { parseLine(line) }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun parseLine(line: String) {
        if (line.isBlank()) return
        val classified = classify(line) ?: return
        if (repository.isDuplicate(packageName, classified.action, line, sinceMs = 1200)) return

        val loc = LOCATION_FIX.find(line)
        val latLon = loc?.let { "lat=${it.groupValues[2]} lon=${it.groupValues[3]}" }

        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = classified.category,
                source = EventSource.LOGCAT,
                action = classified.action,
                permission = classified.permission,
                requestDetails = if (line.contains(packageName)) {
                    "Упоминание $packageName"
                } else {
                    "Системный лог (${classified.action})"
                },
                responseDetails = latLon ?: line.substringAfter(": ").take(280),
                rawData = line.trim(),
                identifierName = classified.identifierId,
                identifierGroup = classified.group
            )
        )
    }

    private fun classify(line: String): Classified? {
        val mentionsPkg = line.contains(packageName)
        for (rule in RULES) {
            if (rule.regex.containsMatchIn(line)) {
                if (rule.requirePackage && !mentionsPkg) continue
                return Classified(rule.category, rule.action, rule.permission, rule.identifierId, rule.group)
            }
        }
        if (mentionsPkg && SENSITIVE.containsMatchIn(line)) {
            return Classified(AccessCategory.SYSTEM_API, "System log", null, null, null)
        }
        return null
    }

    private data class Classified(
        val category: AccessCategory,
        val action: String,
        val permission: String?,
        val identifierId: String?,
        val group: String?
    )

    private data class Rule(
        val regex: Regex,
        val category: AccessCategory,
        val action: String,
        val permission: String? = null,
        val identifierId: String? = null,
        val group: String? = null,
        val requirePackage: Boolean = true
    )

    companion object {
        private val LOCATION_FIX = Regex("""Location\[(\w+)\s+(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)""")
        private val SENSITIVE = Regex(
            "(?i)permission|denied|granted|privacy|pii|imei|android_id|location|camera|mic|sms|contact"
        )

        private val TAGS = listOf(
            "LocationManagerService:V", "LocationProviderManager:V", "GnssLocationProvider:V",
            "GnssManagerService:V", "GpsLocationProvider:V", "FusedLocationProvider:V",
            "FusedLocation:V", "GCoreFlp:V", "FLP:V", "NetworkLocationService:V",
            "NlpService:V", "GeofencerStateMachine:V", "SUPL:V", "IZat:V", "QLocation:V",
            "GoogleLocationManager:V", "WifiScanningService:V",
            "CameraService:V", "Camera2Client:V", "Camera3-Device:V", "CameraManager:V",
            "LegacyCamera:V", "CAM2PORT_:V",
            "AudioFlinger:V", "AudioPolicy:V", "AudioRecord:V", "AudioManager:V",
            "MediaRecorder:V", "SoundTrigger:V", "AHalAudio:V",
            "TelephonyRegistry:V", "PhoneInterfaceManager:V", "IccProvider:V",
            "TelephonyManager:V", "SubscriptionManager:V", "ISub:V", "IPhoneSubInfo:V",
            "GsmCdmaPhone:V", "RILJ:V", "SubscriptionController:V",
            "SmsDispatchersController:V", "InboundSmsHandler:V", "SmsApplication:V",
            "ContactsProvider:V", "ContactsProvider2:V", "CallLogProvider:V",
            "CalendarProvider2:V",
            "ClipboardService:V", "ClipboardServiceImpl:V",
            "SensorService:V", "SensorManager:V", "SensorService+::V",
            "BluetoothManagerService:V", "bt_btif:V", "BluetoothAdapter:V",
            "WifiService:V", "WifiClientModeImpl:V", "WifiScan:V",
            "ConnectivityService:V", "NetworkMonitor:V", "DnsManager:V",
            "NotificationService:V", "NotificationManager:V",
            "AccountManagerService:V", "MediaDrm:V",
            "NfcService:V", "UsbDeviceManager:V",
            "BiometricService:V", "FingerprintService:V", "FaceService:V",
            "MediaProjectionManagerService:V",
            "AppOps:V", "PermissionService:V", "PackageManager:V",
            "ActivityManager:I", "ActivityTaskManager:I",
            "ContentService:V", "StorageManagerService:V",
            "MediaProvider:V", "DownloadManager:V",
            "AutofillManagerService:V", "AccessibilityManager:V",
            "InputMethodManagerService:V",
            "JobScheduler:V", "AlarmManager:V",
            "UsageStatsService:V", "PowerManagerService:V",
            "HealthConnect:V", "NearbyConnections:V", "NearbyMediums:V",
            "ActivityRecognition:V", "Geofence:V", "WorkManager:V",
            "OkHttp:V", "OkHttpClient:V", "Cronet:V", "chromium:V",
            "WebView:V", "cr_AwContents:V",
            "SQLiteLog:V", "SQLiteDatabase:V",
            "auditd:V", "SELinux:V", "binder:V",
            "IZat:V", "QLocation:V", "HwLocation:V", "HmsLocation:V",
            "WifiRtt:V", "UwbService:V", "WifiAware:V",
            "FirebaseMessaging:V", "GCM:V",
            "PrivacyIndicator:V", "SensorPrivacyService:V"
        )

        private val RULES = listOf(
            Rule(Regex("(?i)Location\\[\\w+\\s+-?\\d+\\.\\d+"), AccessCategory.LOCATION, "Location fix", "ACCESS_FINE_LOCATION", "location.gps", "LOCATION"),
            Rule(Regex("(?i)FusedLocation|GCoreFlp|FLP|LocationRequest|requestLocation"), AccessCategory.LOCATION, "Fused / LMS", "ACCESS_FINE_LOCATION", "location.fused", "LOCATION"),
            Rule(Regex("(?i)Gnss|GPS_|SUPL|AGps|Nmea"), AccessCategory.LOCATION, "GNSS / SUPL", "ACCESS_FINE_LOCATION", "location.gnss_nmea", "LOCATION"),
            Rule(Regex("(?i)Camera(Service|Device|Manager)|openCamera|Camera3"), AccessCategory.CAMERA, "Camera", "CAMERA"),
            Rule(Regex("(?i)AudioRecord|MediaRecorder|RECORD_AUDIO|AudioFlinger|SoundTrigger|hotword"), AccessCategory.MICROPHONE, "Microphone / audio", "RECORD_AUDIO"),
            Rule(Regex("(?i)TelephonyRegistry|TelephonyManager|getImei|getDeviceId|getSimState|getSimOperator|getNetworkOperator|IccProvider|RILJ|Subscription|IPhoneSubInfo|PhoneInterfaceManager"), AccessCategory.TELEPHONY, "Telephony / SIM", "READ_PHONE_STATE", "tel.sim_operator", "TELEPHONY"),
            Rule(Regex("(?i)SmsDispatcher|InboundSms|SmsManager|content://sms"), AccessCategory.SMS, "SMS", "READ_SMS"),
            Rule(Regex("(?i)ContactsProvider|ContactsContract|content://com\\.android\\.contacts"), AccessCategory.CONTACTS, "Contacts", "READ_CONTACTS"),
            Rule(Regex("(?i)CallLogProvider|content://call_log"), AccessCategory.TELEPHONY, "Call log", "READ_CALL_LOG"),
            Rule(Regex("(?i)CalendarProvider|content://com\\.android\\.calendar"), AccessCategory.CALENDAR, "Calendar", "READ_CALENDAR"),
            Rule(Regex("(?i)Clipboard"), AccessCategory.CLIPBOARD, "Clipboard", "READ_CLIPBOARD"),
            Rule(Regex("(?i)SensorService|SensorManager|accelerometer|gyroscope|TYPE_"), AccessCategory.SENSOR, "Sensors"),
            Rule(Regex("(?i)Bluetooth|bt_btif|BLE scan"), AccessCategory.BLUETOOTH, "Bluetooth", "BLUETOOTH_CONNECT", "bt.local_mac", "BLUETOOTH"),
            Rule(Regex("(?i)WifiService|WifiScan|getScanResults|BSSID|SSID"), AccessCategory.NETWORK, "Wi‑Fi", "ACCESS_FINE_LOCATION", "wifi.scan_results", "WIFI"),
            Rule(Regex("(?i)ConnectivityService|NetworkMonitor|DnsManager|HttpURLConnection|OkHttp"), AccessCategory.NETWORK, "Network"),
            Rule(Regex("(?i)AccountManager"), AccessCategory.IDENTIFIER, "Accounts", "GET_ACCOUNTS", "account.list", "ACCOUNT"),
            Rule(Regex("(?i)MediaDrm|widevine|deviceUniqueId"), AccessCategory.IDENTIFIER, "DRM", null, "drm.widevine_id", "DRM"),
            Rule(Regex("(?i)MediaProjection|VirtualDisplay|screencast"), AccessCategory.SYSTEM_API, "Screen capture"),
            Rule(Regex("(?i)Biometric|Fingerprint|FaceService"), AccessCategory.SYSTEM_API, "Biometric"),
            Rule(Regex("(?i)NfcService|NfcAdapter"), AccessCategory.SYSTEM_API, "NFC"),
            Rule(Regex("(?i)AppOps|checkPermission|grantRuntimePermission"), AccessCategory.PERMISSION, "Permission / AppOps"),
            Rule(Regex("(?i)MediaProvider|DownloadManager|StorageManager|openFile"), AccessCategory.STORAGE, "Storage / media"),
            Rule(Regex("(?i)Autofill|Accessibility|InputMethod"), AccessCategory.SYSTEM_API, "IME / Autofill / A11y"),
            Rule(Regex("(?i)JobScheduler|AlarmManager|UsageStats|PowerManager"), AccessCategory.SYSTEM_API, "Jobs / alarms / power"),
            Rule(Regex("(?i)HealthConnect|HealthConnectService"), AccessCategory.SENSOR, "Health Connect"),
            Rule(Regex("(?i)NearbyConnections|NearbyMediums|FastShare"), AccessCategory.BLUETOOTH, "Nearby"),
            Rule(Regex("(?i)ActivityRecognition|DetectedActivity"), AccessCategory.LOCATION, "Activity Recognition", identifierId = "location.activity", group = "LOCATION"),
            Rule(Regex("(?i)WorkManager|WorkerWrapper"), AccessCategory.SYSTEM_API, "WorkManager"),
            Rule(Regex("(?i)OkHttp|Cronet|WebView|chromium"), AccessCategory.NETWORK, "HTTP / WebView"),
            Rule(Regex("(?i)SQLiteLog|SQLiteDatabase"), AccessCategory.STORAGE, "SQLite"),
            Rule(Regex("(?i)avc:|SELinux|auditd"), AccessCategory.SYSTEM_API, "SELinux / audit")
        )
    }
}
