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
 * Периодический опрос всех системных сервисов AOSP (dumpsys),
 * через которые приложение может получать данные в обход своего PID.
 */
class ComprehensiveDumpMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    private data class DumpTarget(
        val service: String,
        val category: AccessCategory,
        val action: String,
        val extraArgs: String = "",
        val headBytes: Int = 12000
    )

    private val targets = listOf(
        DumpTarget("media.camera", AccessCategory.CAMERA, "Camera service"),
        DumpTarget("media.camera.provider", AccessCategory.CAMERA, "Camera provider"),
        DumpTarget("media.audio_flinger", AccessCategory.MICROPHONE, "AudioFlinger"),
        DumpTarget("media.audio_policy", AccessCategory.MICROPHONE, "AudioPolicy"),
        DumpTarget("audio", AccessCategory.MICROPHONE, "Audio manager"),
        DumpTarget("media.player", AccessCategory.MICROPHONE, "MediaPlayer"),
        DumpTarget("media.sound_trigger_hw", AccessCategory.MICROPHONE, "SoundTrigger / hotword"),
        DumpTarget("telephony.registry", AccessCategory.TELEPHONY, "Telephony registry"),
        DumpTarget("iphonesubinfo", AccessCategory.TELEPHONY, "IPhoneSubInfo"),
        DumpTarget("isub", AccessCategory.TELEPHONY, "Subscription"),
        DumpTarget("phone", AccessCategory.TELEPHONY, "Phone service"),
        DumpTarget("sms", AccessCategory.SMS, "SMS service"),
        DumpTarget("sensorservice", AccessCategory.SENSOR, "Sensor service"),
        DumpTarget("bluetooth_manager", AccessCategory.BLUETOOTH, "Bluetooth"),
        DumpTarget("bluetooth_audio", AccessCategory.BLUETOOTH, "BT audio"),
        DumpTarget("wifi", AccessCategory.NETWORK, "Wi‑Fi"),
        DumpTarget("wifiscanner", AccessCategory.LOCATION, "Wi‑Fi scanner"),
        DumpTarget("connectivity", AccessCategory.NETWORK, "Connectivity"),
        DumpTarget("netstats", AccessCategory.NETWORK, "NetStats"),
        DumpTarget("network_management", AccessCategory.NETWORK, "Netd"),
        DumpTarget("clipboard", AccessCategory.CLIPBOARD, "Clipboard"),
        DumpTarget("notification", AccessCategory.SYSTEM_API, "Notifications"),
        DumpTarget("activity", AccessCategory.SYSTEM_API, "Activity / FGS", extraArgs = "services $packageName"),
        DumpTarget("jobscheduler", AccessCategory.SYSTEM_API, "JobScheduler"),
        DumpTarget("alarm", AccessCategory.SYSTEM_API, "Alarms"),
        DumpTarget("usagestats", AccessCategory.SYSTEM_API, "UsageStats"),
        DumpTarget("autofill", AccessCategory.SYSTEM_API, "Autofill"),
        DumpTarget("accessibility", AccessCategory.SYSTEM_API, "Accessibility"),
        DumpTarget("input_method", AccessCategory.SYSTEM_API, "IME"),
        DumpTarget("account", AccessCategory.IDENTIFIER, "Accounts"),
        DumpTarget("content", AccessCategory.SYSTEM_API, "ContentResolver"),
        DumpTarget("media_session", AccessCategory.MICROPHONE, "MediaSession"),
        DumpTarget("media.drm", AccessCategory.IDENTIFIER, "MediaDrm"),
        DumpTarget("nfc", AccessCategory.SYSTEM_API, "NFC"),
        DumpTarget("usb", AccessCategory.SYSTEM_API, "USB"),
        DumpTarget("fingerprint", AccessCategory.SYSTEM_API, "Fingerprint"),
        DumpTarget("biometric", AccessCategory.SYSTEM_API, "Biometric"),
        DumpTarget("vibrator", AccessCategory.SENSOR, "Vibrator"),
        DumpTarget("power", AccessCategory.SYSTEM_API, "Power / wake"),
        DumpTarget("deviceidle", AccessCategory.SYSTEM_API, "DeviceIdle"),
        DumpTarget("batterystats", AccessCategory.SYSTEM_API, "BatteryStats"),
        DumpTarget("window", AccessCategory.SYSTEM_API, "Window / overlay"),
        DumpTarget("display", AccessCategory.SYSTEM_API, "Display"),
        DumpTarget("media.projection", AccessCategory.SYSTEM_API, "MediaProjection / screen capture"),
        DumpTarget("shortcut", AccessCategory.SYSTEM_API, "Shortcuts"),
        DumpTarget("role", AccessCategory.PERMISSION, "Roles"),
        DumpTarget("permission", AccessCategory.PERMISSION, "Permission service"),
        DumpTarget("appops", AccessCategory.PERMISSION, "AppOps raw", extraArgs = packageName),
        DumpTarget("package", AccessCategory.PERMISSION, "Package info", extraArgs = packageName),
        DumpTarget("meminfo", AccessCategory.SYSTEM_API, "Meminfo", extraArgs = packageName),
        DumpTarget("procstats", AccessCategory.SYSTEM_API, "Procstats"),
        DumpTarget("gfxinfo", AccessCategory.SYSTEM_API, "Gfx", extraArgs = packageName),
        DumpTarget("dbinfo", AccessCategory.STORAGE, "Databases", extraArgs = packageName),
        DumpTarget("settings", AccessCategory.IDENTIFIER, "Settings provider"),
        DumpTarget("healthconnect", AccessCategory.SENSOR, "Health Connect"),
        DumpTarget("nearby", AccessCategory.BLUETOOTH, "Nearby"),
        DumpTarget("companiondevice", AccessCategory.BLUETOOTH, "Companion device"),
        DumpTarget("voiceinteraction", AccessCategory.MICROPHONE, "Voice interaction / hotword"),
        DumpTarget("search", AccessCategory.SYSTEM_API, "Search / global query"),
        DumpTarget("dropbox", AccessCategory.SYSTEM_API, "DropBox"),
        DumpTarget("backup", AccessCategory.STORAGE, "Backup"),
        DumpTarget("stats", AccessCategory.SYSTEM_API, "statsd"),
        DumpTarget("overlay", AccessCategory.SYSTEM_API, "Overlay / SYSTEM_ALERT"),
        DumpTarget("print", AccessCategory.SYSTEM_API, "Print"),
        DumpTarget("credstore", AccessCategory.IDENTIFIER, "Credential store"),
        DumpTarget("android.security.identity", AccessCategory.IDENTIFIER, "Identity credential"),
        DumpTarget("slice", AccessCategory.SYSTEM_API, "Slices"),
        DumpTarget("wallpaper", AccessCategory.SYSTEM_API, "Wallpaper"),
        DumpTarget("textservices", AccessCategory.SYSTEM_API, "Spell checker / text")
    )

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            record(
                AccessCategory.SYSTEM_API,
                "Полный dumpsys-монитор",
                "Опрос ${targets.size} системных сервисов AOSP",
                "Камера, микрофон, телефония, SMS, сенсоры, BT, Wi‑Fi, буфер, сеть, аккаунты, DRM, NFC, биометрия…",
                "comprehensive-init"
            )
            var index = 0
            while (isActive) {
                val batch = targets.subList(index, (index + 6).coerceAtMost(targets.size))
                for (target in batch) {
                    poll(target)
                }
                index = if (index + 6 >= targets.size) 0 else index + 6
                delay(800)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun poll(target: DumpTarget) {
        val cmd = "dumpsys ${target.service} ${target.extraArgs} 2>/dev/null | head -c ${target.headBytes}"
        val dump = RootShell.execAndRead(cmd, timeoutSec = 8)
        if (dump.isBlank() || dump.contains("Can't find service", ignoreCase = true)) return

        val mentions = dump.contains(packageName) ||
            (uid > 0 && (dump.contains("uid=$uid") || dump.contains("u0a${uid % 100000}") || dump.contains(" $uid ")))

        if (!mentions && target.service !in ALWAYS_PARSE) return

        val snippet = extractSnippet(dump)
        if (snippet.isBlank()) return

        val digest = "${target.service}:${snippet.hashCode()}"
        if (seen.put(digest, snippet) != null) return

        val response = specializedResponse(target, dump) ?: snippet

        record(
            category = target.category,
            action = target.action,
            request = "dumpsys ${target.service} ${target.extraArgs}".trim(),
            response = response,
            raw = snippet
        )
    }

    private fun extractSnippet(dump: String): String {
        val lines = dump.lines()
        val hits = lines.filter { line ->
            line.contains(packageName) ||
                (uid > 0 && (line.contains("$uid") || line.contains("u0a${uid % 100000}")))
        }
        if (hits.isNotEmpty()) {
            return hits.take(8).joinToString("\n").take(700)
        }
        return lines.filter { it.isNotBlank() }.take(6).joinToString("\n").take(400)
    }

    private fun specializedResponse(target: DumpTarget, dump: String): String? {
        return when (target.service) {
            "media.camera", "media.camera.provider" ->
                firstMatch(dump, Regex("(?i)(Camera \\d+|device|client|active).*"))
            "media.audio_flinger", "audio" ->
                firstMatch(dump, Regex("(?i)(Record|Input|source|session|package).*"))
            "sensorservice" ->
                firstMatch(dump, Regex("(?i)(accelerometer|gyroscope|magnetometer|proximity|light|Connection).*"))
            "clipboard" ->
                "Буфер: " + dump.lines().firstOrNull { it.contains("clip", ignoreCase = true) || it.contains("text", ignoreCase = true) }
                    ?.take(200)
            "telephony.registry" ->
                firstMatch(dump, Regex("(?i)(mCallState|mServiceState|mCellIdentity|mSignalStrength|mImei).*"))
            "wifi" ->
                firstMatch(dump, Regex("(?i)(mWifiInfo|SSID|BSSID|MacAddress|Scan).*"))
            "bluetooth_manager" ->
                firstMatch(dump, Regex("(?i)(name|address|state|connected).*"))
            "netstats" ->
                firstMatch(dump, Regex("(?i)(uid=$uid|rb=|rp=|tb=|tp=).*"))
            else -> null
        }
    }

    private fun firstMatch(text: String, regex: Regex): String? {
        return text.lineSequence().mapNotNull { line ->
            regex.find(line)?.value?.trim()
        }.take(5).joinToString(" | ").ifBlank { null }
    }

    private suspend fun record(
        category: AccessCategory,
        action: String,
        request: String?,
        response: String?,
        raw: String
    ) {
        if (repository.isDuplicate(packageName, action, raw, sinceMs = 8000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = request,
                responseDetails = response,
                rawData = raw.take(1500)
            )
        )
    }

    companion object {
        private val ALWAYS_PARSE = setOf("media.camera", "media.audio_flinger", "sensorservice", "clipboard")
    }
}
