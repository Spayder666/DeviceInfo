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
 * Дополнительные каналы, которые не видны в logcat --pid:
 * Binder, /proc/maps (SDK), уведомления, БД/prefs, ss, iptables UID LOG,
 * batterystats GPS, broadcasts.
 */
class ExtraChannelMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private val seen = ConcurrentHashMap<String, String>()
    private var iptablesReady = false

    fun start() {
        job = scope.launch(Dispatchers.IO) {
            setupIptablesLog()
            while (isActive) {
                val pids = RootShell.findAllPids(packageName)
                pollBinder(pids)
                pollNativeMaps(pids)
                pollNotifications()
                pollAppData()
                pollSockets(pids)
                pollIptablesDmesg()
                pollBatteryGps()
                pollBroadcasts()
                pollIntents()
                pollDropbox()
                pollNearbyHealth()
                delay(2500)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        if (iptablesReady && uid > 0) {
            RootShell.execAndRead(
                "iptables -D OUTPUT -m owner --uid-owner $uid -j LOG --log-prefix 'AMNET ' 2>/dev/null"
            )
        }
    }

    private fun setupIptablesLog() {
        if (uid <= 0) return
        RootShell.execAndRead("setenforce 0 2>/dev/null")
        val add = RootShell.execAndRead(
            "iptables -C OUTPUT -m owner --uid-owner $uid -j LOG --log-prefix 'AMNET ' 2>/dev/null || " +
                "iptables -I OUTPUT -m owner --uid-owner $uid -j LOG --log-prefix 'AMNET ' && echo ok"
        )
        iptablesReady = add.contains("ok") || add.isBlank()
    }

    private suspend fun pollBinder(pids: List<Int>) {
        for (pid in pids.take(6)) {
            val dump = RootShell.execAndRead(
                "cat /sys/kernel/debug/binder/proc/$pid 2>/dev/null || " +
                    "cat /dev/binderfs/binder_logs/proc/$pid 2>/dev/null",
                timeoutSec = 5
            )
            if (dump.isBlank()) continue
            val interesting = dump.lineSequence().filter { line ->
                BINDER_HINTS.any { it in line.lowercase() }
            }.take(8).joinToString("\n")
            if (interesting.isBlank()) continue
            remember("binder:$pid:${interesting.hashCode()}", AccessCategory.SYSTEM_API, "Binder IPC",
                "PID=$pid → системные сервисы", interesting, interesting)
        }
    }

    private suspend fun pollNativeMaps(pids: List<Int>) {
        for (pid in pids.take(6)) {
            val maps = RootShell.execAndRead("cat /proc/$pid/maps 2>/dev/null | grep '\\.so'", timeoutSec = 6)
            val hits = SDK_LIBS.filter { lib -> maps.contains(lib, ignoreCase = true) }
            if (hits.isEmpty()) continue
            val grouped = hits.groupBy { categoryForSdk(it) }
            for ((category, libs) in grouped) {
                val id = if (category == AccessCategory.LOCATION) "location.gps" else "net.hostname"
                remember(
                    "maps:$pid:$category:${libs.sorted().joinToString()}",
                    category,
                    "Нативные SDK (.so)",
                    "PID=$pid /proc/maps",
                    libs.joinToString(", "),
                    libs.joinToString("\n"),
                    id
                )
            }
        }
    }

    private suspend fun pollNotifications() {
        val dump = RootShell.execAndRead(
            "dumpsys notification --noredact 2>/dev/null | head -c 20000",
            timeoutSec = 10
        )
        if (!dump.contains(packageName)) return
        val blocks = dump.split("NotificationRecord").filter { it.contains(packageName) }
        for (block in blocks.take(8)) {
            val title = Regex("(?i)title[=:]\\s*(.+)").find(block)?.groupValues?.get(1)?.trim()
            val text = Regex("(?i)(?:text|android.text)[=:]\\s*(.+)").find(block)?.groupValues?.get(1)?.trim()
            val extras = listOfNotNull(title, text).joinToString(" | ")
            if (extras.isBlank()) continue
            val category = if (LOCATION_HINT.containsMatchIn(extras)) AccessCategory.LOCATION else AccessCategory.SYSTEM_API
            remember(
                "notif:${extras.hashCode()}",
                category,
                "Уведомление",
                "dumpsys notification --noredact",
                extras.take(400),
                block.take(500),
                if (category == AccessCategory.LOCATION) "location.gps" else null
            )
        }
    }

    private suspend fun pollAppData() {
        val base = "/data/data/$packageName"
        val listing = RootShell.execAndRead(
            "ls -lR $base/databases $base/shared_prefs $base/files 2>/dev/null | head -c 6000",
            timeoutSec = 8
        )
        if (listing.isBlank()) return
        val changed = listing.lineSequence().filter {
            it.contains(".db") || it.contains(".xml") || it.contains("location", ignoreCase = true) ||
                it.contains("gps", ignoreCase = true) || it.contains("track", ignoreCase = true)
        }.take(12).joinToString("\n")
        if (changed.isBlank()) return
        remember(
            "files:${changed.hashCode()}",
            AccessCategory.STORAGE,
            "Файлы / БД приложения",
            base,
            changed.take(500),
            changed
        )

        val dbFiles = Regex("""(/data/data/$packageName/databases/\S+\.db)""").findAll(listing)
            .map { it.groupValues[1] }.distinct().take(4)
        for (db in dbFiles) {
            val tables = RootShell.execAndRead("sqlite3 $db '.tables' 2>/dev/null", timeoutSec = 5).trim()
            if (tables.isBlank()) continue
            val locTable = tables.split(Regex("\\s+")).firstOrNull { t ->
                listOf("loc", "gps", "track", "coord", "position").any { it in t.lowercase() }
            } ?: continue
            val rows = RootShell.execAndRead(
                "sqlite3 -header -column $db 'select * from $locTable limit 3' 2>/dev/null",
                timeoutSec = 6
            ).trim()
            if (rows.isBlank()) continue
            remember(
                "sqlite:$db:$locTable:${rows.hashCode()}",
                AccessCategory.LOCATION,
                "SQLite $locTable",
                db,
                rows.take(500),
                rows,
                "location.gps"
            )
        }
    }

    private suspend fun pollSockets(pids: List<Int>) {
        val ss = RootShell.execAndRead("ss -tunap 2>/dev/null | head -c 20000", timeoutSec = 8)
        val lines = ss.lineSequence().filter { line ->
            (uid > 0 && line.contains("uid:$uid")) || pids.any { line.contains("pid=$it") } ||
                line.contains(packageName)
        }.toList()
        for (line in lines.take(20)) {
            val dest = Regex("""\d+\.\d+\.\d+\.\d+:\d+|\[?[0-9a-fA-F:]+\]?:\d+""").findAll(line)
                .map { it.value }.toList().getOrNull(1) ?: line
            val locNet = listOf("7275", "7276", "1883", "8883", "5683", "5228", "5229").any { it in line }
            remember(
                "ss:$line",
                if (locNet) AccessCategory.LOCATION else AccessCategory.NETWORK,
                if (locNet) "Сокет SUPL/MQTT" else "Сокет (ss)",
                dest,
                line.trim().take(300),
                line.trim()
            )
        }
    }

    private suspend fun pollIptablesDmesg() {
        if (!iptablesReady) return
        val log = RootShell.execAndRead("dmesg -T 2>/dev/null | grep AMNET | tail -n 20", timeoutSec = 6)
        for (line in log.lines()) {
            if (line.isBlank()) continue
            val dst = Regex("DST=(\\S+)").find(line)?.groupValues?.get(1)
            val dpt = Regex("DPT=(\\S+)").find(line)?.groupValues?.get(1)
            val proto = Regex("PROTO=(\\S+)").find(line)?.groupValues?.get(1)
            remember(
                "ipt:$dst:$dpt:$proto:${line.takeLast(40)}",
                AccessCategory.NETWORK,
                "iptables UID LOG",
                "uid=$uid $proto $dst:$dpt",
                "$proto $dst:$dpt",
                line.trim()
            )
        }
    }

    private suspend fun pollBatteryGps() {
        val dump = RootShell.execAndRead(
            "dumpsys batterystats $packageName 2>/dev/null | head -c 8000",
            timeoutSec = 10
        )
        val gps = dump.lineSequence().filter {
            it.contains("gps", ignoreCase = true) || it.contains("location", ignoreCase = true) ||
                it.contains("wakelock", ignoreCase = true)
        }.take(8).joinToString("\n")
        if (gps.isBlank()) return
        remember(
            "batt:${gps.hashCode()}",
            AccessCategory.LOCATION,
            "BatteryStats GPS / wake",
            "dumpsys batterystats $packageName",
            gps.take(400),
            gps,
            "location.gps"
        )
    }

    private suspend fun pollBroadcasts() {
        val dump = RootShell.execAndRead(
            "dumpsys activity broadcasts 2>/dev/null | grep -A2 -F '$packageName' | head -n 40",
            timeoutSec = 8
        )
        if (dump.isBlank()) return
        remember(
            "bc:${dump.hashCode()}",
            AccessCategory.SYSTEM_API,
            "Broadcast",
            "dumpsys activity broadcasts",
            dump.take(400),
            dump
        )
    }

    private suspend fun pollIntents() {
        val dump = RootShell.execAndRead(
            "dumpsys activity intents $packageName 2>/dev/null | head -c 8000",
            timeoutSec = 8
        )
        if (dump.isBlank() || dump.contains("Can't find", ignoreCase = true)) return
        val interesting = dump.lineSequence().filter { line ->
            INTENT_HINTS.any { it in line.lowercase() } || line.contains(packageName)
        }.take(12).joinToString("\n")
        if (interesting.isBlank()) return
        val category = when {
            LOCATION_HINT.containsMatchIn(interesting) -> AccessCategory.LOCATION
            interesting.contains("sms", ignoreCase = true) -> AccessCategory.SMS
            interesting.contains("camera", ignoreCase = true) -> AccessCategory.CAMERA
            else -> AccessCategory.SYSTEM_API
        }
        remember(
            "intent:${interesting.hashCode()}",
            category,
            "Intent / pending",
            "dumpsys activity intents $packageName",
            interesting.take(400),
            interesting,
            if (category == AccessCategory.LOCATION) "location.gps" else null
        )
    }

    private suspend fun pollDropbox() {
        val dump = RootShell.execAndRead(
            "dumpsys dropbox $packageName 2>/dev/null | head -c 4000",
            timeoutSec = 8
        )
        if (dump.isBlank() || !dump.contains(packageName)) return
        val crash = dump.lineSequence().filter {
            it.contains("crash", ignoreCase = true) || it.contains("anr", ignoreCase = true) ||
                it.contains("data_app", ignoreCase = true)
        }.take(6).joinToString("\n")
        if (crash.isBlank()) return
        remember(
            "dropbox:${crash.hashCode()}",
            AccessCategory.SYSTEM_API,
            "DropBox crash/ANR",
            "dumpsys dropbox $packageName",
            crash.take(400),
            crash
        )
    }

    private suspend fun pollNearbyHealth() {
        for (probe in NEARBY_SERVICES) {
            val dump = RootShell.execAndRead(
                "dumpsys ${probe.service} 2>/dev/null | grep -F -A3 '$packageName' | head -n 20",
                timeoutSec = 8
            )
            if (dump.isBlank()) continue
            remember(
                "svc:${probe.service}:${dump.hashCode()}",
                probe.category,
                probe.action,
                "dumpsys ${probe.service}",
                dump.take(400),
                dump,
                probe.identifierId
            )
        }
    }

    private fun categoryForSdk(lib: String): AccessCategory {
        val l = lib.lowercase()
        return when {
            LOCATION_SDK.any { it in l } -> AccessCategory.LOCATION
            NETWORK_SDK.any { it in l } -> AccessCategory.NETWORK
            else -> AccessCategory.SYSTEM_API
        }
    }

    private suspend fun remember(
        key: String,
        category: AccessCategory,
        action: String,
        request: String?,
        response: String?,
        raw: String,
        identifierId: String? = null
    ) {
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, raw, sinceMs = 6000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = request,
                responseDetails = response,
                rawData = raw.take(1500),
                identifierName = identifierId,
                identifierGroup = when {
                    identifierId?.startsWith("location") == true -> "LOCATION"
                    identifierId?.startsWith("net.") == true -> "NETWORK"
                    identifierId?.startsWith("bt.") == true -> "BLUETOOTH"
                    else -> null
                }
            )
        )
    }

    companion object {
        private val BINDER_HINTS = listOf(
            "location", "gnss", "gps", "camera", "audio", "telephony", "phone",
            "clipboard", "sensor", "wifi", "bluetooth", "notification", "activity"
        )
        private val LOCATION_HINT = Regex("(?i)lat|lon|gps|координат|location|км/ч|speed|accuracy")
        private val SDK_LIBS = listOf(
            "libbaidu", "liblocsdk", "libamap", "libmap", "libtencent", "libtiny",
            "libgmm", "libgms", "liblocation", "libgeolocation", "libgnss",
            "libflp", "libnlp", "libsupl", "libxunfei", "libhms", "libpedometer",
            "libtracker", "libgps", "libyandex", "lib2gis", "libhere",
            "libokhttp", "libcronet", "libflutter", "libreactnative",
            "libmqtt", "libpaho", "libjnisdk"
        )
        private val LOCATION_SDK = listOf(
            "loc", "map", "gps", "gnss", "nlp", "supl", "flp", "geo",
            "yandex", "2gis", "here", "amap", "baidu", "tencent", "pedometer",
            "tracker", "xunfei", "tiny", "gmm", "hms"
        )
        private val NETWORK_SDK = listOf("okhttp", "cronet", "mqtt", "paho")
        private val INTENT_HINTS = listOf(
            "location", "gps", "camera", "sms", "mms", "contact", "bluetooth",
            "nfc", "share", "send", "view", "geo:", "tel:", "package="
        )
        private val NEARBY_SERVICES = listOf(
            ServiceProbe("healthconnect", "Health Connect", AccessCategory.SENSOR, "location.activity"),
            ServiceProbe("nearby", "Nearby / Fast Share", AccessCategory.BLUETOOTH, "bt.local_mac"),
            ServiceProbe("companiondevice", "Companion device", AccessCategory.BLUETOOTH, "bt.local_mac"),
            ServiceProbe("stats", "statsd atoms", AccessCategory.SYSTEM_API, null)
        )
    }

    private data class ServiceProbe(
        val service: String,
        val action: String,
        val category: AccessCategory,
        val identifierId: String?
    )
}
