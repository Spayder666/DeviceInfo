package com.deviceinfo.trafficmonitor.probe

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.IdentifierDefinition
import com.deviceinfo.trafficmonitor.identifiers.IdentifierGroup
import com.deviceinfo.trafficmonitor.monitor.MonitorPaths
import com.deviceinfo.trafficmonitor.root.RootShell

data class IdentifierValue(
    val id: String,
    val label: String,
    val value: String
)

/** Читает фактические значения идентификаторов от root (getprop, settings, service call, dumpsys). */
object IdentifierReader {

    fun readForEvent(event: CaptureEvent): List<IdentifierValue> {
        val values = when (event.category) {
            AccessCategory.LOCATION -> readLocation()
            AccessCategory.TELEPHONY -> readTelephony()
            AccessCategory.CAMERA -> readCamera()
            AccessCategory.MICROPHONE -> readMicrophone()
            AccessCategory.CONTACTS -> readContacts()
            AccessCategory.SMS -> readSms()
            AccessCategory.CALENDAR -> readCalendar()
            AccessCategory.CLIPBOARD -> readClipboard()
            AccessCategory.SENSOR -> readSensors()
            AccessCategory.BLUETOOTH -> readBluetooth()
            AccessCategory.NETWORK -> readNetwork(event.targetPackage)
            AccessCategory.STORAGE -> readStorage(event.targetPackage)
            AccessCategory.PERMISSION -> readPermission(event)
            AccessCategory.IDENTIFIER -> readIdentifier(event)
            AccessCategory.SYSTEM_API -> readSystemApi(event.targetPackage)
            AccessCategory.SYSCALL, AccessCategory.OTHER -> readFromCaptured(event)
        }
        return values.filter { it.value.isNotBlank() && it.value != "(пусто)" }
    }

    private fun readIdentifier(event: CaptureEvent): List<IdentifierValue> {
        val def = event.identifierName?.let { IdentifierCatalog.findById(it) }
        val fromDef = def?.let { readDefinition(it) }
        val group = def?.group ?: inferGroup(event)
        val rest = when (group) {
            IdentifierGroup.LOCATION -> readLocation()
            IdentifierGroup.TELEPHONY, IdentifierGroup.SUBSCRIPTION -> readTelephony()
            IdentifierGroup.SETTINGS -> readSettings()
            IdentifierGroup.BUILD, IdentifierGroup.OS_VERSION, IdentifierGroup.SYSTEM_PROPERTY -> readBuild()
            IdentifierGroup.WIFI -> readWifi()
            IdentifierGroup.BLUETOOTH -> readBluetooth()
            IdentifierGroup.DRM -> readDrm()
            IdentifierGroup.ACCOUNT -> readAccounts()
            else -> emptyList()
        }
        return buildList {
            fromDef?.let { add(it) }
            addAll(rest.filter { it.id != fromDef?.id })
        }
    }

    fun readCommon(): List<IdentifierValue> = buildList {
        addAll(readBuild())
        addAll(readSettings())
        addAll(readTelephony())
    }

    fun readDefinition(def: IdentifierDefinition): IdentifierValue? {
        val raw = when {
            def.systemProperty != null -> getprop(def.systemProperty)
            def.id == "settings.android_id" -> settingsGet("secure", "android_id")
            def.id == "settings.device_name" -> settingsGet("global", "device_name")
            def.id == "settings.bluetooth_address" -> settingsGet("secure", "bluetooth_address")
            def.id == "settings.bluetooth_name" -> settingsGet("secure", "bluetooth_name")
            def.id.startsWith("location.") -> readLocation().let { list ->
                list.firstOrNull { it.id == def.id || it.id.endsWith(def.id.substringAfter("location.")) }?.value
                    ?: IdentifierReader.format(list)
            }
            def.id.startsWith("tel.") || def.id.startsWith("sub.") -> readTelephony().firstOrNull { it.id == def.id }?.value
            def.filePath != null -> RootShell.execAndRead("cat ${def.filePath} 2>/dev/null | head -c 300").trim()
            else -> null
        }?.takeIf { it.isNotBlank() } ?: return null
        return IdentifierValue(def.id, def.displayName, raw)
    }

    fun format(values: List<IdentifierValue>): String {
        if (values.isEmpty()) return "(значения недоступны)"
        return values.joinToString("\n") { "${it.label}: ${it.value}" }
    }

    private fun inferGroup(event: CaptureEvent): IdentifierGroup? {
        event.identifierGroup?.let { name ->
            return IdentifierGroup.entries.firstOrNull { it.name == name }
        }
        return null
    }

    private fun inferFromCategory(event: CaptureEvent): IdentifierGroup? = when (event.category) {
        AccessCategory.LOCATION -> IdentifierGroup.LOCATION
        AccessCategory.TELEPHONY -> IdentifierGroup.TELEPHONY
        AccessCategory.BLUETOOTH -> IdentifierGroup.BLUETOOTH
        AccessCategory.NETWORK -> IdentifierGroup.WIFI
        else -> null
    }

    private fun looksLikeLocation(event: CaptureEvent): Boolean {
        val text = listOfNotNull(event.action, event.requestDetails, event.rawData, event.identifierName)
            .joinToString(" ").lowercase()
        return listOf("location", "gps", "gnss", "fused", "geofence", "supl", "nmea", "lat=", "longitude")
            .any { it in text }
    }

    private fun looksLikeTelephony(event: CaptureEvent): Boolean {
        val text = listOfNotNull(event.action, event.requestDetails, event.rawData, event.responseDetails)
            .joinToString(" ").lowercase()
        return listOf("telephony", "phone", "sim", "imei", "imsi", "icc", "subscriber").any { it in text }
    }

    private fun readBuild(): List<IdentifierValue> {
        val keys = listOf(
            "build.model" to "ro.product.model",
            "build.manufacturer" to "ro.product.manufacturer",
            "build.device" to "ro.product.device",
            "build.fingerprint" to "ro.build.fingerprint",
            "build.serial" to "ro.serialno",
            "version.release" to "ro.build.version.release",
            "version.sdk" to "ro.build.version.sdk",
            "version.security_patch" to "ro.build.version.security_patch"
        )
        return keys.mapNotNull { (id, prop) ->
            val value = firstNonEmpty(getprop(prop), getprop("ro.boot.serialno").takeIf { id == "build.serial" })
            value?.let {
                IdentifierValue(id, IdentifierCatalog.findById(id)?.displayName ?: id, it)
            }
        }
    }

    private fun readSettings(): List<IdentifierValue> {
        val androidId = firstNonEmpty(
            settingsGet("secure", "android_id"),
            querySettings("secure", "android_id")
        )
        val deviceName = firstNonEmpty(
            settingsGet("global", "device_name"),
            getprop("net.hostname")
        )
        return listOfNotNull(
            androidId?.let { IdentifierValue("settings.android_id", "Android ID (SSAID)", it) },
            deviceName?.let { IdentifierValue("settings.device_name", "Имя устройства", it) }
        )
    }

    private fun readTelephony(): List<IdentifierValue> {
        val dumpsysPhone = RootShell.execAndRead("dumpsys iphonesubinfo 2>/dev/null", timeoutSec = 8)
        val dumpsysReg = RootShell.execAndRead(
            "dumpsys telephony.registry 2>/dev/null | head -c 8000",
            timeoutSec = 8
        )
        val siminfo = RootShell.execAndRead(
            "content query --uri content://telephony/siminfo 2>/dev/null | head -c 4000",
            timeoutSec = 8
        )

        val imei = firstNonEmpty(
            getprop("persist.radio.imei"),
            getprop("persist.vendor.radio.imei"),
            getprop("ro.ril.oem.imei"),
            getprop("ril.imei"),
            fieldFrom(dumpsysPhone, "Device ID", "IMEI", "mImei"),
            fieldFrom(dumpsysReg, "mImei", "imei"),
            serviceCallString("iphonesubinfo", 1)
        )
        val imsi = firstNonEmpty(
            getprop("gsm.sim.operator.imsi"),
            fieldFrom(dumpsysPhone, "Subscriber ID", "IMSI", "mSubscriberId"),
            fieldFrom(dumpsysReg, "mSubscriberId", "imsi"),
            serviceCallString("iphonesubinfo", 4)
        )
        val iccid = firstNonEmpty(
            fieldFrom(siminfo, "icc_id", "iccid"),
            fieldFrom(dumpsysPhone, "ICC ID", "ICCID", "mIccId"),
            serviceCallString("iphonesubinfo", 8)
        )
        val number = firstNonEmpty(
            fieldFrom(siminfo, "number", "phoneNumber"),
            fieldFrom(dumpsysPhone, "Phone Number", "Line 1 Number"),
            fieldFrom(dumpsysReg, "mLine1Number", "phoneNumber"),
            getprop("ril.line1.number"),
            serviceCallString("iphonesubinfo", 11)
        )
        val operator = firstNonEmpty(
            getprop("gsm.sim.operator.numeric"),
            getprop("gsm.operator.numeric")
        )
        val operatorName = firstNonEmpty(
            getprop("gsm.sim.operator.alpha"),
            getprop("gsm.operator.alpha"),
            fieldFrom(siminfo, "display_name", "carrier_name")
        )
        val country = firstNonEmpty(
            getprop("gsm.sim.operator.iso-country"),
            getprop("gsm.operator.iso-country")
        )
        val simState = getprop("gsm.sim.state")

        return listOfNotEmpty(
            IdentifierValue("tel.imei", "IMEI", imei ?: ""),
            IdentifierValue("tel.subscriber_id", "IMSI", imsi ?: ""),
            IdentifierValue("tel.sim_serial", "SIM serial / ICCID", iccid ?: ""),
            IdentifierValue("tel.line1_number", "Номер телефона", number ?: ""),
            IdentifierValue("tel.sim_operator", "MCC+MNC (SIM)", operator ?: ""),
            IdentifierValue("tel.sim_operator_name", "Оператор", operatorName ?: ""),
            IdentifierValue("tel.sim_country", "Страна SIM", country ?: ""),
            IdentifierValue("prop.gsm.sim.state", "SIM state", simState)
        )
    }

    fun readLocation(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys location 2>/dev/null", timeoutSec = 12)
        val gnss = RootShell.execAndRead("dumpsys gnss 2>/dev/null | head -c 4000", timeoutSec = 8)
        val values = linkedMapOf<String, IdentifierValue>()

        val regex = Regex(
            """(?i)last (?:coarse )?location=Location\[(\w+)\s+(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)([^\]]*)]"""
        )
        for (match in regex.findAll(dump)) {
            val provider = match.groupValues[1]
            val lat = match.groupValues[2]
            val lon = match.groupValues[3]
            val extra = match.groupValues[4]
            val acc = Regex("hAcc=([^\\s\\]]+)").find(extra)?.groupValues?.get(1)
            val key = "location.$provider"
            if (values.containsKey(key)) continue
            values[key] = IdentifierValue(
                key,
                "Координаты ($provider)",
                buildString {
                    append("lat=$lat lon=$lon")
                    if (acc != null) append(" accuracy=$acc")
                }
            )
        }

        if (values.isEmpty()) {
            Regex("""Location\[(\w+)\s+(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)""")
                .findAll(dump)
                .forEach { match ->
                    val key = "location.${match.groupValues[1]}"
                    values.putIfAbsent(
                        key,
                        IdentifierValue(
                            key,
                            "Координаты (${match.groupValues[1]})",
                            "lat=${match.groupValues[2]} lon=${match.groupValues[3]}"
                        )
                    )
                }
        }

        val started = Regex("(?i)mStarted\\s*=\\s*(true|false)").find(gnss)?.groupValues?.get(1)
        val interval = Regex("(?i)(?:mFixInterval|interval)\\s*=\\s*(\\d+)").find(gnss)?.groupValues?.get(1)
        if (started != null || interval != null) {
            values["location.hal"] = IdentifierValue(
                "location.hal",
                "GNSS HAL",
                listOfNotNull(started?.let { "started=$it" }, interval?.let { "interval=${it}ms" }).joinToString(" ")
            )
        }

        return values.values.toList()
    }

    private fun readWifi(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys wifi 2>/dev/null | head -c 4000", timeoutSec = 8)
        val mac = firstNonEmpty(
            fieldFrom(dump, "mWifiInfo", "MacAddress", "MAC"),
            getprop("ro.boot.wifimacaddr"),
            RootShell.execAndRead("cat /sys/class/net/wlan0/address 2>/dev/null").trim()
        )
        val ssid = fieldFrom(dump, "SSID", "mWifiSsid")
        return listOfNotEmpty(
            IdentifierValue("wifi.mac", "Wi‑Fi MAC", mac ?: ""),
            IdentifierValue("wifi.ssid", "SSID", ssid ?: "")
        )
    }

    private fun readBluetooth(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys bluetooth_manager 2>/dev/null | head -c 3000", timeoutSec = 8)
        val mac = firstNonEmpty(
            settingsGet("secure", "bluetooth_address"),
            fieldFrom(dump, "address", "mAddress"),
            getprop("ro.boot.btmacaddr")
        )
        val name = firstNonEmpty(
            settingsGet("secure", "bluetooth_name"),
            fieldFrom(dump, "name", "mName")
        )
        return listOfNotEmpty(
            IdentifierValue("bt.local_mac", "Bluetooth MAC", mac ?: ""),
            IdentifierValue("bt.local_name", "Bluetooth name", name ?: "")
        )
    }

    private fun readCamera(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys media.camera 2>/dev/null | head -c 8000", timeoutSec = 8)
        val provider = RootShell.execAndRead("dumpsys media.camera.provider 2>/dev/null | head -c 4000", timeoutSec = 8)
        val ids = Regex("(?i)Camera\\s+(\\d+|ID\\s*[=:]\\s*\\S+)").findAll(dump + provider)
            .map { it.value }.distinct().take(8).joinToString(", ")
        val clients = dump.lineSequence().filter {
            it.contains("client", ignoreCase = true) || it.contains("active", ignoreCase = true) ||
                it.contains("device", ignoreCase = true)
        }.take(6).joinToString(" | ")
        return listOfNotEmpty(
            IdentifierValue("camera.ids", "Камеры", ids.ifBlank { "список недоступен" }),
            IdentifierValue("camera.state", "Состояние", clients.ifBlank { dump.lines().firstOrNull { it.isNotBlank() } ?: "" })
        )
    }

    private fun readMicrophone(): List<IdentifierValue> {
        val flinger = RootShell.execAndRead("dumpsys media.audio_flinger 2>/dev/null | head -c 8000", timeoutSec = 8)
        val audio = RootShell.execAndRead("dumpsys audio 2>/dev/null | head -c 4000", timeoutSec = 8)
        val recording = (flinger + "\n" + audio).lineSequence().filter {
            it.contains("Record", ignoreCase = true) || it.contains("Input", ignoreCase = true) ||
                it.contains("source", ignoreCase = true) || it.contains("session", ignoreCase = true)
        }.take(8).joinToString("\n")
        val mode = fieldFrom(audio, "mMode", "mode")
        return listOfNotEmpty(
            IdentifierValue("mic.mode", "Audio mode", mode ?: ""),
            IdentifierValue("mic.tracks", "Запись / входы", recording.ifBlank { "(нет активной записи в dumpsys)" })
        )
    }

    private fun readContacts(): List<IdentifierValue> {
        val count = RootShell.execAndRead(
            "content query --uri content://com.android.contacts/contacts --projection _id 2>/dev/null | wc -l",
            timeoutSec = 8
        ).trim()
        val sample = RootShell.execAndRead(
            "content query --uri content://com.android.contacts/contacts --projection display_name:has_phone_number 2>/dev/null | head -n 5",
            timeoutSec = 8
        ).trim()
        return listOfNotEmpty(
            IdentifierValue("contacts.count", "Контактов (строк)", count),
            IdentifierValue("contacts.sample", "Пример", sample.take(400))
        )
    }

    private fun readSms(): List<IdentifierValue> {
        val inbox = RootShell.execAndRead(
            "content query --uri content://sms/inbox --projection address:date:body 2>/dev/null | head -n 4",
            timeoutSec = 8
        ).trim()
        val count = RootShell.execAndRead(
            "content query --uri content://sms --projection _id 2>/dev/null | wc -l",
            timeoutSec = 8
        ).trim()
        return listOfNotEmpty(
            IdentifierValue("sms.count", "SMS (строк)", count),
            IdentifierValue("sms.inbox", "Последние входящие", inbox.take(500).ifBlank { "(пусто / нет доступа)" })
        )
    }

    private fun readCalendar(): List<IdentifierValue> {
        val events = RootShell.execAndRead(
            "content query --uri content://com.android.calendar/events --projection title:dtstart 2>/dev/null | head -n 5",
            timeoutSec = 8
        ).trim()
        return listOfNotEmpty(
            IdentifierValue("calendar.events", "События календаря", events.take(500).ifBlank { "(пусто / нет доступа)" })
        )
    }

    private fun readClipboard(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys clipboard 2>/dev/null | head -c 3000", timeoutSec = 6)
        val text = dump.lineSequence()
            .filter { it.contains("text", ignoreCase = true) || it.contains("clip", ignoreCase = true) || it.contains("mPrimary") }
            .take(8)
            .joinToString("\n")
        return listOfNotEmpty(
            IdentifierValue("clipboard.primary", "Буфер обмена", text.ifBlank { dump.take(300).ifBlank { "(пусто)" } })
        )
    }

    private fun readSensors(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys sensorservice 2>/dev/null | head -c 8000", timeoutSec = 8)
        val active = dump.lineSequence().filter {
            it.contains("accelerometer", ignoreCase = true) ||
                it.contains("gyroscope", ignoreCase = true) ||
                it.contains("magnetometer", ignoreCase = true) ||
                it.contains("Connection", ignoreCase = true) ||
                it.contains("active", ignoreCase = true)
        }.take(10).joinToString("\n")
        return listOfNotEmpty(
            IdentifierValue("sensors.active", "Активные сенсоры", active.ifBlank { dump.lines().take(8).joinToString("\n") })
        )
    }

    private fun readNetwork(packageName: String): List<IdentifierValue> {
        val wifi = readWifi()
        val conn = RootShell.execAndRead("dumpsys connectivity 2>/dev/null | head -c 4000", timeoutSec = 8)
        val active = conn.lineSequence().filter {
            it.contains("NetworkAgentInfo", ignoreCase = true) ||
                it.contains("CONNECTED", ignoreCase = true) ||
                it.contains("extra:", ignoreCase = true)
        }.take(6).joinToString(" | ")
        val pcap = RootShell.execAndRead(
            "ls -l ${MonitorPaths.PCAP}* 2>/dev/null | head -n 6",
            timeoutSec = 5
        ).trim()
        val dns = RootShell.execAndRead(
            "tcpdump -nn -r ${MonitorPaths.PCAP} -c 12 port 53 2>/dev/null | tail -n 12",
            timeoutSec = 8
        ).trim()
        val ct = RootShell.execAndRead(
            "cat /proc/net/nf_conntrack 2>/dev/null | grep -F '$packageName' | head -n 8",
            timeoutSec = 5
        ).trim()
        return wifi + listOfNotEmpty(
            IdentifierValue("net.active", "Активная сеть", active),
            IdentifierValue("net.pcap", "pcap (заголовки)", pcap.ifBlank { MonitorPaths.PCAP }),
            IdentifierValue("net.dns", "DNS из pcap", dns),
            IdentifierValue("net.conntrack", "conntrack", ct)
        )
    }

    private fun readStorage(packageName: String): List<IdentifierValue> {
        val db = RootShell.execAndRead("dumpsys dbinfo $packageName 2>/dev/null | head -c 3000", timeoutSec = 8)
        val media = RootShell.execAndRead(
            "content query --uri content://media/external/images/media --projection _id 2>/dev/null | wc -l",
            timeoutSec = 8
        ).trim()
        return listOfNotEmpty(
            IdentifierValue("storage.images", "Изображений в MediaStore", media),
            IdentifierValue("storage.db", "БД пакета", db.lines().take(8).joinToString("\n"))
        )
    }

    private fun readPermission(event: CaptureEvent): List<IdentifierValue> {
        val op = event.permission ?: event.action
        val appops = RootShell.execAndRead("dumpsys appops ${event.targetPackage} 2>/dev/null | head -c 8000", timeoutSec = 10)
        val block = Regex("""$op[\s\S]{0,350}""").find(appops)?.value
            ?: appops.lineSequence().filter { it.contains(op, ignoreCase = true) }.take(6).joinToString("\n")
        val granted = RootShell.execAndRead(
            "dumpsys package ${event.targetPackage} 2>/dev/null | grep -A1 '$op' | head -n 4",
            timeoutSec = 8
        ).trim()
        return listOfNotEmpty(
            IdentifierValue("perm.op", "AppOps $op", block.take(400)),
            IdentifierValue("perm.grant", "Package $op", granted)
        )
    }

    private fun readSystemApi(packageName: String): List<IdentifierValue> {
        val svc = RootShell.execAndRead(
            "dumpsys activity services $packageName 2>/dev/null | head -c 4000",
            timeoutSec = 8
        )
        val snippet = svc.lineSequence().filter {
            it.contains("ServiceRecord") || it.contains("isForeground") || it.contains("app=")
        }.take(8).joinToString("\n")
        return listOfNotEmpty(
            IdentifierValue("sys.services", "Сервисы пакета", snippet.ifBlank { svc.take(300) })
        )
    }

    private fun readDrm(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys media.drm 2>/dev/null | head -c 2000", timeoutSec = 6)
        return listOfNotEmpty(IdentifierValue("drm.widevine_id", "MediaDrm", dump.take(300)))
    }

    private fun readAccounts(): List<IdentifierValue> {
        val dump = RootShell.execAndRead("dumpsys account 2>/dev/null | head -c 3000", timeoutSec = 6)
        val lines = dump.lineSequence().filter {
            it.contains("Account ", ignoreCase = true) || it.contains("type=", ignoreCase = true)
        }.take(8).joinToString("\n")
        return listOfNotEmpty(IdentifierValue("account.list", "Аккаунты", lines.ifBlank { dump.take(300) }))
    }

    private fun readFromCaptured(event: CaptureEvent): List<IdentifierValue> {
        val captured = event.responseDetails?.takeIf { it.isNotBlank() && !it.startsWith("FD=") }
            ?: event.requestDetails
            ?: return emptyList()
        return listOf(IdentifierValue(event.action, event.action, captured))
    }

    private fun getprop(key: String): String {
        return RootShell.execAndRead("getprop $key", timeoutSec = 5).trim()
    }

    private fun settingsGet(namespace: String, key: String): String {
        return RootShell.execAndRead("settings get $namespace $key", timeoutSec = 6).trim()
            .let { if (it == "null" || it.isBlank()) "" else it }
    }

    private fun querySettings(namespace: String, key: String): String {
        val out = RootShell.execAndRead(
            "content query --uri content://settings/$namespace --where \"name='$key'\" 2>/dev/null",
            timeoutSec = 6
        )
        return fieldFrom(out, "value") ?: ""
    }

    private fun serviceCallString(service: String, code: Int): String? {
        val raw = RootShell.execAndRead(
            "service call $service $code s16 com.android.shell 2>/dev/null",
            timeoutSec = 6
        )
        return parseParcelString(raw)
    }

    internal fun parseParcelString(output: String): String? {
        if (output.isBlank()) return null
        if (output.contains("Exception", ignoreCase = true)) return null
        if (output.contains("Unknown transaction", ignoreCase = true)) return null

        val words = Regex("(?i)0x[0-9a-f]+:\\s+((?:[0-9a-f]{8}\\s*)+)")
            .findAll(output)
            .flatMap { match -> match.groupValues[1].trim().split(Regex("\\s+")) }
            .filter { it.length == 8 }
            .toList()

        if (words.size >= 2) {
            val length = words[1].chunked(2).reversed().joinToString("").toIntOrNull(16)
            if (length != null && length in 1..256) {
                val bytes = words.drop(2).flatMap { word -> word.chunked(2).reversed() }
                val chars = buildString {
                    for (i in 0 until length) {
                        val lo = bytes.getOrNull(i * 2)?.toIntOrNull(16) ?: break
                        val hi = bytes.getOrNull(i * 2 + 1)?.toIntOrNull(16) ?: 0
                        append((lo or (hi shl 8)).toChar())
                    }
                }.trim { it <= ' ' || it == '\u0000' }
                if (chars.isNotBlank()) return chars
            }
        }

        val quoted = Regex("'([^']*)'").findAll(output).joinToString("") { it.groupValues[1] }
        val cleaned = quoted.dropWhile { it == '.' || it == ' ' }.filter { it != '.' && it != ' ' }
        return cleaned.takeIf { it.length >= 4 }
    }

    private fun fieldFrom(text: String, vararg names: String): String? {
        if (text.isBlank()) return null
        for (name in names) {
            Regex(
                """(?i)(?:^|[\s,;])$name\s*[=:]\s*["']?([^,"'\n\r]+)["']?"""
            ).find(text)?.groupValues?.getOrNull(1)?.trim()
                ?.takeIf { it.isNotBlank() && it != "null" && it != "unknown" }
                ?.let { return it }
        }
        return null
    }

    private fun firstNonEmpty(vararg values: String?): String? {
        return values.firstOrNull { !it.isNullOrBlank() && it != "null" }
    }

    private fun listOfNotEmpty(vararg values: IdentifierValue): List<IdentifierValue> {
        return values.filter { it.value.isNotBlank() }
    }
}
