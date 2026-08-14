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
        val id = event.identifierName
        val values = when {
            id == "net.dns" || event.action.equals("DNS", ignoreCase = true) -> readDnsReplay(event)
            id == "net.http" || id == "net.https" || id == "net.sni" || id == "net.http2" -> readHttpReplay(event)
            id == "net.vpn" || id == "net.proxy" || id == "net.user_ca" || id == "net.pin_fail" ->
                readNetworkEnv(event)
            id?.startsWith("contacts.") == true || id == "cp.contacts" -> readContacts()
            id?.startsWith("sms.") == true || id == "cp.sms" || id?.startsWith("mms.") == true -> readSms()
            id?.startsWith("calendar.") == true || id == "cp.calendar" -> readCalendar()
            id?.startsWith("camera.") == true -> readCamera()
            id?.startsWith("mic.") == true -> readMicrophone()
            id?.startsWith("sensor.") == true || id == "hw.sensor_list" -> readSensors()
            id?.startsWith("nearby.") == true -> readBluetooth() + readFromCaptured(event)
            id?.startsWith("clipboard.") == true -> readClipboard()
            id?.startsWith("fcm.") == true || id?.startsWith("cred.") == true ||
                id?.startsWith("play.") == true ||
                id?.startsWith("ad.") == true || id?.startsWith("oem.") == true ||
                id?.startsWith("fido.") == true || id == "health.connect" ||
                id?.startsWith("tel.eid") == true || id == "install.source" ||
                id == "install.referrer" -> readFromCaptured(event)
            id?.startsWith("pkg.") == true || id?.startsWith("perm.") == true ->
                readSystemApi(event.targetPackage) + readFromCaptured(event)
            id?.startsWith("browser.") == true || id == "webview.ua" || id == "hw.webview_pkg" ->
                readBrowser(event) + readFromCaptured(event)
            id?.startsWith("fraud.") == true ->
                readFraudFingerprint(event) + readFromCaptured(event)
            id?.startsWith("settings.") == true -> {
                val def = IdentifierCatalog.findById(id)
                listOfNotNull(def?.let { readDefinition(it) }) + readFromCaptured(event)
            }
            id?.startsWith("tel.") == true || id?.startsWith("sub.") == true ->
                readTelephonyReplay(event)
            event.category == AccessCategory.LOCATION -> readLocation()
            event.category == AccessCategory.TELEPHONY -> readTelephonyReplay(event)
            event.category == AccessCategory.CAMERA -> readCamera()
            event.category == AccessCategory.MICROPHONE -> readMicrophone()
            event.category == AccessCategory.CONTACTS -> readContacts()
            event.category == AccessCategory.SMS -> readSms()
            event.category == AccessCategory.CALENDAR -> readCalendar()
            event.category == AccessCategory.CLIPBOARD -> readClipboard()
            event.category == AccessCategory.SENSOR -> readSensors()
            event.category == AccessCategory.BLUETOOTH -> readBluetooth()
            event.category == AccessCategory.NETWORK -> readDnsReplay(event).ifEmpty { readHttpReplay(event) }
            event.category == AccessCategory.STORAGE -> readStorage(event.targetPackage)
            event.category == AccessCategory.PERMISSION -> readPermission(event)
            event.category == AccessCategory.IDENTIFIER -> readIdentifier(event)
            event.category == AccessCategory.SYSTEM_API -> readSystemApi(event.targetPackage)
            event.category == AccessCategory.SECURITY -> readSecurity(event)
            else -> readFromCaptured(event)
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
            IdentifierGroup.ACCOUNT, IdentifierGroup.IDENTITY -> readAccounts()
            IdentifierGroup.ROOT, IdentifierGroup.ATTESTATION -> readSecurity(event)
            IdentifierGroup.PERSONAL -> readContacts() + readSms() + readCalendar()
            IdentifierGroup.HARDWARE -> readCamera() + readMicrophone() + readSensors() + readClipboard()
            IdentifierGroup.FRAUD -> readFraudFingerprint(event)
            IdentifierGroup.BROWSER -> readBrowser(event)
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
            def.id == "settings.adb" -> settingsGet("global", "adb_enabled")
            def.id == "settings.development" -> settingsGet("global", "development_settings_enabled")
            def.id == "settings.animation" -> listOf(
                "transition=${settingsGet("global", "transition_animation_scale")}",
                "window=${settingsGet("global", "window_animation_scale")}",
                "animator=${settingsGet("global", "animator_duration_scale")}"
            ).joinToString(" ")
            def.id == "settings.data_roaming" -> settingsGet("global", "data_roaming")
            def.id == "settings.touch_exploration" -> settingsGet("secure", "touch_exploration_enabled")
            def.id == "settings.alarm" -> settingsGet("system", "alarm_alert")
            def.id == "settings.date_format" -> settingsGet("system", "date_format")
            def.id == "settings.font_scale" -> settingsGet("system", "font_scale")
            def.id == "settings.screen_off" -> settingsGet("system", "screen_off_timeout")
            def.id == "settings.time_12_24" -> settingsGet("system", "time_12_24")
            def.id == "settings.brightness" -> settingsGet("system", "screen_brightness")
            def.id == "settings.boot_count" -> settingsGet("global", "boot_count")
            def.id == "settings.airplane" -> settingsGet("global", "airplane_mode_on")
            def.id == "settings.auto_time" ->
                "auto_time=${settingsGet("global", "auto_time")} zone=${settingsGet("global", "auto_time_zone")}"
            def.id == "settings.private_dns" ->
                "${settingsGet("global", "private_dns_mode")} ${settingsGet("global", "private_dns_specifier")}"
            def.id == "settings.unknown_sources" -> settingsGet("secure", "install_non_market_apps")
            def.id == "settings.stay_on" -> settingsGet("global", "stay_on_while_plugged_in")
            def.id == "settings.end_button" -> settingsGet("system", "end_button_behavior")
            def.id == "settings.accessibility" -> settingsGet("secure", "enabled_accessibility_services")
            def.id == "settings.input_method" -> settingsGet("secure", "default_input_method")
            def.id == "settings.mock_location" -> settingsGet("secure", "mock_location")
            def.id == "attest.vbmeta" -> getprop("ro.boot.vbmeta.digest")
            def.id == "attest.flash_locked" -> getprop("ro.boot.flash.locked")
            def.id == "attest.warranty" -> getprop("ro.boot.warranty_bit")
            def.id == "fraud.harmony" -> firstNonEmpty(
                getprop("ro.build.version.emui"),
                getprop("hw_sc.build.os.apiversion"),
                getprop("ro.build.version.harmony")
            )
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
        AccessCategory.SECURITY -> IdentifierGroup.ROOT
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
        val adb = settingsGet("global", "adb_enabled")
        val dev = settingsGet("global", "development_settings_enabled")
        val boot = settingsGet("global", "boot_count")
        val brightness = settingsGet("system", "screen_brightness")
        val ime = settingsGet("secure", "default_input_method")
        return listOfNotNull(
            androidId?.let { IdentifierValue("settings.android_id", "Android ID (SSAID)", it) },
            deviceName?.let { IdentifierValue("settings.device_name", "Имя устройства", it) },
            adb.takeIf { it.isNotBlank() }?.let { IdentifierValue("settings.adb", "ADB", it) },
            dev.takeIf { it.isNotBlank() }?.let { IdentifierValue("settings.development", "Developer options", it) },
            boot.takeIf { it.isNotBlank() }?.let { IdentifierValue("settings.boot_count", "Boot count", it) },
            brightness.takeIf { it.isNotBlank() }?.let { IdentifierValue("settings.brightness", "Яркость", it) },
            ime.takeIf { it.isNotBlank() }?.let { IdentifierValue("settings.input_method", "IME", it) }
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

    private fun extractHost(event: CaptureEvent): String? {
        val blob = listOfNotNull(event.requestDetails, event.action, event.responseDetails, event.rawData)
            .joinToString("\n")
        Regex("""(?i)(?:A\?|AAAA\?)\s+([A-Za-z0-9._-]+\.[A-Za-z]{2,})""")
            .find(blob)?.groupValues?.get(1)?.let { return it.trim('.') }
        Regex("""(?i)https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})""")
            .find(blob)?.groupValues?.get(1)?.let { return it }
        event.requestDetails?.trim()
            ?.takeIf { it.contains('.') && !it.contains(' ') && it.length < 128 }
            ?.let { return it.trim('.') }
        return Regex("""([A-Za-z0-9._-]+\.[A-Za-z]{2,})""").find(event.requestDetails.orEmpty())
            ?.groupValues?.get(1)
    }

    private fun readDnsReplay(event: CaptureEvent): List<IdentifierValue> {
        val host = extractHost(event) ?: return readFromCaptured(event)
        val resolver = RootShell.execAndRead(
            "dumpsys dnsresolver 2>/dev/null | grep -i -F ${RootShell.shellQuote(host)} | head -n 8",
            timeoutSec = 8
        ).trim()
        val hosts = firstNonEmpty(
            RootShell.execAndRead("getent hosts $host 2>/dev/null", timeoutSec = 6).trim(),
            RootShell.execAndRead("nslookup $host 2>/dev/null | head -n 12", timeoutSec = 8).trim(),
            RootShell.execAndRead("ping -c 1 -W 2 $host 2>/dev/null | head -n 4", timeoutSec = 6).trim()
        )
        return listOfNotEmpty(
            IdentifierValue("net.dns.query", "Запрос", "A? $host"),
            IdentifierValue("net.dns.replay", "Повтор DNS", hosts ?: resolver),
            IdentifierValue("net.dns.resolver", "dnsresolver", resolver),
            IdentifierValue("net.dns.captured", "Перехват", event.responseDetails.orEmpty())
        )
    }

    private fun readHttpReplay(event: CaptureEvent): List<IdentifierValue> {
        val host = extractHost(event)
        val url = event.requestDetails?.takeIf { it.contains('/') || it.startsWith("http") } ?: host
        val dns = host?.let { h ->
            firstNonEmpty(
                RootShell.execAndRead("getent hosts $h 2>/dev/null", timeoutSec = 6).trim(),
                RootShell.execAndRead("dumpsys dnsresolver 2>/dev/null | grep -i -F ${RootShell.shellQuote(h)} | head -n 6", timeoutSec = 6).trim()
            )
        }
        return listOfNotEmpty(
            IdentifierValue("net.http.query", "Запрос", url ?: event.action),
            IdentifierValue("net.http.dns", "Повтор (DNS хоста)", dns ?: ""),
            IdentifierValue("net.http.captured", "Перехват", event.responseDetails.orEmpty())
        )
    }

    private fun readTelephonyReplay(event: CaptureEvent): List<IdentifierValue> {
        val all = readTelephony()
        val wanted = event.identifierName
        val primary = wanted?.let { id -> all.firstOrNull { it.id == id } }
            ?: event.identifierName?.let { IdentifierCatalog.findById(it) }?.let { readDefinition(it) }
        return buildList {
            if (primary != null) add(primary)
            event.requestDetails?.let { add(IdentifierValue("tel.request", "Оригинал", it)) }
            event.responseDetails?.takeIf { it.isNotBlank() }?.let {
                add(IdentifierValue("tel.captured", "Перехват", it))
            }
            addAll(all.filter { it.id != primary?.id })
        }
    }

    private fun readNetworkEnv(event: CaptureEvent): List<IdentifierValue> {
        val vpn = RootShell.execAndRead(
            "dumpsys connectivity 2>/dev/null | grep -i -E 'TRANSPORT_VPN|type: VPN|tun0' | head -n 10",
            timeoutSec = 8
        ).trim()
        val proxy = RootShell.execAndRead(
            "settings get global http_proxy; getprop http.proxyHost",
            timeoutSec = 6
        ).trim()
        val cas = RootShell.execAndRead(
            "ls /data/misc/user/0/cacerts-added /data/misc/keychain/cacerts-added 2>/dev/null | head -n 8",
            timeoutSec = 6
        ).trim()
        return listOfNotEmpty(
            IdentifierValue("net.vpn", "VPN", vpn),
            IdentifierValue("net.proxy", "proxy", proxy),
            IdentifierValue("net.user_ca", "user CA", cas),
            IdentifierValue("net.captured", "перехват", event.responseDetails.orEmpty())
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
        val https = RootShell.execAndRead(
            "grep net.https ${com.deviceinfo.trafficmonitor.frida.FridaInstaller.EVENTS_PATH} 2>/dev/null | tail -n 8",
            timeoutSec = 5
        ).trim()
        return wifi + listOfNotEmpty(
            IdentifierValue("net.active", "Активная сеть", active),
            IdentifierValue("net.pcap", "pcap (заголовки)", pcap.ifBlank { MonitorPaths.PCAP }),
            IdentifierValue("net.dns", "DNS из pcap", dns),
            IdentifierValue("net.conntrack", "conntrack", ct),
            IdentifierValue("net.https", "HTTPS plaintext", https)
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

    private fun readSecurity(event: CaptureEvent): List<IdentifierValue> {
        val id = event.identifierName.orEmpty()
        return when {
            id == "root.selinux" || event.action.contains("getenforce", ignoreCase = true) ->
                listOfNotEmpty(IdentifierValue("root.selinux", "getenforce", RootShell.execAndRead("getenforce", timeoutSec = 5).trim()))
            id == "root.adb" -> listOfNotEmpty(
                IdentifierValue("root.adb", "adb_enabled", settingsGet("global", "adb_enabled")),
                IdentifierValue("root.dev", "development_settings", settingsGet("global", "development_settings_enabled"))
            )
            id == "root.lsposed" || id == "root.xposed" || id == "root.lspatch" -> listOfNotEmpty(
                IdentifierValue("root.lsposed", "lspd dir", RootShell.execAndRead("ls -ld /data/adb/lspd /data/adb/modules/zygisk_lsposed /data/adb/modules/riru_lsposed 2>&1 | head -n 8", timeoutSec = 6).take(300)),
                IdentifierValue("root.xposedjar", "XposedBridge.jar", RootShell.execAndRead("ls -l /system/framework/XposedBridge.jar 2>&1", timeoutSec = 5).trim())
            )
            id == "root.inject" || id == "root.threads" || id == "root.ports" || id == "root.dlsym" || id == "root.stack" -> {
                val pid = event.processId?.takeIf { it > 0 } ?: RootShell.findPid(event.targetPackage)
                if (pid == null) {
                    listOfNotEmpty(IdentifierValue("root.maps", "maps hook/inject", "нет PID цели"))
                } else {
                    listOfNotEmpty(
                        IdentifierValue(
                            "root.maps",
                            "maps hook/inject",
                            RootShell.execAndRead(
                                "grep -E -i 'frida|lsposed|lspd|xposed|memfd|rwxp' /proc/$pid/maps 2>/dev/null | head -n 8",
                                timeoutSec = 6
                            ).take(400)
                        ),
                        IdentifierValue(
                            "root.tracer",
                            "TracerPid",
                            RootShell.execAndRead("grep TracerPid /proc/$pid/status", timeoutSec = 5).trim()
                        )
                    )
                }
            }
            id == "root.emulator" -> listOfNotEmpty(
                IdentifierValue("root.qemu", "ro.kernel.qemu", getprop("ro.kernel.qemu")),
                IdentifierValue("root.hardware", "ro.hardware", getprop("ro.hardware")),
                IdentifierValue("root.fingerprint", "fingerprint", getprop("ro.build.fingerprint"))
            )
            id == "root.hide" -> listOfNotEmpty(
                IdentifierValue("root.hide", "DenyList/Shamiko", RootShell.execAndRead(
                    "(/data/adb/magisk/magisk --denylist ls 2>/dev/null || magisk --denylist ls 2>/dev/null || true) | head -n 20; " +
                        "ls -ld /data/adb/modules/zygisk_shamiko /data/adb/modules/shamiko 2>&1 | head -n 6",
                    timeoutSec = 8
                ).take(400))
            )
            id == "root.isolated" -> {
                val pids = RootShell.findAllPids(event.targetPackage)
                val text = if (pids.isEmpty()) {
                    "процесс цели не найден"
                } else {
                    pids.take(12).joinToString("\n") { pid ->
                        val cmd = RootShell.execAndRead(
                            "tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null",
                            timeoutSec = 3
                        ).trim()
                        val st = RootShell.execAndRead(
                            "grep -E 'NSpid|NoNewPrivs|Seccomp' /proc/$pid/status 2>/dev/null | tr '\\n' ' '",
                            timeoutSec = 3
                        ).trim()
                        "$pid $cmd $st"
                    }
                }
                listOfNotEmpty(IdentifierValue("root.isolated", "isolated", text.take(400)))
            }
            id == "root.text" || id == "root.svc" || id == "root.decision" || id == "root.talsec" ->
                readFromCaptured(event)
            id == "ent.integrity" || id == "ent.safetynet" || id == "ent.verdict" || id.startsWith("attest.") -> listOfNotEmpty(
                IdentifierValue("attest.vb", "verifiedbootstate", getprop("ro.boot.verifiedbootstate")),
                IdentifierValue("attest.lock", "flash.locked", getprop("ro.boot.flash.locked")),
                IdentifierValue("attest.vbmeta", "vbmeta.device_state", getprop("ro.boot.vbmeta.device_state")),
                IdentifierValue("ent.verdict", "перехват", event.responseDetails.orEmpty())
            )
            else -> readRootSnapshot()
        }.ifEmpty { readRootSnapshot() } + readFromCaptured(event)
    }

    private fun readRootSnapshot(): List<IdentifierValue> {
        val su = RootShell.execAndRead(
            "ls -l /system/bin/su /system/xbin/su /sbin/su /su/bin/su /data/adb/magisk /sbin/.magisk 2>&1 | head -n 12",
            timeoutSec = 6
        )
        return listOfNotEmpty(
            IdentifierValue("root.secure", "ro.secure", getprop("ro.secure")),
            IdentifierValue("root.debuggable", "ro.debuggable", getprop("ro.debuggable")),
            IdentifierValue("root.tags", "ro.build.tags", getprop("ro.build.tags")),
            IdentifierValue("root.vb", "verifiedbootstate", getprop("ro.boot.verifiedbootstate")),
            IdentifierValue("root.selinux", "getenforce", RootShell.execAndRead("getenforce", timeoutSec = 5).trim()),
            IdentifierValue("root.paths", "su/magisk paths", su.take(400))
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

    private fun readFraudFingerprint(event: CaptureEvent): List<IdentifierValue> {
        val id = event.identifierName.orEmpty()
        val pkg = event.targetPackage
        val fromDef = IdentifierCatalog.findById(id)?.let { readDefinition(it) }
        val clone = RootShell.execAndRead(
            "ls -ld /data/user/0/$pkg /data/user/999/$pkg /data/user/10/$pkg 2>/dev/null | head -n 6",
            timeoutSec = 6
        ).trim()
        val users = RootShell.execAndRead(
            "dumpsys user 2>/dev/null | grep -E 'UserInfo|managedProfile|flags=' | head -n 8",
            timeoutSec = 6
        ).trim()
        val dual = RootShell.execAndRead(
            "pm list packages 2>/dev/null | grep -E 'parallel|dualspace|dualaid|multiapp|da.daagent|island|shelter' | head -n 8",
            timeoutSec = 8
        ).trim()
        val vbmeta = getprop("ro.boot.vbmeta.digest")
        val harmony = firstNonEmpty(
            getprop("ro.build.version.emui"),
            getprop("hw_sc.build.os.apiversion"),
            getprop("ro.build.version.harmony")
        )
        val a11y = settingsGet("secure", "enabled_accessibility_services")
        return buildList {
            fromDef?.let { add(it) }
            if (id.startsWith("fraud.") || id.startsWith("settings.")) {
                addAll(
                    listOfNotEmpty(
                        IdentifierValue("fraud.clone", "data dirs", clone.take(300)),
                        IdentifierValue("fraud.work_profile", "users", users.take(300)),
                        IdentifierValue("fraud.dual_app", "dual/clone pkgs", dual.take(300)),
                        IdentifierValue("attest.vbmeta", "vbmeta", vbmeta),
                        IdentifierValue("fraud.harmony", "Harmony/EMUI", harmony.orEmpty()),
                        IdentifierValue("settings.accessibility", "a11y", a11y)
                    )
                )
            }
            addAll(readFromCaptured(event))
        }.distinctBy { it.id + it.value }
    }

    private fun readBrowser(event: CaptureEvent): List<IdentifierValue> {
        val pkg = event.targetPackage
        val wvPkg = RootShell.execAndRead(
            "dumpsys webviewupdate 2>/dev/null | head -n 20",
            timeoutSec = 6
        ).trim()
        val ua = RootShell.execAndRead(
            "dumpsys package com.google.android.webview 2>/dev/null | grep -E 'versionName|versionCode' | head -n 4",
            timeoutSec = 6
        ).trim()
        val impl = firstNonEmpty(
            getprop("persist.sys.webview.provider"),
            getprop("ro.webview.provider")
        )
        return buildList {
            IdentifierCatalog.findById(event.identifierName.orEmpty())?.let { def ->
                readDefinition(def)?.let { add(it) }
            }
            addAll(
                listOfNotEmpty(
                    IdentifierValue("hw.webview_pkg", "WebView update", wvPkg.take(400)),
                    IdentifierValue("browser.default_ua", "WebView package", ua.take(200)),
                    IdentifierValue("browser.feature", "webview provider", impl.orEmpty())
                )
            )
            if (pkg.isNotBlank()) {
                val js = RootShell.execAndRead(
                    "dumpsys webviewupdate 2>/dev/null | grep -i -F ${RootShell.shellQuote(pkg)} | head -n 6",
                    timeoutSec = 6
                ).trim()
                if (js.isNotBlank()) add(IdentifierValue("net.webview", "webview mentions", js.take(200)))
            }
            addAll(readFromCaptured(event))
        }.distinctBy { it.id + it.value }
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
