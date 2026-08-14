package com.deviceinfo.trafficmonitor.identifiers

import com.deviceinfo.trafficmonitor.data.AccessCategory

/**
 * Каталог того, что целевое приложение может *запросить* (AOSP API 33–35).
 * Это не чекер root/ресурсов: каждая запись — API/путь/prop, который приложение читает.
 */
enum class IdentifierGroup(val label: String) {
    BUILD("Build / устройство"),
    OS_VERSION("Версия ОС"),
    SYSTEM_PROPERTY("System property (getprop)"),
    SETTINGS("Settings (Secure/Global/System)"),
    TELEPHONY("Telephony / SIM"),
    SUBSCRIPTION("Subscription / eSIM"),
    WIFI("Wi‑Fi"),
    BLUETOOTH("Bluetooth"),
    ADVERTISING("Рекламные / app ID"),
    DRM("DRM / Widevine"),
    INSTALL("Установка / пакет"),
    ACCOUNT("Аккаунты"),
    CONTENT_PROVIDER("ContentProvider"),
    PROC_SYS("/proc / /sys"),
    NETWORK("Сеть / IP"),
    ENTERPRISE("Enterprise / MDM"),
    OEM("OEM-специфичные"),
    ATTESTATION("Attestation / Integrity"),
    LOCATION("GPS / локация"),
    ROOT("Root / детект среды"),
    PERSONAL("Контакты / SMS / календарь"),
    HARDWARE("Камера / датчики / экран / NFC"),
    IDENTITY("Токены / credentials / FCM"),
    FRAUD("Антифрод / fingerprint"),
    BROWSER("Браузер / WebView / JS")
}

data class IdentifierDefinition(
    val id: String,
    val displayName: String,
    val group: IdentifierGroup,
    val api: String? = null,
    val systemProperty: String? = null,
    val filePath: String? = null,
    val logcatPatterns: List<Regex> = emptyList(),
    val stracePathPatterns: List<Regex> = emptyList(),
    val permission: String? = null,
    val description: String? = null
)

object IdentifierCatalog {

    val all: List<IdentifierDefinition> = buildList {
        addAll(buildIdentifiers())
        addAll(versionIdentifiers())
        addAll(systemPropertyIdentifiers())
        addAll(settingsIdentifiers())
        addAll(telephonyIdentifiers())
        addAll(subscriptionIdentifiers())
        addAll(wifiIdentifiers())
        addAll(bluetoothIdentifiers())
        addAll(advertisingIdentifiers())
        addAll(drmIdentifiers())
        addAll(installIdentifiers())
        addAll(accountIdentifiers())
        addAll(contentProviderIdentifiers())
        addAll(procSysIdentifiers())
        addAll(networkIdentifiers())
        addAll(enterpriseIdentifiers())
        addAll(oemIdentifiers())
        addAll(attestationIdentifiers())
        addAll(locationIdentifiers())
        addAll(rootIdentifiers())
        addAll(personalIdentifiers())
        addAll(hardwareIdentifiers())
        addAll(identityIdentifiers())
        addAll(packageQueryIdentifiers())
        addAll(extraRequestIdentifiers())
        addAll(fraudFingerprintIdentifiers())
        addAll(browserIdentifiers())
        addAll(missedSurfaceIdentifiers())
    }

    private val byId = all.associateBy { it.id }

    fun findById(id: String): IdentifierDefinition? = byId[id]

    private fun buildIdentifiers() = listOf(
        id("build.model", "Модель устройства", IdentifierGroup.BUILD, "Build.MODEL", "ro.product.model"),
        id("build.device", "Кодовое имя устройства", IdentifierGroup.BUILD, "Build.DEVICE", "ro.product.device"),
        id("build.manufacturer", "Производитель", IdentifierGroup.BUILD, "Build.MANUFACTURER", "ro.product.manufacturer"),
        id("build.brand", "Бренд", IdentifierGroup.BUILD, "Build.BRAND", "ro.product.brand"),
        id("build.product", "Имя продукта", IdentifierGroup.BUILD, "Build.PRODUCT", "ro.product.name"),
        id("build.hardware", "Аппаратная платформа", IdentifierGroup.BUILD, "Build.HARDWARE", "ro.hardware"),
        id("build.board", "Плата", IdentifierGroup.BUILD, "Build.BOARD", "ro.product.board"),
        id("build.bootloader", "Версия bootloader", IdentifierGroup.BUILD, "Build.BOOTLOADER", "ro.bootloader"),
        id("build.display", "Display ID сборки", IdentifierGroup.BUILD, "Build.DISPLAY", "ro.build.display.id"),
        id("build.fingerprint", "Build fingerprint", IdentifierGroup.BUILD, "Build.FINGERPRINT", "ro.build.fingerprint"),
        id("build.id", "Build ID", IdentifierGroup.BUILD, "Build.ID", "ro.build.id"),
        id("build.host", "Хост сборки", IdentifierGroup.BUILD, "Build.HOST", "ro.build.host"),
        id("build.tags", "Теги сборки", IdentifierGroup.BUILD, "Build.TAGS", "ro.build.tags"),
        id("build.type", "Тип сборки", IdentifierGroup.BUILD, "Build.TYPE", "ro.build.type"),
        id("build.user", "Пользователь сборки", IdentifierGroup.BUILD, "Build.USER", "ro.build.user"),
        id("build.soc_manufacturer", "Производитель SoC", IdentifierGroup.BUILD, "Build.SOC_MANUFACTURER", "ro.soc.manufacturer"),
        id("build.soc_model", "Модель SoC", IdentifierGroup.BUILD, "Build.SOC_MODEL", "ro.soc.model"),
        id("build.sku", "Hardware SKU", IdentifierGroup.BUILD, "Build.SKU", "ro.boot.hardware.sku"),
        id("build.odm_sku", "ODM SKU", IdentifierGroup.BUILD, "Build.ODM_SKU", "ro.boot.product.hardware.sku"),
        id("build.radio", "Версия radio/baseband", IdentifierGroup.BUILD, "Build.RADIO / getRadioVersion()", "gsm.version.baseband"),
        id("build.serial", "Серийный номер", IdentifierGroup.BUILD, "Build.getSerial()", "ro.serialno", perm = "READ_PRIVILEGED_PHONE_STATE"),
        id("build.time", "Время сборки", IdentifierGroup.BUILD, "Build.TIME", "ro.build.date.utc"),
        id("build.supported_abis", "Поддерживаемые ABI", IdentifierGroup.BUILD, "Build.SUPPORTED_ABIS", "ro.product.cpu.abilist"),
        id("build.supported_32_bit_abis", "32-bit ABI", IdentifierGroup.BUILD, "Build.SUPPORTED_32_BIT_ABIS", "ro.product.cpu.abilist32"),
        id("build.supported_64_bit_abis", "64-bit ABI", IdentifierGroup.BUILD, "Build.SUPPORTED_64_BIT_ABIS", "ro.product.cpu.abilist64"),
        id("build.is_emulator", "Флаг эмулятора", IdentifierGroup.BUILD, "Build.IS_EMULATOR", "ro.boot.qemu"),
        id("build.is_treble_enabled", "Treble enabled", IdentifierGroup.BUILD, "Build.IS_TREBLE_ENABLED", "ro.treble.enabled")
    )

    private fun versionIdentifiers() = listOf(
        id("version.sdk", "SDK версия", IdentifierGroup.OS_VERSION, "Build.VERSION.SDK_INT", "ro.build.version.sdk"),
        id("version.release", "Версия Android", IdentifierGroup.OS_VERSION, "Build.VERSION.RELEASE", "ro.build.version.release"),
        id("version.incremental", "Incremental версия", IdentifierGroup.OS_VERSION, "Build.VERSION.INCREMENTAL", "ro.build.version.incremental"),
        id("version.codename", "Кодовое имя версии", IdentifierGroup.OS_VERSION, "Build.VERSION.CODENAME", "ro.build.version.codename"),
        id("version.security_patch", "Security patch", IdentifierGroup.OS_VERSION, "Build.VERSION.SECURITY_PATCH", "ro.build.version.security_patch"),
        id("version.base_os", "Base OS", IdentifierGroup.OS_VERSION, "Build.VERSION.BASE_OS", "ro.build.version.base_os"),
        id("version.preview_sdk", "Preview SDK", IdentifierGroup.OS_VERSION, "Build.VERSION.PREVIEW_SDK_INT"),
        id("version.first_sdk", "First SDK shipped", IdentifierGroup.OS_VERSION, "Build.VERSION.FIRST_SDK_INT", "ro.product.first_api_level"),
        id("kernel.version", "Версия ядра", IdentifierGroup.PROC_SYS, file = "/proc/version", strace = listOf("/proc/version"))
    )

    private fun systemPropertyIdentifiers() = listOf(
        id("prop.serialno", "Серийный номер (prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.serialno", strace = listOf("ro\\.serialno", "ro\\.boot\\.serialno")),
        id("prop.boot.serialno", "Boot serial", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.boot.serialno"),
        id("prop.product.model", "Модель (prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.product.model"),
        id("prop.product.device", "Device (prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.product.device"),
        id("prop.product.brand", "Brand (prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.product.brand"),
        id("prop.product.manufacturer", "Manufacturer (prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.product.manufacturer"),
        id("prop.build.fingerprint", "Fingerprint (prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.build.fingerprint"),
        id("prop.hardware", "Hardware (prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.hardware"),
        id("prop.boot.hardware", "Boot hardware", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.boot.hardware"),
        id("prop.gsm.sim.state", "SIM state", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "gsm.sim.state"),
        id("prop.gsm.version.baseband", "Baseband version", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "gsm.version.baseband"),
        id("prop.persist.radio.imei", "IMEI (OEM prop)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "persist.radio.imei", strace = listOf("persist\\.radio\\.imei")),
        id("prop.persist.radio.factory_sn", "Factory serial (OEM)", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "persist.radio.factory_sn"),
        id("prop.net.hostname", "Hostname", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "net.hostname"),
        id("prop.boot.qemu", "QEMU/emulator", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.boot.qemu"),
        id("prop.gms.version", "GMS version", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.com.google.gmsversion"),
        id("prop.bootimage.fingerprint", "Bootimage fingerprint", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.bootimage.build.fingerprint", logcat = listOf("ro\\.bootimage\\.build\\.fingerprint"), strace = listOf("bootimage\\.build\\.fingerprint")),
        id("getprop.shell", "getprop (shell)", IdentifierGroup.SYSTEM_PROPERTY, api = "Runtime.exec(getprop)", logcat = listOf("getprop", "execve.*getprop", "__system_property_get", "Access denied finding property"))
    )

    private fun settingsIdentifiers() = listOf(
        id("settings.android_id", "Android ID (SSAID)", IdentifierGroup.SETTINGS, "Settings.Secure.ANDROID_ID", logcat = listOf("getAndroidId", "android_id", "SettingsProvider.*android_id"), strace = listOf("settings_ssaid\\.xml", "android_id")),
        id("settings.bluetooth_address", "BT MAC (legacy settings)", IdentifierGroup.SETTINGS, "Settings.Secure.bluetooth_address", logcat = listOf("bluetooth_address"), perm = "targetSdk≤31"),
        id("settings.bluetooth_name", "BT name (legacy settings)", IdentifierGroup.SETTINGS, "Settings.Secure.bluetooth_name", logcat = listOf("bluetooth_name")),
        id("settings.device_name", "Имя устройства", IdentifierGroup.SETTINGS, "Settings.Global.DEVICE_NAME", logcat = listOf("device_name", "DEVICE_NAME")),
        id("settings.secure", "Settings.Secure (bulk)", IdentifierGroup.SETTINGS, "content://settings/secure", strace = listOf("content://settings/secure", "settings/secure")),
        id("settings.global", "Settings.Global (bulk)", IdentifierGroup.SETTINGS, "content://settings/global", strace = listOf("content://settings/global")),
        id("settings.system", "Settings.System (bulk)", IdentifierGroup.SETTINGS, "content://settings/system", strace = listOf("content://settings/system")),
        id("settings.accessibility", "Accessibility services", IdentifierGroup.SETTINGS, "Settings.Secure.enabled_accessibility_services", logcat = listOf("enabled_accessibility_services", "accessibility_enabled")),
        id("settings.notification_listeners", "Notification listeners", IdentifierGroup.SETTINGS, "enabled_notification_listeners", logcat = listOf("enabled_notification_listeners")),
        id("settings.input_method", "Клавиатура / IME", IdentifierGroup.SETTINGS, "default_input_method", logcat = listOf("default_input_method")),
        id("settings.location_mode", "Location mode", IdentifierGroup.SETTINGS, "location_mode / location_providers_allowed", logcat = listOf("location_mode", "location_providers_allowed")),
        id("settings.mock_location", "Mock location", IdentifierGroup.SETTINGS, "allow_mock_location", logcat = listOf("allow_mock_location", "mock_location")),
        id("settings.overlay", "SYSTEM_ALERT_WINDOW", IdentifierGroup.SETTINGS, "Settings.canDrawOverlays", logcat = listOf("canDrawOverlays", "SYSTEM_ALERT_WINDOW")),
        id("settings.adb", "ADB enabled", IdentifierGroup.SETTINGS, "Settings.Global.adb_enabled", logcat = listOf("adb_enabled")),
        id("settings.development", "Developer options", IdentifierGroup.SETTINGS, "Settings.Global.development_settings_enabled", logcat = listOf("development_settings_enabled")),
        id("settings.animation", "Animation scale", IdentifierGroup.SETTINGS, "transition_animation_scale / window_animation_scale / animator_duration_scale", logcat = listOf("transition_animation_scale", "window_animation_scale", "animator_duration_scale")),
        id("settings.data_roaming", "Data roaming", IdentifierGroup.SETTINGS, "Settings.Global.data_roaming", logcat = listOf("data_roaming")),
        id("settings.touch_exploration", "TalkBack / touch exploration", IdentifierGroup.SETTINGS, "Settings.Secure.touch_exploration_enabled", logcat = listOf("touch_exploration_enabled")),
        id("settings.alarm", "Alarm ringtone path", IdentifierGroup.SETTINGS, "Settings.System.alarm_alert", logcat = listOf("alarm_alert")),
        id("settings.date_format", "Date format", IdentifierGroup.SETTINGS, "Settings.System.date_format", logcat = listOf("date_format")),
        id("settings.font_scale", "Font scale", IdentifierGroup.SETTINGS, "Settings.System.font_scale", logcat = listOf("font_scale")),
        id("settings.screen_off", "Screen off timeout", IdentifierGroup.SETTINGS, "Settings.System.screen_off_timeout", logcat = listOf("screen_off_timeout")),
        id("settings.time_12_24", "12/24 hour", IdentifierGroup.SETTINGS, "Settings.System.time_12_24", logcat = listOf("time_12_24")),
        id("settings.brightness", "Яркость экрана", IdentifierGroup.SETTINGS, "Settings.System.screen_brightness", logcat = listOf("screen_brightness")),
        id("settings.boot_count", "Boot count", IdentifierGroup.SETTINGS, "Settings.Global.boot_count", logcat = listOf("boot_count")),
        id("settings.airplane", "Airplane mode", IdentifierGroup.SETTINGS, "Settings.Global.airplane_mode_on", logcat = listOf("airplane_mode_on")),
        id("settings.auto_time", "Auto time / timezone", IdentifierGroup.SETTINGS, "Settings.Global.auto_time", logcat = listOf("auto_time", "auto_time_zone")),
        id("settings.private_dns", "Private DNS", IdentifierGroup.SETTINGS, "Settings.Global.private_dns_mode", logcat = listOf("private_dns_mode", "private_dns_specifier")),
        id("settings.unknown_sources", "Unknown sources", IdentifierGroup.SETTINGS, "Settings.Secure.install_non_market_apps", logcat = listOf("install_non_market_apps")),
        id("settings.stay_on", "Stay on while plugged", IdentifierGroup.SETTINGS, "Settings.Global.stay_on_while_plugged_in", logcat = listOf("stay_on_while_plugged_in")),
        id("settings.end_button", "End button behaviour", IdentifierGroup.SETTINGS, "Settings.System.end_button_behavior", logcat = listOf("end_button_behavior"))
    )

    private fun telephonyIdentifiers() = listOf(
        id("tel.imei", "IMEI", IdentifierGroup.TELEPHONY, "TelephonyManager.getImei()", logcat = listOf("getImei", "getPrimaryImei"), perm = "READ_PRIVILEGED_PHONE_STATE / carrier"),
        id("tel.meid", "MEID", IdentifierGroup.TELEPHONY, "TelephonyManager.getMeid()", logcat = listOf("getMeid"), perm = "READ_PRIVILEGED_PHONE_STATE"),
        id("tel.device_id", "Device ID (legacy)", IdentifierGroup.TELEPHONY, "TelephonyManager.getDeviceId()", logcat = listOf("getDeviceId")),
        id("tel.subscriber_id", "IMSI", IdentifierGroup.TELEPHONY, "TelephonyManager.getSubscriberId()", logcat = listOf("getSubscriberId", "IMSI"), perm = "READ_PRIVILEGED_PHONE_STATE"),
        id("tel.sim_serial", "SIM serial / ICCID", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimSerialNumber()", logcat = listOf("getSimSerialNumber", "ICCID"), perm = "READ_PRIVILEGED_PHONE_STATE"),
        id("tel.line1_number", "Номер телефона", IdentifierGroup.TELEPHONY, "TelephonyManager.getLine1Number()", logcat = listOf("getLine1Number", "getLine1NumberForDisplay"), perm = "READ_PHONE_NUMBERS"),
        id("tel.nai", "Network Access Identifier", IdentifierGroup.TELEPHONY, "TelephonyManager.getNai()", logcat = listOf("getNai")),
        id("tel.group_id", "Group ID Level 1", IdentifierGroup.TELEPHONY, "TelephonyManager.getGroupIdLevel1()", logcat = listOf("getGroupIdLevel1")),
        id("tel.tac", "Type Allocation Code", IdentifierGroup.TELEPHONY, "TelephonyManager.getTypeAllocationCode()", logcat = listOf("getTypeAllocationCode", "TAC")),
        id("tel.software_version", "Device software version (IMEISV)", IdentifierGroup.TELEPHONY, "TelephonyManager.getDeviceSoftwareVersion()", logcat = listOf("getDeviceSoftwareVersion", "IMEISV")),
        id("tel.network_operator", "MCC+MNC (сеть)", IdentifierGroup.TELEPHONY, "TelephonyManager.getNetworkOperator()", logcat = listOf("getNetworkOperator", "MCCMNC")),
        id("tel.network_operator_name", "Имя оператора сети", IdentifierGroup.TELEPHONY, "TelephonyManager.getNetworkOperatorName()", logcat = listOf("getNetworkOperatorName")),
        id("tel.network_country", "Страна сети", IdentifierGroup.TELEPHONY, "TelephonyManager.getNetworkCountryIso()", logcat = listOf("getNetworkCountryIso")),
        id("tel.sim_operator", "MCC+MNC (SIM)", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimOperator()", logcat = listOf("getSimOperator")),
        id("tel.sim_operator_name", "Имя оператора SIM", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimOperatorName()", logcat = listOf("getSimOperatorName")),
        id("tel.sim_country", "Страна SIM", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimCountryIso()", logcat = listOf("getSimCountryIso")),
        id("tel.carrier_id", "Carrier ID", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimCarrierId()", logcat = listOf("getSimCarrierId", "CarrierId")),
        id("tel.carrier_name", "Имя carrier ID", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimCarrierIdName()", logcat = listOf("getSimCarrierIdName")),
        id("tel.specific_carrier_id", "Specific carrier ID", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimSpecificCarrierId()", logcat = listOf("getSimSpecificCarrierId")),
        id("tel.voicemail", "Голосовая почта", IdentifierGroup.TELEPHONY, "TelephonyManager.getVoiceMailNumber()", logcat = listOf("getVoiceMailNumber")),
        id("tel.voicemail_tag", "Метка голосовой почты", IdentifierGroup.TELEPHONY, "TelephonyManager.getVoiceMailAlphaTag()", logcat = listOf("getVoiceMailAlphaTag")),
        id("tel.sim_state", "SIM state", IdentifierGroup.TELEPHONY, "TelephonyManager.getSimState()", logcat = listOf("getSimState", "SIM_STATE")),
        id("tel.phone_type", "Phone type", IdentifierGroup.TELEPHONY, "TelephonyManager.getPhoneType()", logcat = listOf("getPhoneType")),
        id("tel.modem_count", "Число модемов", IdentifierGroup.TELEPHONY, "TelephonyManager.getActiveModemCount()", logcat = listOf("getActiveModemCount", "getSupportedModemCount", "getPhoneCount")),
        id("tel.multi_sim", "Multi-SIM", IdentifierGroup.TELEPHONY, "TelephonyManager.isMultiSimSupported()", logcat = listOf("isMultiSimSupported", "getMultiSimConfiguration")),
        id("tel.has_icc", "hasIccCard", IdentifierGroup.TELEPHONY, "TelephonyManager.hasIccCard()", logcat = listOf("hasIccCard")),
        id("tel.network_type", "Тип сети", IdentifierGroup.TELEPHONY, "TelephonyManager.getDataNetworkType()", logcat = listOf("getDataNetworkType", "getNetworkType", "getVoiceNetworkType")),
        id("tel.service_state", "ServiceState", IdentifierGroup.TELEPHONY, "TelephonyManager.getServiceState()", logcat = listOf("getServiceState")),
        id("tel.phone_interface", "PhoneInterfaceManager", IdentifierGroup.TELEPHONY, logcat = listOf("PhoneInterfaceManager", "ITelephony", "TelephonyPermissions")),
        id("tel.eid", "eSIM EID", IdentifierGroup.TELEPHONY, "EuiccManager.getEid()", logcat = listOf("getEid", "EuiccManager"), perm = "READ_PRIVILEGED_PHONE_STATE"),
        id("tel.msisdn", "MSISDN", IdentifierGroup.TELEPHONY, "TelephonyManager.getMsisdn()", logcat = listOf("getMsisdn"), perm = "READ_PHONE_NUMBERS"),
        id("tel.manufacturer_code", "Manufacturer code", IdentifierGroup.TELEPHONY, "TelephonyManager.getManufacturerCode()", logcat = listOf("getManufacturerCode")),
        id("tel.icc_auth", "SIM ICC authentication", IdentifierGroup.TELEPHONY, "TelephonyManager.getIccAuthentication()", logcat = listOf("getIccAuthentication", "iccOpenLogicalChannel")),
        id("tel.isim", "ISIM IMPI/IMPU", IdentifierGroup.TELEPHONY, "TelephonyManager.getIsimImpi()", logcat = listOf("getIsimImpi", "getIsimImpu", "getIsimDomain")),
        id("tel.callback", "TelephonyCallback / listen", IdentifierGroup.TELEPHONY, "registerTelephonyCallback / listen", logcat = listOf("registerTelephonyCallback", "PhoneStateListener")),
        id("tel.carrier_config", "CarrierConfig", IdentifierGroup.TELEPHONY, "CarrierConfigManager.getConfigForSubId()", logcat = listOf("CarrierConfigManager", "getConfigForSubId")),
        id("tel.telecom", "TelecomManager.getLine1Number", IdentifierGroup.TELEPHONY, "TelecomManager.getLine1Number()", logcat = listOf("TelecomManager"), perm = "READ_PHONE_NUMBERS")
    )

    private fun subscriptionIdentifiers() = listOf(
        id("sub.subscription_id", "Subscription ID", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getSubscriptionId()", logcat = listOf("getSubscriptionId", "SubscriptionManager")),
        id("sub.iccid", "ICCID (Subscription)", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getIccId()", logcat = listOf("getIccId"), perm = "USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER"),
        id("sub.phone_number", "Номер (Subscription)", IdentifierGroup.SUBSCRIPTION, "SubscriptionManager.getPhoneNumber()", logcat = listOf("SubscriptionManager.*getPhoneNumber"), perm = "READ_PHONE_NUMBERS"),
        id("sub.sim_slot", "SIM slot index", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getSimSlotIndex()", logcat = listOf("getSimSlotIndex")),
        id("sub.mcc", "MCC string", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getMccString()", logcat = listOf("getMccString")),
        id("sub.mnc", "MNC string", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getMncString()", logcat = listOf("getMncString")),
        id("sub.group_uuid", "Group UUID", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getGroupUuid()", logcat = listOf("getGroupUuid")),
        id("sub.card_id", "Card ID", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getCardId()", logcat = listOf("getCardId")),
        id("sub.port_index", "eSIM port index", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getPortIndex()", logcat = listOf("getPortIndex")),
        id("sub.card_string", "Card string / eUICC", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getCardString()", logcat = listOf("getCardString")),
        id("sub.embedded", "isEmbedded (eSIM)", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.isEmbedded()", logcat = listOf("isEmbedded"))
    )

    private fun wifiIdentifiers() = listOf(
        id("wifi.mac", "Wi‑Fi MAC", IdentifierGroup.WIFI, "WifiInfo.getMacAddress()", logcat = listOf("getMacAddress", "WifiInfo"), perm = "LOCAL_MAC_ADDRESS + LOCATION"),
        id("wifi.bssid", "BSSID (AP MAC)", IdentifierGroup.WIFI, "WifiInfo.getBSSID()", logcat = listOf("getBSSID", "BSSID"), perm = "ACCESS_FINE_LOCATION"),
        id("wifi.ssid", "SSID", IdentifierGroup.WIFI, "WifiInfo.getSSID()", logcat = listOf("getSSID"), perm = "ACCESS_FINE_LOCATION / NEARBY_WIFI_DEVICES"),
        id("wifi.network_id", "Network ID", IdentifierGroup.WIFI, "WifiInfo.getNetworkId()", logcat = listOf("getNetworkId")),
        id("wifi.ip", "Wi‑Fi IP (legacy)", IdentifierGroup.WIFI, "WifiInfo.getIpAddress()", logcat = listOf("getIpAddress")),
        id("wifi.scan_results", "Wi‑Fi scan results", IdentifierGroup.WIFI, "WifiManager.getScanResults()", logcat = listOf("getScanResults", "WifiScanningService")),
        id("wifi.sysfs_mac", "MAC из sysfs", IdentifierGroup.WIFI, file = "/sys/class/net/wlan0/address", strace = listOf("/sys/class/net/.*/address")),
        id("wifi.ap_mld_mac", "AP MLD MAC", IdentifierGroup.WIFI, "WifiInfo.getApMldMacAddress()", logcat = listOf("ApMldMacAddress")),
        id("wifi.passpoint", "Passpoint FQDN", IdentifierGroup.WIFI, "WifiInfo.getPasspointFqdn()", logcat = listOf("Passpoint"))
    )

    private fun bluetoothIdentifiers() = listOf(
        id("bt.local_mac", "Локальный BT MAC", IdentifierGroup.BLUETOOTH, "BluetoothAdapter.getAddress()", logcat = listOf("BluetoothAdapter.*getAddress"), perm = "BLUETOOTH_CONNECT + LOCAL_MAC_ADDRESS"),
        id("bt.local_name", "Локальное BT имя", IdentifierGroup.BLUETOOTH, "BluetoothAdapter.getName()", logcat = listOf("BluetoothAdapter.*getName"), perm = "BLUETOOTH_CONNECT"),
        id("bt.remote_mac", "MAC удалённого устройства", IdentifierGroup.BLUETOOTH, "BluetoothDevice.getAddress()", logcat = listOf("BluetoothDevice.*getAddress"), perm = "BLUETOOTH_CONNECT"),
        id("bt.remote_name", "Имя удалённого устройства", IdentifierGroup.BLUETOOTH, "BluetoothDevice.getName()", logcat = listOf("BluetoothDevice.*getName")),
        id("bt.sysfs_mac", "BT MAC из sysfs", IdentifierGroup.BLUETOOTH, file = "/sys/class/bluetooth/hci0/address", strace = listOf("/sys/class/bluetooth")),
        id("bt.audio_device_mac", "MAC аудиоустройства", IdentifierGroup.BLUETOOTH, "AudioDeviceInfo.getAddress()", logcat = listOf("getCommunicationDevice", "AudioDeviceInfo"))
    )

    private fun advertisingIdentifiers() = listOf(
        id("ad.gaid", "Google Advertising ID (GAID)", IdentifierGroup.ADVERTISING, "AdvertisingIdClient.getId()", logcat = listOf("AdvertisingIdClient", "AdvertisingIdSettings", "AD_ID"), perm = "com.google.android.gms.permission.AD_ID"),
        id("ad.gsf_id", "GSF ID", IdentifierGroup.ADVERTISING, "content://com.google.android.gsf.gservices", logcat = listOf("gsf\\.gservices", "gservices\\.db"), strace = listOf("gservices", "com\\.google\\.android\\.gsf"), perm = "READ_GSERVICES"),
        id("ad.firebase_fid", "Firebase Installation ID", IdentifierGroup.ADVERTISING, "FirebaseInstallations.getId()", logcat = listOf("FirebaseInstallations", "Installation ID", "FirebaseInstanceId")),
        id("ad.firebase_token", "Firebase auth token", IdentifierGroup.ADVERTISING, "FirebaseInstallations.getToken()", logcat = listOf("Installation auth token")),
        id("ad.app_set_id", "App Set ID (ASID)", IdentifierGroup.ADVERTISING, "AppSetIdManager.getAppSetId()", logcat = listOf("AppSetId", "AppSetIdManager")),
        id("ad.oaid", "OAID (China/OEM)", IdentifierGroup.OEM, logcat = listOf("OAID", "MdidSdk", "com\\.bun\\.miitmdid", "HmsAdsIdentifier")),
        id("ad.limit_tracking", "Limit ad tracking flag", IdentifierGroup.ADVERTISING, logcat = listOf("limit ad tracking", "isLimitAdTrackingEnabled")),
        id("ad.adservices", "Privacy Sandbox AdId", IdentifierGroup.ADVERTISING, "android.adservices.adid.AdIdManager.getAdId()", logcat = listOf("AdIdManager", "adservices.adid"), perm = "ACCESS_ADSERVICES_AD_ID"),
        id("ad.topics", "Privacy Sandbox Topics", IdentifierGroup.ADVERTISING, "TopicsManager.getTopics()", logcat = listOf("TopicsManager", "getTopics")),
        id("ad.measurement", "Privacy Sandbox Measurement", IdentifierGroup.ADVERTISING, "MeasurementManager", logcat = listOf("MeasurementManager", "registerSource")),
        id("ad.instance_id", "InstanceID / FID", IdentifierGroup.ADVERTISING, "FirebaseInstanceId.getId / InstanceID.getId", logcat = listOf("FirebaseInstanceId", "InstanceID.getId"))
    )

    private fun drmIdentifiers() = listOf(
        id("drm.widevine_id", "Widevine Device ID", IdentifierGroup.DRM, "MediaDrm.getPropertyByteArray(deviceUniqueId)", logcat = listOf("deviceUniqueId", "MediaDrm", "widevine"), strace = listOf("/dev/mediadrm", "mediadrm")),
        id("drm.vendor", "MediaDrm vendor", IdentifierGroup.DRM, "MediaDrm.getPropertyString(vendor)", logcat = listOf("MediaDrm.*vendor")),
        id("drm.version", "MediaDrm version", IdentifierGroup.DRM, "MediaDrm.getPropertyString(version)", logcat = listOf("MediaDrm.*version")),
        id("drm.security_level", "Widevine security level", IdentifierGroup.DRM, logcat = listOf("securityLevel", "L1", "L3")),
        id("drm.playready", "PlayReady ID", IdentifierGroup.DRM, logcat = listOf("playready", "PlayReady")),
        id("drm.legacy", "DrmManagerClient (legacy)", IdentifierGroup.DRM, "DrmManagerClient.getUniqueId()", logcat = listOf("DrmManagerClient", "getUniqueId"))
    )

    private fun installIdentifiers() = listOf(
        id("install.referrer", "Install Referrer", IdentifierGroup.INSTALL, "InstallReferrerClient.getInstallReferrer()", logcat = listOf("InstallReferrer", "getInstallReferrer", "referrerClickTimestamp")),
        id("install.installer", "Installer package", IdentifierGroup.INSTALL, "PackageManager.getInstallerPackageName()", logcat = listOf("getInstallerPackageName")),
        id("install.first_install", "First install time", IdentifierGroup.INSTALL, "PackageInfo.firstInstallTime", logcat = listOf("firstInstallTime")),
        id("install.last_update", "Last update time", IdentifierGroup.INSTALL, "PackageInfo.lastUpdateTime", logcat = listOf("lastUpdateTime")),
        id("install.signing_cert", "Signing certificate hash", IdentifierGroup.INSTALL, "PackageManager GET_SIGNING_CERTIFICATES", logcat = listOf("GET_SIGNING_CERTIFICATES", "signatures")),
        id("install.package_info", "PackageManager.getPackageInfo", IdentifierGroup.INSTALL, "PackageManager.getPackageInfo", logcat = listOf("getPackageInfo")),
        id("install.application_info", "getApplicationInfo", IdentifierGroup.INSTALL, "PackageManager.getApplicationInfo", logcat = listOf("getApplicationInfo")),
        id("install.source", "InstallSourceInfo", IdentifierGroup.INSTALL, "PackageManager.getInstallSourceInfo()", logcat = listOf("getInstallSourceInfo", "InstallSourceInfo"))
    )

    private fun accountIdentifiers() = listOf(
        id("account.list", "Список аккаунтов", IdentifierGroup.ACCOUNT, "AccountManager.getAccounts()", logcat = listOf("getAccounts", "AccountManagerService"), perm = "GET_ACCOUNTS"),
        id("account.by_type", "Аккаунты по типу", IdentifierGroup.ACCOUNT, "AccountManager.getAccountsByType()", logcat = listOf("getAccountsByType"), perm = "GET_ACCOUNTS"),
        id("account.name", "Имя аккаунта (email)", IdentifierGroup.ACCOUNT, "Account.name", logcat = listOf("Account.*name")),
        id("account.auth_token", "Auth token", IdentifierGroup.ACCOUNT, "AccountManager.getAuthToken()", logcat = listOf("getAuthToken")),
        id("account.google", "Google Sign-In ID", IdentifierGroup.ACCOUNT, "GoogleSignInAccount.getId()", logcat = listOf("GoogleSignIn", "getIdToken"))
    )

    private fun contentProviderIdentifiers() = listOf(
        id("cp.telephony", "Telephony provider", IdentifierGroup.CONTENT_PROVIDER, "content://telephony/siminfo", strace = listOf("content://telephony"), perm = "READ_PHONE_STATE"),
        id("cp.gsf", "GSF provider", IdentifierGroup.CONTENT_PROVIDER, "content://com.google.android.gsf.gservices", strace = listOf("gsf\\.gservices")),
        id("cp.settings_secure", "Settings secure CP", IdentifierGroup.CONTENT_PROVIDER, "content://settings/secure"),
        id("cp.icc", "SIM ICC provider", IdentifierGroup.CONTENT_PROVIDER, "content://icc/adn", strace = listOf("content://icc")),
        id("cp.contacts", "Contacts provider", IdentifierGroup.PERSONAL, "content://com.android.contacts", strace = listOf("content://com.android.contacts")),
        id("cp.sms", "SMS/MMS provider", IdentifierGroup.PERSONAL, "content://sms", strace = listOf("content://sms", "content://mms")),
        id("cp.call_log", "CallLog provider", IdentifierGroup.PERSONAL, "content://call_log", strace = listOf("content://call_log")),
        id("cp.calendar", "Calendar provider", IdentifierGroup.PERSONAL, "content://com.android.calendar", strace = listOf("content://com.android.calendar")),
        id("cp.browser", "Browser bookmarks/history", IdentifierGroup.PERSONAL, "content://browser", strace = listOf("content://browser")),
        id("cp.voicemail", "Voicemail provider", IdentifierGroup.PERSONAL, "content://com.android.voicemail", strace = listOf("voicemail")),
        id("cp.blocked", "Blocked numbers", IdentifierGroup.PERSONAL, "content://com.android.blockednumber", strace = listOf("blockednumber")),
        id("storage.media", "MediaStore", IdentifierGroup.CONTENT_PROVIDER, "content://media", strace = listOf("content://media")),
        id("storage.downloads", "DownloadManager / downloads", IdentifierGroup.CONTENT_PROVIDER, "content://downloads", strace = listOf("content://downloads")),
        id("cp.other", "Другой ContentProvider", IdentifierGroup.CONTENT_PROVIDER, "ContentResolver.query")
    )

    private fun procSysIdentifiers() = listOf(
        id("proc.cpuinfo", "CPU info", IdentifierGroup.PROC_SYS, file = "/proc/cpuinfo", strace = listOf("/proc/cpuinfo")),
        id("proc.meminfo", "Memory info", IdentifierGroup.PROC_SYS, file = "/proc/meminfo", strace = listOf("/proc/meminfo")),
        id("proc.version", "Kernel version", IdentifierGroup.PROC_SYS, file = "/proc/version", strace = listOf("/proc/version")),
        id("proc.boot_id", "Boot ID", IdentifierGroup.PROC_SYS, file = "/proc/sys/kernel/random/boot_id", strace = listOf("boot_id")),
        id("proc.auxv", "ELF hwcaps", IdentifierGroup.PROC_SYS, file = "/proc/self/auxv", strace = listOf("/proc/self/auxv")),
        id("proc.properties", "System properties area", IdentifierGroup.PROC_SYS, file = "/dev/__properties__", strace = listOf("/dev/__properties__", "__system_property_get")),
        id("sys.cpu", "CPU topology", IdentifierGroup.PROC_SYS, file = "/sys/devices/system/cpu", strace = listOf("/sys/devices/system/cpu")),
        id("sys.block_cid", "SD card CID", IdentifierGroup.PROC_SYS, file = "/sys/block/mmcblk0/device/cid", strace = listOf("/sys/block"))
    )

    private fun networkIdentifiers() = listOf(
        id("net.link_addresses", "IP адреса", IdentifierGroup.NETWORK, "LinkProperties.getLinkAddresses()", logcat = listOf("LinkProperties", "getLinkAddresses")),
        id("net.hardware_address", "NetworkInterface MAC", IdentifierGroup.NETWORK, "NetworkInterface.getHardwareAddress()", logcat = listOf("getHardwareAddress", "NetworkInterface")),
        id("net.hostname", "Hostname", IdentifierGroup.NETWORK, "InetAddress.getHostName()", logcat = listOf("getHostName")),
        id("net.inet6", "IPv6 address", IdentifierGroup.NETWORK, logcat = listOf("inet6", "Inet6Address")),
        id("net.http", "HTTP URL (OkHttp / HttpURLConnection)", IdentifierGroup.NETWORK, "OkHttp / HttpURLConnection", logcat = listOf("OkHttp", "HttpURLConnection", "okhttp3")),
        id("net.webview", "WebView URL", IdentifierGroup.NETWORK, "WebView.loadUrl", logcat = listOf("WebView.loadUrl", "chromium")),
        id("net.dns", "DNS QNAME (tcpdump)", IdentifierGroup.NETWORK, "tcpdump port 53", logcat = listOf("A?", "AAAA?")),
        id("net.pcap", "pcap заголовки", IdentifierGroup.NETWORK, "tcpdump -s 96"),
        id("net.sni", "TLS SNI (имя хоста)", IdentifierGroup.NETWORK, "SSL_get_servername / SSLSocket.getPeerHost"),
        id("net.https", "HTTPS plaintext (MITM)", IdentifierGroup.NETWORK, "SSL_read/write + local CA proxy"),
        id("net.http2", "HTTP/2 MITM (ALPN h2)", IdentifierGroup.NETWORK, "ALPN h2 + HEADERS :path/:status"),
        id("net.vpn", "VPN / TRANSPORT_VPN", IdentifierGroup.NETWORK, "NetworkCapabilities.hasTransport(TRANSPORT_VPN)", logcat = listOf("TRANSPORT_VPN", "VpnService", "tun0")),
        id("net.proxy", "HTTP proxy", IdentifierGroup.NETWORK, "Proxy.getDefaultHost / http.proxyHost", logcat = listOf("http_proxy", "http.proxyHost", "ProxySelector")),
        id("net.user_ca", "User CA", IdentifierGroup.NETWORK, "/data/misc/user/0/cacerts-added", file = "/data/misc/user/0/cacerts-added", strace = listOf("cacerts-added", "UserCertificateSource")),
        id("net.pin_fail", "Certificate pinning fail", IdentifierGroup.NETWORK, "CertificatePinner / SSLPeerUnverifiedException", logcat = listOf("CertificatePinner", "SSLPeerUnverified", "Trust anchor", "ERR_CERT")),
        id("storage.sqlite", "SQLite query", IdentifierGroup.CONTENT_PROVIDER, "SQLiteDatabase.rawQuery", logcat = listOf("SQLiteDatabase", "SQLiteLog")),
        id("storage.prefs", "SharedPreferences", IdentifierGroup.CONTENT_PROVIDER, "SharedPreferences.getString", logcat = listOf("SharedPreferences")),
        id("storage.file", "Файлы приложения", IdentifierGroup.PROC_SYS, "FileInputStream / FileOutputStream", strace = listOf("/data/data/"))
    )

    private fun enterpriseIdentifiers() = listOf(
        id("ent.esid", "Enrollment Specific ID", IdentifierGroup.ENTERPRISE, "DevicePolicyManager.getEnrollmentSpecificId()", logcat = listOf("getEnrollmentSpecificId", "enterpriseSpecificId")),
        id("ent.org_id", "Organization ID", IdentifierGroup.ENTERPRISE, "DevicePolicyManager.setOrganizationId()", logcat = listOf("setOrganizationId")),
        id("ent.integrity", "Play Integrity token", IdentifierGroup.ATTESTATION, "IntegrityManager.requestIntegrityToken()", logcat = listOf("IntegrityService", "PlayIntegrity", "StandardIntegrity")),
        id("ent.safetynet", "SafetyNet attestation", IdentifierGroup.ATTESTATION, "SafetyNetClient.attest()", logcat = listOf("SafetyNet")),
        id("ent.verdict", "Integrity verdict", IdentifierGroup.ATTESTATION, "MEETS_DEVICE_INTEGRITY / ctsProfileMatch / decodeIntegrityToken", logcat = listOf("MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY", "MEETS_BASIC_INTEGRITY", "NO_INTEGRITY", "ctsProfileMatch", "deviceRecognitionVerdict", "decodeIntegrityToken"))
    )

    private fun oemIdentifiers() = listOf(
        id("oem.samsung_wifi", "Samsung Wi‑Fi SSID list", IdentifierGroup.OEM, "sem_auto_wifi_added_removed_list", logcat = listOf("sem_auto_wifi")),
        id("oem.samsung_account", "Samsung account", IdentifierGroup.OEM, "Settings.System.samsungaccount", logcat = listOf("samsungaccount")),
        id("oem.samsung_imsi", "Samsung SIM IMSI cache", IdentifierGroup.OEM, "dsa_sim1_value", logcat = listOf("dsa_sim")),
        id("oem.vivo_wifi", "Vivo ext Wi‑Fi scan", IdentifierGroup.OEM, logcat = listOf("getExtWifiScanResults")),
        id("oem.huawei_oaid", "Huawei OAID", IdentifierGroup.OEM, logcat = listOf("HmsAdsIdentifier")),
        id("oem.oaid_msa", "MSA OAID (MdidSdk)", IdentifierGroup.OEM, "com.bun.miitmdid.core.MdidSdkHelper", logcat = listOf("MdidSdkHelper", "miitmdid")),
        id("oem.oaid_xiaomi", "Xiaomi OAID", IdentifierGroup.OEM, "com.android.id.impl.IdProviderImpl", logcat = listOf("IdProviderImpl", "xiaomi.oaid")),
        id("oem.oaid_oppo", "OPPO/Heytap OAID", IdentifierGroup.OEM, "com.heytap.openid", logcat = listOf("heytap.openid", "HeytapID")),
        id("oem.oaid_vivo", "Vivo OAID", IdentifierGroup.OEM, "com.vivo.identifier", logcat = listOf("VivoIdentifier", "vivo.identifier")),
        id("oem.sem_tel", "Samsung SemTelephony", IdentifierGroup.OEM, "SemTelephonyManager.getImei()", logcat = listOf("SemTelephonyManager", "semGetImei")),
        id("oem.knox", "Samsung Knox / TIMA", IdentifierGroup.OEM, "EnterpriseDeviceManager / Knox", logcat = listOf("EnterpriseDeviceManager", "KnoxAttestation", "TIMA"))
    )

    private fun locationIdentifiers() = listOf(
        id("location.gps", "GPS / GNSS (LocationManager)", IdentifierGroup.LOCATION, "LocationManager.requestLocationUpdates(GPS)", logcat = listOf("requestLocationUpdates", "getLastKnownLocation", "getCurrentLocation", "LocationManager"), perm = "ACCESS_FINE_LOCATION"),
        id("location.fused", "Fused Location (GMS/AOSP)", IdentifierGroup.LOCATION, "FusedLocationProviderClient", logcat = listOf("FusedLocation", "GCoreFlp", "FusedLocationProvider", "FLP"), perm = "ACCESS_FINE_LOCATION"),
        id("location.network", "Network Location (NLP/Wi‑Fi/Cell)", IdentifierGroup.LOCATION, "LocationManager.NETWORK_PROVIDER", logcat = listOf("NetworkLocation", "NlpService", "NlpLocationHelper"), perm = "ACCESS_COARSE_LOCATION"),
        id("location.passive", "Passive location", IdentifierGroup.LOCATION, "LocationManager.PASSIVE_PROVIDER", logcat = listOf("passive provider", "PassiveProvider")),
        id("location.gnss_nmea", "NMEA / GNSS raw", IdentifierGroup.LOCATION, "LocationManager.addNmeaListener / GnssMeasurements", logcat = listOf("Nmea", "GnssMeasurement", "GnssNavigation", "GnssStatus"), perm = "ACCESS_FINE_LOCATION"),
        id("location.geofence", "Geofence", IdentifierGroup.LOCATION, "GeofencingClient", logcat = listOf("Geofence", "GeofencerStateMachine")),
        id("location.cell", "Cell location", IdentifierGroup.LOCATION, "TelephonyManager.getAllCellInfo / getCellLocation", logcat = listOf("getAllCellInfo", "getCellLocation", "requestCellInfoUpdate", "CellIdentity"), perm = "ACCESS_FINE_LOCATION"),
        id("location.wifi_scan", "Wi‑Fi scan for location", IdentifierGroup.LOCATION, "WifiManager.getScanResults / startScan", logcat = listOf("WifiScanningService", "getScanResults", "startScan"), perm = "ACCESS_FINE_LOCATION"),
        id("location.gms", "GMS LocationServices", IdentifierGroup.LOCATION, "LocationServices.getFusedLocationProviderClient", logcat = listOf("LocationServices", "GoogleLocationManager", "GmsLocation")),
        id("location.hal", "GNSS HAL /dev", IdentifierGroup.LOCATION, file = "/dev/gnss0", strace = listOf("/dev/gnss", "/dev/gps", "/dev/ttyGPS", "/vendor/etc/gps", "/data/vendor/gps")),
        id("location.supl", "SUPL / AGPS", IdentifierGroup.LOCATION, logcat = listOf("SUPL", "AGps", "agps", "supl.google")),
        id("location.activity", "Activity Recognition", IdentifierGroup.LOCATION, "ActivityRecognitionClient", logcat = listOf("ActivityRecognition", "DetectedActivity")),
        id("location.wifi_rtt", "Wi‑Fi RTT / ranging", IdentifierGroup.LOCATION, "WifiRttManager.startRanging", logcat = listOf("WifiRtt", "startRanging"), perm = "NEARBY_WIFI_DEVICES"),
        id("location.uwb", "UWB ranging", IdentifierGroup.LOCATION, "UwbManager", logcat = listOf("UwbManager", "uwb"))
    )

    private fun attestationIdentifiers() = listOf(
        id("attest.key", "Key attestation", IdentifierGroup.ATTESTATION, "KeyGenParameterSpec.setAttestationChallenge()", logcat = listOf("KeyAttestation", "KeyMint", "attestation")),
        id("attest.strongbox", "StrongBox", IdentifierGroup.ATTESTATION, "KeyInfo.isInsideSecureHardware()", logcat = listOf("StrongBox")),
        id("attest.verified_boot", "Verified boot state", IdentifierGroup.ATTESTATION, systemProp = "ro.boot.verifiedbootstate", logcat = listOf("verifiedbootstate", "vbmeta"))
    )

    private fun rootIdentifiers() = listOf(
        id("root.su", "Поиск su", IdentifierGroup.ROOT, "File.exists(/system/bin/su)", file = "/system/bin/su", logcat = listOf("which su", "su binary", "/system/bin/su", "/system/xbin/su"), strace = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su")),
        id("root.magisk", "Magisk / Zygisk", IdentifierGroup.ROOT, "File.exists(/sbin/.magisk)", file = "/sbin/.magisk", logcat = listOf("Magisk", "Zygisk", "magiskd"), strace = listOf("/sbin/.magisk", "/data/adb/magisk", "/debug_ramdisk", "libmagisk", "libzygisk")),
        id("root.ksu", "KernelSU / APatch", IdentifierGroup.ROOT, logcat = listOf("KernelSU", "APatch", "ksud"), strace = listOf("/data/adb/ksu", "/data/adb/ap")),
        id("root.exec", "Runtime.exec (su / getenforce)", IdentifierGroup.ROOT, "Runtime.exec / ProcessBuilder", logcat = listOf("getenforce", "which su")),
        id("root.packages", "Пакеты root-менеджеров", IdentifierGroup.ROOT, "PackageManager.getPackageInfo(magisk/supersu)", logcat = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu")),
        id("root.props", "Свойства root/unlock", IdentifierGroup.ROOT, "SystemProperties ro.secure / ro.debuggable / ro.build.tags", systemProp = "ro.secure", logcat = listOf("ro.secure", "ro.debuggable", "ro.build.tags", "test-keys")),
        id("root.selinux", "SELinux getenforce", IdentifierGroup.ROOT, "Runtime.exec(getenforce)", logcat = listOf("getenforce", "SELinux")),
        id("root.adb", "ADB / developer options", IdentifierGroup.ROOT, "Settings.Global.adb_enabled", logcat = listOf("adb_enabled", "development_settings")),
        id("root.debugger", "Отладчик / TracerPid", IdentifierGroup.ROOT, "Debug.isDebuggerConnected / TracerPid", logcat = listOf("isDebuggerConnected", "TracerPid")),
        id("root.maps", "maps: frida/xposed/magisk", IdentifierGroup.ROOT, "/proc/self/maps", file = "/proc/self/maps", strace = listOf("/proc/self/maps", "/proc/self/status")),
        id("root.rootbeer", "RootBeer.isRooted", IdentifierGroup.ROOT, "com.scottyab.rootbeer.RootBeer", logcat = listOf("RootBeer", "isRooted")),
        id("root.xposed", "Xposed / EdXposed", IdentifierGroup.ROOT, "Class.forName(XposedBridge)", logcat = listOf("XposedBridge", "XposedHelpers", "EdXposed", "handleHookedMethod"), strace = listOf("XposedBridge", "libxposed_art")),
        id("root.lsposed", "LSPosed / lspd", IdentifierGroup.ROOT, "Class.forName(LSPosedBridge) / /data/adb/lspd", file = "/data/adb/lspd", logcat = listOf("LSPosed", "LSPosedBridge", "LSPosedContext", "liblspd", "lsplant"), strace = listOf("/data/adb/lspd", "zygisk_lsposed", "riru_lsposed", "liblspd", "liblsplant")),
        id("root.lspatch", "LSPatch / VirtualXposed", IdentifierGroup.ROOT, "org.lsposed.lspatch / me.weishu.exp", logcat = listOf("LSPatch", "VirtualXposed", "TaiChi", "io.va.exposed")),
        id("root.frida_detect", "Детект Frida", IdentifierGroup.ROOT, "frida-server / :27042 / gum-js-loop", logcat = listOf("frida-server", "27042", "gum-js-loop", "LIBFRIDA", "frida-agent", "libfrida-gadget")),
        id("root.inject", "Инжект в память / maps / rwx", IdentifierGroup.ROOT, "/proc/self/maps memfd rwxp sandhook/dobby", file = "/proc/self/maps", logcat = listOf("rwxp", "memfd", "sandhook", "yahfa", "dobby", "libwhale"), strace = listOf("/proc/self/maps", "/proc/self/smaps", "memfd:")),
        id("root.threads", "Потоки gum-js / linjector", IdentifierGroup.ROOT, "/proc/self/task/*/comm", logcat = listOf("gum-js-loop", "gmain", "gdbus", "pool-frida", "linjector")),
        id("root.ports", "Порты Frida 27042/27043", IdentifierGroup.ROOT, "Socket.connect(127.0.0.1:27042)", logcat = listOf("27042", "27043", "23946")),
        id("root.dlsym", "dlsym frida/xposed символы", IdentifierGroup.ROOT, "dlsym(frida_agent_main / MSHookFunction)", logcat = listOf("frida_agent_main", "gum_interceptor", "MSHookFunction", "xposedCallHandler")),
        id("root.stack", "Стек на Xposed/LSPosed", IdentifierGroup.ROOT, "Thread.getAllStackTraces / handleHookedMethod", logcat = listOf("handleHookedMethod", "invokeOriginalMethodNative", "LSPHooker")),
        id("root.emulator", "Детект эмулятора", IdentifierGroup.ROOT, "qemu/goldfish/ranchu", logcat = listOf("goldfish", "ranchu", "qemu_pipe", "ro.kernel.qemu"), strace = listOf("/dev/qemu_pipe", "/dev/goldfish_pipe", "/sys/qemu_trace")),
        id("root.mounts", "mount magisk/rw system", IdentifierGroup.ROOT, "/proc/mounts", file = "/proc/mounts", strace = listOf("/proc/mounts", "/proc/self/mounts")),
        id("root.hide", "Hide root (Shamiko / DenyList)", IdentifierGroup.ROOT, "/proc/pid/root vs host su", file = "/data/adb/modules/zygisk_shamiko", logcat = listOf("Shamiko", "DenyList", "denylist", "zygisk_shamiko"), strace = listOf("zygisk_shamiko", "/data/adb/modules/shamiko")),
        id("root.isolated", "Isolated process", IdentifierGroup.ROOT, "Process.isIsolated / u0iN", logcat = listOf("isIsolated", "isolated_app", ":isolated")),
        id("root.text", "libc .text диск≠RAM", IdentifierGroup.ROOT, "/proc/pid/mem vs libc.so r-xp", file = "/proc/self/mem"),
        id("root.decision", "После проверки → решение", IdentifierGroup.ROOT, "root-check → login/403/finish"),
        id("root.svc", "libc syscall() (SVC wrapper)", IdentifierGroup.ROOT, "libc.so!syscall openat/faccessat/execve/ptrace"),
        id("root.talsec", "Talsec / freeRASP / JailMonkey", IdentifierGroup.ROOT, "com.aheaditec.talsec / JailMonkey", logcat = listOf("Talsec", "freeRASP", "ThreatListener", "JailMonkey"))
    )

    private fun personalIdentifiers() = listOf(
        id("contacts.query", "Контакты", IdentifierGroup.PERSONAL, "ContactsContract / content://com.android.contacts", logcat = listOf("ContactsContract", "ContactsProvider"), perm = "READ_CONTACTS", strace = listOf("content://com.android.contacts", "content://contacts")),
        id("contacts.profile", "Профиль владельца", IdentifierGroup.PERSONAL, "ContactsContract.Profile", logcat = listOf("ContactsContract.Profile"), perm = "READ_CONTACTS"),
        id("sms.inbox", "SMS inbox", IdentifierGroup.PERSONAL, "content://sms", logcat = listOf("content://sms", "Telephony.Sms"), perm = "READ_SMS", strace = listOf("content://sms")),
        id("sms.send", "Отправка SMS", IdentifierGroup.PERSONAL, "SmsManager.sendTextMessage", logcat = listOf("sendTextMessage", "sendMultipartTextMessage"), perm = "SEND_SMS"),
        id("mms.query", "MMS", IdentifierGroup.PERSONAL, "content://mms", logcat = listOf("content://mms"), perm = "READ_SMS", strace = listOf("content://mms")),
        id("call_log.query", "Журнал звонков", IdentifierGroup.PERSONAL, "CallLog.Calls / content://call_log", logcat = listOf("CallLog", "content://call_log"), perm = "READ_CALL_LOG", strace = listOf("content://call_log")),
        id("calendar.query", "Календарь", IdentifierGroup.PERSONAL, "CalendarContract", logcat = listOf("CalendarContract", "content://com.android.calendar"), perm = "READ_CALENDAR", strace = listOf("content://com.android.calendar")),
        id("voicemail.query", "Голосовая почта (CP)", IdentifierGroup.PERSONAL, "content://com.android.voicemail", logcat = listOf("VoicemailContract"), perm = "READ_VOICEMAIL"),
        id("blocked.query", "Заблокированные номера", IdentifierGroup.PERSONAL, "BlockedNumberContract", logcat = listOf("BlockedNumber"), perm = "READ_CONTACTS"),
        id("browser.history", "История браузера", IdentifierGroup.PERSONAL, "content://browser/bookmarks", logcat = listOf("Browser.BOOKMARKS", "content://browser"))
    )

    private fun hardwareIdentifiers() = listOf(
        id("camera.open", "Камера", IdentifierGroup.HARDWARE, "CameraManager.openCamera", logcat = listOf("openCamera", "CameraManager", "CameraDevice"), perm = "CAMERA"),
        id("camera.ids", "Список камер", IdentifierGroup.HARDWARE, "CameraManager.getCameraIdList", logcat = listOf("getCameraIdList")),
        id("mic.record", "Микрофон / запись", IdentifierGroup.HARDWARE, "AudioRecord.startRecording", logcat = listOf("AudioRecord", "MediaRecorder.start"), perm = "RECORD_AUDIO"),
        id("sensor.register", "Сенсоры", IdentifierGroup.HARDWARE, "SensorManager.registerListener", logcat = listOf("SensorManager", "registerListener")),
        id("clipboard.primary", "Буфер обмена", IdentifierGroup.HARDWARE, "ClipboardManager.getPrimaryClip", logcat = listOf("ClipboardManager", "getPrimaryClip")),
        id("display.metrics", "Экран / density", IdentifierGroup.HARDWARE, "Display.getMetrics / DisplayMetrics", logcat = listOf("DisplayMetrics", "getRealMetrics")),
        id("display.capture", "Захват экрана", IdentifierGroup.HARDWARE, "MediaProjectionManager.createScreenCaptureIntent", logcat = listOf("MediaProjection", "createScreenCaptureIntent")),
        id("hw.biometric", "Биометрия", IdentifierGroup.HARDWARE, "BiometricPrompt.authenticate", logcat = listOf("BiometricPrompt", "FingerprintManager")),
        id("nfc.adapter", "NFC", IdentifierGroup.HARDWARE, "NfcAdapter", logcat = listOf("NfcAdapter", "enableReaderMode")),
        id("usb.devices", "USB устройства", IdentifierGroup.HARDWARE, "UsbManager.getDeviceList", logcat = listOf("UsbManager", "getDeviceList")),
        id("battery.status", "Батарея", IdentifierGroup.HARDWARE, "BatteryManager / ACTION_BATTERY_CHANGED", logcat = listOf("BatteryManager", "EXTRA_LEVEL")),
        id("locale.default", "Locale / timezone", IdentifierGroup.HARDWARE, "Locale.getDefault / TimeZone.getDefault", logcat = listOf("Locale.getDefault", "TimeZone.getDefault")),
        id("gpu.gl", "GPU / GLES renderer", IdentifierGroup.HARDWARE, "GLES20.glGetString(GL_RENDERER)", logcat = listOf("GL_RENDERER", "glGetString")),
        id("storage.statfs", "StatFs / свободное место", IdentifierGroup.HARDWARE, "StatFs / StorageStatsManager", logcat = listOf("StatFs", "StorageStatsManager"))
    )

    private fun identityIdentifiers() = listOf(
        id("fcm.token", "FCM push token", IdentifierGroup.IDENTITY, "FirebaseMessaging.getToken", logcat = listOf("FirebaseMessaging", "getToken", "InstanceID")),
        id("cred.manager", "Credential Manager / passkey", IdentifierGroup.IDENTITY, "CredentialManager.getCredential", logcat = listOf("CredentialManager", "GetCredentialRequest")),
        id("cred.phone_hint", "Phone number hint", IdentifierGroup.IDENTITY, "Identity.getPhoneNumberHintIntent", logcat = listOf("PhoneNumberHint", "HintRequest")),
        id("sms.retriever", "SMS Retriever / User Consent", IdentifierGroup.IDENTITY, "SmsRetrieverClient", logcat = listOf("SmsRetriever", "SmsToken")),
        id("play.license", "Play Licensing (LVL)", IdentifierGroup.IDENTITY, "LicenseChecker.checkAccess", logcat = listOf("LicenseChecker", "ILicensingService")),
        id("play.recaptcha", "reCAPTCHA / SafetyNet", IdentifierGroup.IDENTITY, "SafetyNet.Recaptcha / RecaptchaAction", logcat = listOf("Recaptcha", "verifyWithRecaptcha")),
        id("webview.ua", "WebView User-Agent", IdentifierGroup.IDENTITY, "WebSettings.getUserAgentString", logcat = listOf("getUserAgentString", "user-agent"))
    )

    private fun packageQueryIdentifiers() = listOf(
        id("pkg.installed", "Список установленных пакетов", IdentifierGroup.INSTALL, "getInstalledPackages / getInstalledApplications", logcat = listOf("getInstalledPackages", "getInstalledApplications"), perm = "QUERY_ALL_PACKAGES"),
        id("pkg.query_intent", "queryIntentActivities", IdentifierGroup.INSTALL, "PackageManager.queryIntentActivities", logcat = listOf("queryIntentActivities", "queryBroadcastReceivers", "queryIntentServices")),
        id("pkg.running", "Running processes", IdentifierGroup.INSTALL, "ActivityManager.getRunningAppProcesses", logcat = listOf("getRunningAppProcesses", "getRunningTasks")),
        id("pkg.usage", "UsageStats", IdentifierGroup.INSTALL, "UsageStatsManager.queryUsageStats", logcat = listOf("UsageStatsManager", "queryUsageStats"), perm = "PACKAGE_USAGE_STATS"),
        id("perm.check", "checkSelfPermission / requestPermissions", IdentifierGroup.INSTALL, "Context.checkSelfPermission", logcat = listOf("checkSelfPermission", "requestPermissions", "checkPermission")),
        id("perm.appops", "AppOpsManager.checkOp / noteOp", IdentifierGroup.INSTALL, "AppOpsManager", logcat = listOf("AppOpsManager", "noteOp", "checkOp"))
    )

    private fun extraRequestIdentifiers() = listOf(
        id("hw.usb_serial", "USB serial", IdentifierGroup.HARDWARE, "UsbDevice.getSerialNumber()", logcat = listOf("UsbDevice.getSerialNumber")),
        id("hw.input", "InputDevice descriptor", IdentifierGroup.HARDWARE, "InputDevice.getDescriptor()", logcat = listOf("InputDevice.getDescriptor", "InputManager")),
        id("hw.config", "Configuration MCC/MNC/uiMode", IdentifierGroup.HARDWARE, "Resources.getConfiguration()", logcat = listOf("getConfiguration", "Configuration.mcc")),
        id("hw.storage_uuid", "StorageVolume UUID", IdentifierGroup.HARDWARE, "StorageManager.getStorageVolumes / getUuid", logcat = listOf("StorageVolume", "getUuidForPath")),
        id("hw.memory", "RAM / MemoryInfo", IdentifierGroup.HARDWARE, "ActivityManager.getMemoryInfo", logcat = listOf("getMemoryInfo", "availMem")),
        id("hw.features", "hasSystemFeature", IdentifierGroup.HARDWARE, "PackageManager.hasSystemFeature / getSystemAvailableFeatures", logcat = listOf("hasSystemFeature", "getSystemAvailableFeatures")),
        id("hw.power", "PowerManager idle/save", IdentifierGroup.HARDWARE, "PowerManager.isPowerSaveMode / isInteractive", logcat = listOf("isPowerSaveMode", "isDeviceIdleMode")),
        id("hw.audio_dev", "AudioDeviceInfo", IdentifierGroup.HARDWARE, "AudioManager.getDevices / getAddress", logcat = listOf("AudioManager.getDevices")),
        id("net.link_props", "LinkProperties DNS/IP", IdentifierGroup.NETWORK, "ConnectivityManager.getLinkProperties", logcat = listOf("getLinkProperties", "getDnsServers")),
        id("net.interfaces", "NetworkInterface.list", IdentifierGroup.NETWORK, "NetworkInterface.getNetworkInterfaces()", logcat = listOf("getNetworkInterfaces")),
        id("net.local", "InetAddress.getLocalHost", IdentifierGroup.NETWORK, "InetAddress.getLocalHost / getHostAddress", logcat = listOf("getLocalHost", "getHostAddress")),
        id("net.cookies", "CookieManager", IdentifierGroup.NETWORK, "CookieManager.getCookie", logcat = listOf("CookieManager", "getCookie")),
        id("net.traffic", "TrafficStats UID", IdentifierGroup.NETWORK, "TrafficStats.getUidRxBytes", logcat = listOf("TrafficStats", "getUidRxBytes")),
        id("net.nsd", "NSD / mDNS", IdentifierGroup.NETWORK, "NsdManager.discoverServices", logcat = listOf("NsdManager", "discoverServices")),
        id("net.p2p", "Wi‑Fi P2P", IdentifierGroup.NETWORK, "WifiP2pManager", logcat = listOf("WifiP2pManager", "requestPeers")),
        id("net.aware", "Wi‑Fi Aware / NAN", IdentifierGroup.NETWORK, "WifiAwareManager", logcat = listOf("WifiAwareManager", "attach")),
        id("net.netstats", "NetworkStatsManager", IdentifierGroup.NETWORK, "NetworkStatsManager.querySummary", logcat = listOf("NetworkStatsManager", "querySummary")),
        id("bt.bonded", "Bonded Bluetooth devices", IdentifierGroup.BLUETOOTH, "BluetoothAdapter.getBondedDevices()", logcat = listOf("getBondedDevices"), perm = "BLUETOOTH_CONNECT"),
        id("fido.fido2", "FIDO2 / WebAuthn", IdentifierGroup.IDENTITY, "Fido.getFido2ApiClient", logcat = listOf("Fido2ApiClient", "PublicKeyCredential")),
        id("health.connect", "Health Connect", IdentifierGroup.PERSONAL, "HealthConnectClient / HealthConnectManager", logcat = listOf("HealthConnect", "HealthConnectClient"), perm = "HEALTH"),
        id("games.player", "Play Games player ID", IdentifierGroup.IDENTITY, "PlayersClient.getCurrentPlayer", logcat = listOf("PlayersClient", "getCurrentPlayer")),
        id("droidguard", "DroidGuard", IdentifierGroup.ATTESTATION, "com.google.ccc.abuse.droidguard", logcat = listOf("DroidGuard", "droidguard")),
        id("play.recaptcha_ent", "reCAPTCHA Enterprise", IdentifierGroup.IDENTITY, "Recaptcha.getClient / execute", logcat = listOf("RecaptchaAction", "RecaptchaEnterprise")),
        id("autofill", "AutofillManager", IdentifierGroup.IDENTITY, "AutofillManager", logcat = listOf("AutofillManager")),
        id("role.sms", "Default SMS / RoleManager", IdentifierGroup.IDENTITY, "RoleManager.isRoleHeld(ROLE_SMS) / getDefaultSmsPackage", logcat = listOf("RoleManager", "getDefaultSmsPackage")),
        id("keystore.aliases", "AndroidKeyStore aliases", IdentifierGroup.ATTESTATION, "KeyStore.getInstance(AndroidKeyStore).aliases", logcat = listOf("AndroidKeyStore", "KeyStore.aliases")),
        id("keychain", "KeyChain cert/key", IdentifierGroup.ATTESTATION, "KeyChain.getCertificateChain / getPrivateKey", logcat = listOf("KeyChain.getCertificateChain", "KeyChain.getPrivateKey")),
        id("gms.availability", "Play Services version", IdentifierGroup.IDENTITY, "GoogleApiAvailability.isGooglePlayServicesAvailable", logcat = listOf("GoogleApiAvailability", "isGooglePlayServicesAvailable")),
        id("location.settings", "LocationSettings check", IdentifierGroup.LOCATION, "SettingsClient.checkLocationSettings", logcat = listOf("checkLocationSettings", "LocationSettingsRequest")),
        id("location.geocoder", "Geocoder", IdentifierGroup.LOCATION, "Geocoder.getFromLocation", logcat = listOf("Geocoder", "getFromLocation")),
        id("companion", "CompanionDevice", IdentifierGroup.HARDWARE, "CompanionDeviceManager.associate", logcat = listOf("CompanionDeviceManager", "associate")),
        id("launcher.apps", "LauncherApps list", IdentifierGroup.INSTALL, "LauncherApps.getActivityList", logcat = listOf("LauncherApps", "getActivityList")),
        id("notify.enabled", "Notifications enabled", IdentifierGroup.SETTINGS, "NotificationManager.areNotificationsEnabled", logcat = listOf("areNotificationsEnabled")),
        id("download.manager", "DownloadManager", IdentifierGroup.CONTENT_PROVIDER, "DownloadManager.enqueue / query", logcat = listOf("DownloadManager")),
        id("photo.picker", "Photo Picker / READ_MEDIA", IdentifierGroup.CONTENT_PROVIDER, "PickVisualMedia / MediaStore.createWriteRequest", logcat = listOf("PickVisualMedia", "createWriteRequest", "READ_MEDIA")),
        id("user.serial", "UserManager serial", IdentifierGroup.SETTINGS, "UserManager.getSerialNumberForUser", logcat = listOf("getSerialNumberForUser", "UserManager")),
        id("dpm.owner", "Device owner / admin", IdentifierGroup.ENTERPRISE, "DevicePolicyManager.isDeviceOwnerApp / isAdminActive", logcat = listOf("isDeviceOwnerApp", "isProfileOwnerApp", "isAdminActive")),
        id("cell.identity", "CellIdentity MCC/CID/TAC", IdentifierGroup.LOCATION, "CellIdentity.getMccString / getCi / getTac", logcat = listOf("CellIdentity", "getCi", "getTac")),
        id("hw.sensor_list", "Список сенсоров", IdentifierGroup.HARDWARE, "SensorManager.getSensorList / getDefaultSensor", logcat = listOf("getSensorList", "getDefaultSensor")),
        id("hw.battery_capacity", "Ёмкость батареи", IdentifierGroup.HARDWARE, "BatteryManager /sys/class/power_supply", file = "/sys/class/power_supply/battery/charge_full", logcat = listOf("charge_full", "BATTERY_PROPERTY_CHARGE_COUNTER"), strace = listOf("/sys/class/power_supply")),
        id("hw.gles_version", "GLES version", IdentifierGroup.HARDWARE, "ConfigurationInfo.reqGlEsVersion / glGetString(GL_VERSION)", logcat = listOf("reqGlEsVersion", "GL_VERSION")),
        id("hw.codec_list", "MediaCodec list", IdentifierGroup.HARDWARE, "MediaCodecList.getCodecInfos", logcat = listOf("MediaCodecList", "getCodecInfos")),
        id("hw.encryption", "Шифрование хранилища", IdentifierGroup.HARDWARE, "DevicePolicyManager.getStorageEncryptionStatus", logcat = listOf("getStorageEncryptionStatus", "ENCRYPTION_STATUS")),
        id("hw.security_providers", "Security providers", IdentifierGroup.HARDWARE, "Security.getProviders()", logcat = listOf("Security.getProviders", "Provider.getName")),
        id("hw.pin_lock", "PIN / lock screen", IdentifierGroup.HARDWARE, "KeyguardManager.isDeviceSecure / isKeyguardSecure", logcat = listOf("isDeviceSecure", "isKeyguardSecure")),
        id("hw.fp_enrolled", "Биометрия enrolled", IdentifierGroup.HARDWARE, "BiometricManager.canAuthenticate / hasEnrolledTemplates", logcat = listOf("canAuthenticate", "hasEnrolledTemplates", "hasEnrolledFingerprints")),
        id("hw.uptime", "Uptime / elapsedRealtime", IdentifierGroup.HARDWARE, "SystemClock.elapsedRealtime / uptimeMillis", logcat = listOf("elapsedRealtime", "uptimeMillis")),
        id("hw.cores", "Число ядер CPU", IdentifierGroup.HARDWARE, "Runtime.availableProcessors", logcat = listOf("availableProcessors")),
        id("hw.ringtone", "Ringtone URI", IdentifierGroup.HARDWARE, "RingtoneManager.getActualDefaultRingtoneUri", logcat = listOf("getActualDefaultRingtoneUri")),
        id("hw.locales", "Available locales", IdentifierGroup.HARDWARE, "Locale.getAvailableLocales / AssetManager.getLocales", logcat = listOf("getAvailableLocales")),
        id("hw.dark_mode", "Dark / night mode", IdentifierGroup.HARDWARE, "Configuration.uiMode / UiModeManager", logcat = listOf("uiMode", "UiModeManager", "NIGHT_YES")),
        id("hw.ringer", "Ringer mode", IdentifierGroup.HARDWARE, "AudioManager.getRingerMode", logcat = listOf("getRingerMode")),
        id("hw.webview_pkg", "WebView package / version", IdentifierGroup.HARDWARE, "WebView.getCurrentWebViewPackage", logcat = listOf("getCurrentWebViewPackage", "WebViewProvider")),
        id("proc.uptime", "/proc/uptime", IdentifierGroup.PROC_SYS, file = "/proc/uptime", strace = listOf("/proc/uptime")),
        id("proc.stat", "/proc/stat", IdentifierGroup.PROC_SYS, file = "/proc/stat", strace = listOf("/proc/stat")),
        id("sys.cpu_freq", "CPU frequency", IdentifierGroup.PROC_SYS, file = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", strace = listOf("cpufreq")),
        id("attest.vbmeta", "vbmeta digest", IdentifierGroup.ATTESTATION, systemProp = "ro.boot.vbmeta.digest", logcat = listOf("vbmeta.digest", "vbmeta_digest")),
        id("attest.flash_locked", "Bootloader lock", IdentifierGroup.ATTESTATION, systemProp = "ro.boot.flash.locked", logcat = listOf("flash.locked", "ro.boot.flash.locked")),
        id("attest.warranty", "Warranty bit", IdentifierGroup.ATTESTATION, systemProp = "ro.boot.warranty_bit", logcat = listOf("warranty_bit")),
        id("wifi.dhcp", "DHCP / gateway", IdentifierGroup.WIFI, "WifiManager.getDhcpInfo", logcat = listOf("getDhcpInfo", "DhcpInfo")),
        id("net.capabilities", "NetworkCapabilities", IdentifierGroup.NETWORK, "ConnectivityManager.getNetworkCapabilities", logcat = listOf("getNetworkCapabilities", "NET_CAPABILITY"))
    )

    /**
     * Сигналы, которые собирают Matrix/ThreatMetrix, TrustDecision, FingerprintJS,
     * SEON, Sift, Forter, iovation, Tongdun, Group-IB, KFP и похожие antifraud SDK.
     * Событие — только если целевое приложение само запросило API / вызвало SDK.
     */
    private fun fraudFingerprintIdentifiers() = listOf(
        id("fraud.tmx", "ThreatMetrix / Matrix", IdentifierGroup.FRAUD, "TMXProfiling.profile / TrustDefender", logcat = listOf("TMXProfiling", "TrustDefender", "ThreatMetrix", "lexisnexis.tmsdk", "doProfileRequest")),
        id("fraud.trustdecision", "TrustDecision / Tongdun", IdentifierGroup.FRAUD, "TDRisk / FMAgent", logcat = listOf("TrustDecision", "TDRisk", "tongdun", "FMAgent", "cn.tongdun")),
        id("fraud.fingerprintjs", "FingerprintJS / Fingerprint Pro", IdentifierGroup.FRAUD, "Fingerprinter.getFingerprint / getDeviceId", logcat = listOf("fingerprintjs", "Fingerprinter", "com.fingerprint.android")),
        id("fraud.seon", "SEON Device Fingerprinting", IdentifierGroup.FRAUD, "io.seon.androidsdk", logcat = listOf("io.seon", "SeonBuilder", "getFingerprintBase64")),
        id("fraud.sift", "Sift Science", IdentifierGroup.FRAUD, "siftscience.android.Sift", logcat = listOf("siftscience", "Sift.collect")),
        id("fraud.forter", "Forter", IdentifierGroup.FRAUD, "com.forter.mobile", logcat = listOf("forter.mobile", "ForterMobile")),
        id("fraud.iovation", "iovation / TransUnion", IdentifierGroup.FRAUD, "com.iovation.mobile", logcat = listOf("iovation", "FraudForceManager")),
        id("fraud.kount", "Kount", IdentifierGroup.FRAUD, "com.kount.api", logcat = listOf("kount.api", "KountSDK")),
        id("fraud.groupib", "Group-IB / F.A.C.C.T.", IdentifierGroup.FRAUD, "com.group_ib / ru.group_ib", logcat = listOf("group_ib", "groupib", "F.A.C.C.T", "facct")),
        id("fraud.kfp", "Kaspersky Fraud Prevention", IdentifierGroup.FRAUD, "com.kaspersky.kfp", logcat = listOf("kaspersky.kfp", "KFPSdk", "KasperskyFraud")),
        id("fraud.shumeng", "Shumeng / iShumei", IdentifierGroup.FRAUD, "com.ishumei.smantifraud", logcat = listOf("ishumei", "SmAntiFraud", "shumei")),
        id("fraud.appsflyer", "AppsFlyer Protect360", IdentifierGroup.FRAUD, "com.appsflyer.AppsFlyerLib", logcat = listOf("AppsFlyerLib", "appsflyer")),
        id("fraud.adjust", "Adjust Fraud Prevention", IdentifierGroup.FRAUD, "com.adjust.sdk.Adjust", logcat = listOf("com.adjust.sdk", "Adjust.getAdid")),
        id("fraud.incognia", "Incognia", IdentifierGroup.FRAUD, "com.incognia.Incognia", logcat = listOf("incognia", "Incognia")),
        id("fraud.biocatch", "BioCatch / BehavioSec", IdentifierGroup.FRAUD, "com.biocatch / com.behaviosec", logcat = listOf("biocatch", "BehavioSec", "TMXBehavioral")),
        id("fraud.sumsub", "Sumsub Device Intel", IdentifierGroup.FRAUD, "com.sumsub.sns", logcat = listOf("sumsub", "SNSMobileSDK")),
        id("fraud.clone", "Clone / filesDir path", IdentifierGroup.FRAUD, "Context.getFilesDir / /data/user/999", logcat = listOf("getFilesDir", "getDataDir"), strace = listOf("/data/user/999", "/data/user/10")),
        id("fraud.work_profile", "Work / managed profile", IdentifierGroup.FRAUD, "UserManager.isManagedProfile / getUserProfiles", logcat = listOf("isManagedProfile", "getUserProfiles", "isProfile")),
        id("fraud.dual_app", "Dual app / Parallel Space", IdentifierGroup.FRAUD, "PackageManager.getPackageInfo(parallel/dual)", logcat = listOf("com.lbe.parallel", "com.excelliance", "com.dual.dualspace", "com.oplus.multiapp", "com.samsung.android.da.daagent")),
        id("fraud.factory_reset", "Factory reset / first boot", IdentifierGroup.FRAUD, "Settings.Global.boot_count + firstInstallTime", logcat = listOf("factory.?reset", "first_boot")),
        id("fraud.harmony", "HarmonyOS / EMUI", IdentifierGroup.FRAUD, "SystemProperties hw_sc.build / ro.build.version.emui", systemProp = "ro.build.version.emui", logcat = listOf("HarmonyOS", "hw_sc.build", "ro.build.version.emui")),
        id("fraud.canvas", "Canvas fingerprint (WebView)", IdentifierGroup.FRAUD, "WebView.evaluateJavascript(toDataURL/canvas)", logcat = listOf("toDataURL", "getImageData", "canvas fingerprint")),
        id("fraud.webgl", "WebGL vendor/renderer", IdentifierGroup.FRAUD, "WebGLRenderingContext.getParameter / UNMASKED", logcat = listOf("UNMASKED_VENDOR", "UNMASKED_RENDERER", "webgl")),
        id("fraud.audio_fp", "Audio fingerprint", IdentifierGroup.FRAUD, "AudioTrack / AudioContext oscillator", logcat = listOf("AudioContext", "createOscillator", "audio fingerprint")),
        id("fraud.touch", "Behavioral touch / swipe", IdentifierGroup.FRAUD, "View.dispatchTouchEvent / MotionEvent", logcat = listOf("dispatchTouchEvent", "OnTouchListener")),
        id("fraud.wifi_on", "Wi‑Fi enabled", IdentifierGroup.FRAUD, "WifiManager.isWifiEnabled", logcat = listOf("isWifiEnabled")),
        id("fraud.bt_on", "Bluetooth enabled", IdentifierGroup.FRAUD, "BluetoothAdapter.isEnabled", logcat = listOf("BluetoothAdapter.isEnabled")),
        id("fraud.location_on", "Location enabled", IdentifierGroup.FRAUD, "LocationManager.isLocationEnabled / isProviderEnabled", logcat = listOf("isLocationEnabled", "isProviderEnabled")),
        id("fraud.cast", "Cast / virtual display", IdentifierGroup.FRAUD, "DisplayManager.getDisplays / MediaRouter", logcat = listOf("DisplayManager.getDisplays", "virtual display", "MediaRouter")),
        id("fraud.talkback", "TalkBack / AccessibilityManager", IdentifierGroup.FRAUD, "AccessibilityManager.isTouchExplorationEnabled / getEnabledAccessibilityServiceList", logcat = listOf("isTouchExplorationEnabled", "getEnabledAccessibilityServiceList")),
        id("fraud.mock_apps", "Fake GPS / mock location apps", IdentifierGroup.FRAUD, "PackageManager.getPackageInfo(fakegps/joystick)", logcat = listOf("fakegps", "fake.?gps", "gpsjoystick", "com.lexa.fakegps")),
        id("fraud.vpn_apps", "VPN client packages", IdentifierGroup.FRAUD, "PackageManager.getPackageInfo(vpn/outline/wireguard)", logcat = listOf("org.torproject", "com.wireguard", "org.outline")),
        id("fraud.auto_click", "Auto-clicker / accessibility fraud", IdentifierGroup.FRAUD, "enabled_accessibility_services clicker", logcat = listOf("autoclick", "auto.?click", "clicker")),
        id("fraud.elapsed", "SystemClock elapsed (session age)", IdentifierGroup.FRAUD, "SystemClock.elapsedRealtimeNanos", logcat = listOf("elapsedRealtimeNanos")),
        id("net.stun", "STUN / WebRTC real IP", IdentifierGroup.NETWORK, "PeerConnection / STUN binding", logcat = listOf("PeerConnection", "stun:", "iceCandidate", "RTCPeerConnection"))
    )

    /**
     * Что браузер / WebView / JS-fingerprint может запросить.
     * Источники: AOSP android.webkit.*, androidx.webkit, Chromium AwSettings,
     * Custom Tabs/TWA, FingerprintJS (browser), CreepJS.
     */
    private fun browserIdentifiers() = listOf(
        id("browser.default_ua", "Default User-Agent", IdentifierGroup.BROWSER, "WebSettings.getDefaultUserAgent", logcat = listOf("getDefaultUserAgent")),
        id("browser.ua_meta", "UA Client Hints metadata", IdentifierGroup.BROWSER, "WebSettingsCompat.getUserAgentMetadata / AwUserAgentMetadata", logcat = listOf("UserAgentMetadata", "setUserAgentMetadata", "AwUserAgentMetadata")),
        id("browser.ch_ua", "Sec-CH-UA / userAgentData", IdentifierGroup.BROWSER, "navigator.userAgentData.getHighEntropyValues / Sec-CH-UA", logcat = listOf("Sec-CH-UA", "userAgentData", "getHighEntropyValues")),
        id("browser.safe_browsing", "Safe Browsing", IdentifierGroup.BROWSER, "WebView.startSafeBrowsing / setSafeBrowsingEnabled", logcat = listOf("startSafeBrowsing", "setSafeBrowsingEnabled", "SafeBrowsing")),
        id("browser.custom_tabs", "Chrome Custom Tabs", IdentifierGroup.BROWSER, "CustomTabsIntent / CustomTabsClient.bindCustomTabsService", logcat = listOf("CustomTabsIntent", "CustomTabsClient", "CustomTabsSession", "bindCustomTabsService")),
        id("browser.twa", "Trusted Web Activity", IdentifierGroup.BROWSER, "TrustedWebUtils / TwaLauncher", logcat = listOf("TrustedWebUtils", "TwaLauncher", "TrustedWebActivity")),
        id("browser.js_interface", "addJavascriptInterface", IdentifierGroup.BROWSER, "WebView.addJavascriptInterface", logcat = listOf("addJavascriptInterface", "removeJavascriptInterface")),
        id("browser.web_message", "WebMessage / JS bridge", IdentifierGroup.BROWSER, "WebViewCompat.addWebMessageListener / postWebMessage", logcat = listOf("addWebMessageListener", "postWebMessage", "createWebMessageChannel")),
        id("browser.geolocation_js", "WebView geolocation", IdentifierGroup.BROWSER, "WebChromeClient.onGeolocationPermissionsShowPrompt / setGeolocationEnabled", logcat = listOf("onGeolocationPermissionsShowPrompt", "setGeolocationEnabled")),
        id("browser.permission_req", "WebView PermissionRequest", IdentifierGroup.BROWSER, "WebChromeClient.onPermissionRequest", logcat = listOf("onPermissionRequest", "RESOURCE_VIDEO_CAPTURE", "RESOURCE_AUDIO_CAPTURE")),
        id("browser.eme", "EME / protected media ID", IdentifierGroup.BROWSER, "PermissionRequest.RESOURCE_PROTECTED_MEDIA_ID / requestMediaKeySystemAccess", logcat = listOf("RESOURCE_PROTECTED_MEDIA_ID", "requestMediaKeySystemAccess", "MediaKeys")),
        id("browser.file_chooser", "WebView file chooser", IdentifierGroup.BROWSER, "WebChromeClient.onShowFileChooser", logcat = listOf("onShowFileChooser", "FileChooserParams")),
        id("browser.ssl_error", "WebView SSL error", IdentifierGroup.BROWSER, "WebViewClient.onReceivedSslError", logcat = listOf("onReceivedSslError", "SslErrorHandler")),
        id("browser.client_cert", "WebView client cert", IdentifierGroup.BROWSER, "WebViewClient.onReceivedClientCertRequest", logcat = listOf("onReceivedClientCertRequest", "ClientCertRequest")),
        id("browser.http_auth", "WebView HTTP auth", IdentifierGroup.BROWSER, "WebViewClient.onReceivedHttpAuthRequest", logcat = listOf("onReceivedHttpAuthRequest", "HttpAuthHandler")),
        id("browser.intercept", "shouldInterceptRequest", IdentifierGroup.BROWSER, "WebViewClient.shouldInterceptRequest", logcat = listOf("shouldInterceptRequest")),
        id("browser.web_storage", "WebStorage / origins", IdentifierGroup.BROWSER, "WebStorage.getOrigins / deleteAllData", logcat = listOf("WebStorage", "getOrigins")),
        id("browser.web_db", "WebViewDatabase", IdentifierGroup.BROWSER, "WebViewDatabase.getInstance", logcat = listOf("WebViewDatabase")),
        id("browser.service_worker", "ServiceWorkerController", IdentifierGroup.BROWSER, "ServiceWorkerController.getInstance", logcat = listOf("ServiceWorkerController", "ServiceWorkerClient")),
        id("browser.cookie_3p", "Third-party cookies", IdentifierGroup.BROWSER, "CookieManager.setAcceptThirdPartyCookies", logcat = listOf("setAcceptThirdPartyCookies", "acceptThirdPartyCookies")),
        id("browser.debug", "WebView remote debug", IdentifierGroup.BROWSER, "WebView.setWebContentsDebuggingEnabled", logcat = listOf("setWebContentsDebuggingEnabled", "webContentsDebugging")),
        id("browser.proxy", "WebView proxy override", IdentifierGroup.BROWSER, "ProxyController.setProxyOverride", logcat = listOf("ProxyController", "setProxyOverride")),
        id("browser.profile", "WebView Profile", IdentifierGroup.BROWSER, "androidx.webkit.Profile / ProfileStore", logcat = listOf("ProfileStore", "webkit.Profile")),
        id("browser.variations", "Chrome Variations header", IdentifierGroup.BROWSER, "WebViewCompat.getVariationsHeader", logcat = listOf("getVariationsHeader", "X-Client-Data")),
        id("browser.xrw", "X-Requested-With (package)", IdentifierGroup.BROWSER, "X-Requested-With header", logcat = listOf("X-Requested-With", "RequestedWithHeader")),
        id("browser.multiprocess", "WebView multiprocess", IdentifierGroup.BROWSER, "WebView.isMultiProcessEnabled / getWebViewClassLoader", logcat = listOf("isMultiProcessEnabled", "getWebViewClassLoader")),
        id("browser.feature", "WebViewFeature", IdentifierGroup.BROWSER, "WebViewFeature.isFeatureSupported", logcat = listOf("WebViewFeature", "isFeatureSupported")),
        id("browser.dark", "WebView force dark", IdentifierGroup.BROWSER, "WebSettingsCompat.setForceDark / setAlgorithmicDarkeningAllowed", logcat = listOf("setForceDark", "setAlgorithmicDarkeningAllowed")),
        id("browser.dom_storage", "DOM storage enabled", IdentifierGroup.BROWSER, "WebSettings.setDomStorageEnabled", logcat = listOf("setDomStorageEnabled", "getDomStorageEnabled")),
        id("browser.fonts_css", "WebSettings font families", IdentifierGroup.BROWSER, "WebSettings.getStandardFontFamily / getSansSerifFontFamily", logcat = listOf("getStandardFontFamily", "getFixedFontFamily", "getSansSerifFontFamily")),
        id("browser.intent", "ACTION_VIEW http(s)", IdentifierGroup.BROWSER, "Intent.ACTION_VIEW browser resolve", logcat = listOf("CustomTabsIntent", "startActivity.*https")),
        id("browser.geckoview", "GeckoView / Firefox", IdentifierGroup.BROWSER, "org.mozilla.geckoview.GeckoRuntime", logcat = listOf("GeckoRuntime", "GeckoSession", "geckoview")),
        id("browser.chromium_aw", "Chromium AwSettings", IdentifierGroup.BROWSER, "org.chromium.android_webview.AwSettings", logcat = listOf("AwSettings", "AwContents", "AwCookieManager")),
        id("browser.fp_lib", "FingerprintJS / CreepJS / ClientJS", IdentifierGroup.BROWSER, "FingerprintJS / creepjs / ClientJS / Thumbmark", logcat = listOf("FingerprintJS", "fingerprintjs", "creepjs", "ClientJS", "ThumbmarkJS")),
        id("browser.canvas", "Canvas 2D fingerprint", IdentifierGroup.BROWSER, "canvas.toDataURL / getImageData / OffscreenCanvas", logcat = listOf("toDataURL", "OffscreenCanvas")),
        id("browser.webgl", "WebGL / GPU params", IdentifierGroup.BROWSER, "WEBGL_debug_renderer_info / getSupportedExtensions", logcat = listOf("WEBGL_debug_renderer_info", "getSupportedExtensions")),
        id("browser.audio", "Web Audio fingerprint", IdentifierGroup.BROWSER, "AudioContext / OfflineAudioContext", logcat = listOf("OfflineAudioContext", "createDynamicsCompressor")),
        id("browser.fonts", "JS font enumeration", IdentifierGroup.BROWSER, "queryLocalFonts / measureText / offsetWidth", logcat = listOf("queryLocalFonts", "document.fonts")),
        id("browser.speech", "speechSynthesis voices", IdentifierGroup.BROWSER, "speechSynthesis.getVoices", logcat = listOf("speechSynthesis", "getVoices")),
        id("browser.math", "Math fingerprint", IdentifierGroup.BROWSER, "Math.tan/sinh/expm1", logcat = listOf("Math.sinh", "math fingerprint")),
        id("browser.navigator", "navigator platform/vendor/plugins", IdentifierGroup.BROWSER, "navigator.platform / vendor / plugins / mimeTypes", logcat = listOf("navigator.platform", "navigator.plugins", "pdfViewerEnabled")),
        id("browser.ua_data", "navigator.userAgentData", IdentifierGroup.BROWSER, "navigator.userAgentData.brands / mobile / platform", logcat = listOf("userAgentData")),
        id("browser.hardware_concurrency", "navigator.hardwareConcurrency", IdentifierGroup.BROWSER, "navigator.hardwareConcurrency", logcat = listOf("hardwareConcurrency")),
        id("browser.device_memory", "navigator.deviceMemory", IdentifierGroup.BROWSER, "navigator.deviceMemory", logcat = listOf("deviceMemory")),
        id("browser.media_devices", "enumerateDevices / getUserMedia", IdentifierGroup.BROWSER, "navigator.mediaDevices.enumerateDevices", logcat = listOf("enumerateDevices", "getUserMedia", "mediaDevices")),
        id("browser.connection", "Network Information API", IdentifierGroup.BROWSER, "navigator.connection.effectiveType / downlink / rtt", logcat = listOf("navigator.connection")),
        id("browser.battery_js", "Battery Status API", IdentifierGroup.BROWSER, "navigator.getBattery", logcat = listOf("navigator.getBattery")),
        id("browser.screen_js", "screen / devicePixelRatio", IdentifierGroup.BROWSER, "screen.width / colorDepth / devicePixelRatio", logcat = listOf("devicePixelRatio", "colorDepth", "pixelDepth")),
        id("browser.css_media", "CSS media queries", IdentifierGroup.BROWSER, "matchMedia prefers-color-scheme / reduced-motion / hdr / gamut", logcat = listOf("prefers-color-scheme", "prefers-reduced-motion", "color-gamut", "dynamic-range")),
        id("browser.intl", "Intl / timezone JS", IdentifierGroup.BROWSER, "Intl.DateTimeFormat.resolvedOptions", logcat = listOf("resolvedOptions", "DateTimeFormat")),
        id("browser.languages", "navigator.languages", IdentifierGroup.BROWSER, "navigator.languages / language", logcat = listOf("navigator.languages")),
        id("browser.webdriver", "navigator.webdriver / headless", IdentifierGroup.BROWSER, "navigator.webdriver / HeadlessChrome / domAutomation", logcat = listOf("navigator.webdriver", "HeadlessChrome", "domAutomation")),
        id("browser.permissions_js", "Permissions API", IdentifierGroup.BROWSER, "navigator.permissions.query", logcat = listOf("permissions.query")),
        id("browser.storage_js", "localStorage / indexedDB / sessionStorage", IdentifierGroup.BROWSER, "indexedDB.open / localStorage / openDatabase", logcat = listOf("indexedDB", "localStorage", "sessionStorage", "openDatabase")),
        id("browser.storage_est", "StorageManager.estimate", IdentifierGroup.BROWSER, "navigator.storage.estimate / persist", logcat = listOf("storage.estimate", "navigator.storage")),
        id("browser.webgpu", "WebGPU adapter", IdentifierGroup.BROWSER, "navigator.gpu.requestAdapter", logcat = listOf("navigator.gpu", "requestAdapter", "WebGPU")),
        id("browser.worker", "Worker / ServiceWorker JS", IdentifierGroup.BROWSER, "Worker / SharedWorker / serviceWorker.register", logcat = listOf("serviceWorker.register", "SharedWorker")),
        id("browser.domrect", "DOMRect / getClientRects", IdentifierGroup.BROWSER, "getClientRects / getBoundingClientRect", logcat = listOf("getClientRects")),
        id("browser.notification_js", "Notification.permission", IdentifierGroup.BROWSER, "Notification.requestPermission", logcat = listOf("Notification.requestPermission")),
        id("browser.webauthn_js", "WebAuthn in page", IdentifierGroup.BROWSER, "navigator.credentials.create / get", logcat = listOf("navigator.credentials", "PublicKeyCredential")),
        id("browser.topics_js", "Topics / Privacy Sandbox JS", IdentifierGroup.BROWSER, "document.browsingTopics / sharedStorage", logcat = listOf("browsingTopics", "sharedStorage", "privateAggregation")),
        id("browser.performance", "performance.memory / now", IdentifierGroup.BROWSER, "performance.memory / performance.now", logcat = listOf("performance.memory", "jsHeapSizeLimit"))
    )

    /**
     * Поверхности, которых не было: GNSS extras, Places/Awareness, сенсоры,
     * VAID/AAID, OMAPI, Nearby, EXIF, thermal/fold, satellite, identity credential.
     */
    private fun missedSurfaceIdentifiers() = listOf(
        id("location.gnss_antenna", "GNSS antenna info", IdentifierGroup.LOCATION, "LocationManager.registerAntennaInfoListener / GnssAntennaInfo", logcat = listOf("registerAntennaInfoListener", "GnssAntennaInfo"), perm = "ACCESS_FINE_LOCATION"),
        id("location.gnss_caps", "GNSS hardware model / year", IdentifierGroup.LOCATION, "getGnssCapabilities / getGnssHardwareModelName / getGnssYearOfHardware", logcat = listOf("getGnssCapabilities", "getGnssHardwareModelName", "getGnssYearOfHardware")),
        id("location.gnss_clock", "GnssClock / full measurements", IdentifierGroup.LOCATION, "registerGnssMeasurementsCallback / GnssClock", logcat = listOf("GnssClock", "registerGnssMeasurementsCallback"), perm = "ACCESS_FINE_LOCATION"),
        id("location.providers", "Location providers list", IdentifierGroup.LOCATION, "getProviders / getAllProviders / getProviderProperties", logcat = listOf("getAllProviders", "getProviderProperties", "getBestProvider")),
        id("location.extras", "Location extras (sats / NLP type)", IdentifierGroup.LOCATION, "Location.getExtras / getSatelliteCount", logcat = listOf("getExtras", "satellites", "networkLocationType")),
        id("location.mock_test", "Test / mock location provider", IdentifierGroup.LOCATION, "addTestProvider / setTestProviderLocation", logcat = listOf("addTestProvider", "setTestProviderLocation", "setTestProviderEnabled")),
        id("location.altitude", "MSL altitude / AltitudeConverter", IdentifierGroup.LOCATION, "Location.getMslAltitudeMeters / AltitudeConverter", logcat = listOf("getMslAltitudeMeters", "AltitudeConverter")),
        id("location.awareness", "Awareness Snapshot / Fence", IdentifierGroup.LOCATION, "Awareness.getSnapshotClient / getFenceClient", logcat = listOf("Awareness", "SnapshotClient", "FenceClient")),
        id("location.places", "Places current place", IdentifierGroup.LOCATION, "PlacesClient.findCurrentPlace", logcat = listOf("findCurrentPlace", "PlacesClient", "PlaceLikelihood")),
        id("location.orientation", "Fused orientation / heading", IdentifierGroup.LOCATION, "FusedOrientationProviderClient / DeviceOrientationRequest", logcat = listOf("FusedOrientation", "DeviceOrientationRequest")),
        id("location.transition", "Activity transition / sleep", IdentifierGroup.LOCATION, "ActivityTransitionRequest / SleepSegmentRequest", logcat = listOf("ActivityTransition", "SleepSegmentRequest")),
        id("location.izat", "Qualcomm IZat / FLP", IdentifierGroup.LOCATION, "com.qti.location / IZat / FlpService", logcat = listOf("IZat", "FlpService", "com.qti.location", "izat")),
        id("location.cmd", "sendExtraCommand (xtra/aiding)", IdentifierGroup.LOCATION, "LocationManager.sendExtraCommand", logcat = listOf("sendExtraCommand", "force_xtra", "delete_aiding")),
        id("location.proximity", "Proximity alert", IdentifierGroup.LOCATION, "LocationManager.addProximityAlert", logcat = listOf("addProximityAlert")),
        id("location.current", "getCurrentLocation / CurrentLocationRequest", IdentifierGroup.LOCATION, "getCurrentLocation / CurrentLocationRequest", logcat = listOf("CurrentLocationRequest", "LastLocationRequest")),
        id("location.semantic", "Semantic location", IdentifierGroup.LOCATION, "SemanticLocation / Incognia-like", logcat = listOf("SemanticLocation")),
        id("sensor.direct", "SensorDirectChannel", IdentifierGroup.HARDWARE, "SensorManager.createDirectChannel", logcat = listOf("createDirectChannel", "SensorDirectChannel")),
        id("sensor.trigger", "Trigger sensors", IdentifierGroup.HARDWARE, "SensorManager.requestTriggerSensor", logcat = listOf("requestTriggerSensor", "TriggerEventListener")),
        id("sensor.dynamic", "Dynamic sensors", IdentifierGroup.HARDWARE, "registerDynamicSensorCallback", logcat = listOf("registerDynamicSensorCallback", "getDynamicSensorList")),
        id("sensor.additional", "SensorAdditionalInfo", IdentifierGroup.HARDWARE, "SensorEventCallback.onSensorAdditionalInfo", logcat = listOf("SensorAdditionalInfo")),
        id("sensor.privacy", "SensorPrivacyManager", IdentifierGroup.HARDWARE, "SensorPrivacyManager.areAnySensorPrivacyTogglesEnabled", logcat = listOf("SensorPrivacyManager", "sensor.?privacy")),
        id("sensor.heading", "TYPE_HEADING", IdentifierGroup.HARDWARE, "Sensor.TYPE_HEADING", logcat = listOf("TYPE_HEADING")),
        id("sensor.hinge", "Hinge angle / fold", IdentifierGroup.HARDWARE, "Sensor.TYPE_HINGE_ANGLE / DeviceStateManager", logcat = listOf("TYPE_HINGE_ANGLE", "DeviceStateManager", "HingeAngle")),
        id("sensor.head_tracker", "Head tracker", IdentifierGroup.HARDWARE, "Sensor.TYPE_HEAD_TRACKER", logcat = listOf("TYPE_HEAD_TRACKER")),
        id("sensor.step", "Step counter / detector", IdentifierGroup.HARDWARE, "TYPE_STEP_COUNTER / TYPE_STEP_DETECTOR", logcat = listOf("TYPE_STEP_COUNTER", "TYPE_STEP_DETECTOR", "StepCounter"), perm = "ACTIVITY_RECOGNITION"),
        id("sensor.heart", "Heart rate / body sensors", IdentifierGroup.HARDWARE, "TYPE_HEART_RATE / TYPE_HEART_BEAT", logcat = listOf("TYPE_HEART_RATE", "TYPE_HEART_BEAT"), perm = "BODY_SENSORS"),
        id("sensor.pressure", "Barometer / pressure", IdentifierGroup.HARDWARE, "Sensor.TYPE_PRESSURE", logcat = listOf("TYPE_PRESSURE")),
        id("sensor.light", "Ambient light", IdentifierGroup.HARDWARE, "Sensor.TYPE_LIGHT", logcat = listOf("TYPE_LIGHT")),
        id("sensor.proximity", "Proximity sensor", IdentifierGroup.HARDWARE, "Sensor.TYPE_PROXIMITY", logcat = listOf("TYPE_PROXIMITY")),
        id("sensor.uncalibrated", "Uncalibrated IMU / mag", IdentifierGroup.HARDWARE, "TYPE_*_UNCALIBRATED", logcat = listOf("UNCALIBRATED")),
        id("sensor.geomagnetic", "GeomagneticField", IdentifierGroup.HARDWARE, "android.hardware.GeomagneticField", logcat = listOf("GeomagneticField")),
        id("sensor.high_rate", "High sampling rate sensors", IdentifierGroup.HARDWARE, "HIGH_SAMPLING_RATE_SENSORS", logcat = listOf("HIGH_SAMPLING_RATE_SENSORS"), perm = "HIGH_SAMPLING_RATE_SENSORS"),
        id("sensor.offbody", "Off-body detect", IdentifierGroup.HARDWARE, "TYPE_LOW_LATENCY_OFFBODY_DETECT", logcat = listOf("OFFBODY_DETECT")),
        id("sensor.significant", "Significant motion", IdentifierGroup.HARDWARE, "TYPE_SIGNIFICANT_MOTION", logcat = listOf("TYPE_SIGNIFICANT_MOTION")),
        id("ad.vaid", "VAID (MSA)", IdentifierGroup.ADVERTISING, "IdProvider.getVAID / MdidSdk VAID", logcat = listOf("getVAID", "VAID")),
        id("ad.aaid", "AAID (MSA)", IdentifierGroup.ADVERTISING, "IdProvider.getAAID", logcat = listOf("getAAID", "AAID")),
        id("ad.udid", "UDID (OEM)", IdentifierGroup.ADVERTISING, "IdProvider.getUDID", logcat = listOf("getUDID", "UDID")),
        id("ad.guid", "Vivo GUID", IdentifierGroup.ADVERTISING, "IdentifierManager.getGuid", logcat = listOf("getGuid", "VivoGuid")),
        id("ad.app_instance", "Firebase Analytics appInstanceId", IdentifierGroup.ADVERTISING, "FirebaseAnalytics.getAppInstanceId", logcat = listOf("getAppInstanceId", "appInstanceId")),
        id("ad.metrica", "Yandex AppMetrica device id", IdentifierGroup.ADVERTISING, "YandexMetrica.getStartupParams / deviceId", logcat = listOf("YandexMetrica", "AppMetrica", "yandex.metrica")),
        id("ad.amplitude", "Amplitude / Mixpanel device id", IdentifierGroup.ADVERTISING, "Amplitude.getDeviceId / MixpanelAPI", logcat = listOf("Amplitude.getDeviceId", "MixpanelAPI")),
        id("drm.clearkey", "ClearKey DRM", IdentifierGroup.DRM, "MediaDrm ClearKey UUID", logcat = listOf("clearkey", "ClearKey")),
        id("drm.wiseplay", "WisePlay DRM", IdentifierGroup.DRM, "MediaDrm WisePlay", logcat = listOf("WisePlay", "wiseplay")),
        id("tel.signal", "SignalStrength", IdentifierGroup.TELEPHONY, "TelephonyManager.getSignalStrength", logcat = listOf("getSignalStrength", "SignalStrength")),
        id("tel.display_info", "TelephonyDisplayInfo", IdentifierGroup.TELEPHONY, "getTelephonyDisplayInfo / overrideNetworkType", logcat = listOf("TelephonyDisplayInfo", "getOverrideNetworkType")),
        id("tel.satellite", "SatelliteManager", IdentifierGroup.TELEPHONY, "android.telephony.satellite.SatelliteManager", logcat = listOf("SatelliteManager", "requestSatelliteEnabled")),
        id("tel.emergency", "Emergency numbers", IdentifierGroup.TELEPHONY, "TelephonyManager.getEmergencyNumberList", logcat = listOf("getEmergencyNumberList", "EmergencyNumber")),
        id("tel.physical_channel", "PhysicalChannelConfig", IdentifierGroup.TELEPHONY, "getPhysicalChannelConfigList", logcat = listOf("PhysicalChannelConfig")),
        id("tel.barring", "BarringInfo", IdentifierGroup.TELEPHONY, "TelephonyManager.getBarringInfo", logcat = listOf("getBarringInfo", "BarringInfo")),
        id("tel.ims", "IMS / VoNR / Wi‑Fi calling", IdentifierGroup.TELEPHONY, "ImsMmTelManager / isAvailable", logcat = listOf("ImsMmTelManager", "isVoNrAvailable", "WifiCalling")),
        id("tel.omapi", "OMAPI / Secure Element", IdentifierGroup.TELEPHONY, "org.simalliance.openmobileapi.SEService / android.se.omapi", logcat = listOf("SEService", "android.se.omapi", "OpenMobileAPI")),
        id("tel.uicc", "UiccCardsInfo", IdentifierGroup.TELEPHONY, "TelephonyManager.getUiccCardsInfo", logcat = listOf("getUiccCardsInfo", "UiccCardInfo")),
        id("tel.phone_account", "PhoneAccount handles", IdentifierGroup.TELEPHONY, "TelecomManager.getCallCapablePhoneAccounts", logcat = listOf("getCallCapablePhoneAccounts", "PhoneAccountHandle")),
        id("nearby.connections", "Nearby Connections", IdentifierGroup.BLUETOOTH, "Nearby.getConnectionsClient", logcat = listOf("ConnectionsClient", "NearbyConnections")),
        id("nearby.messages", "Nearby Messages", IdentifierGroup.BLUETOOTH, "Nearby.getMessagesClient", logcat = listOf("MessagesClient", "NearbyMessages")),
        id("nearby.share", "Nearby Share / Quick Share", IdentifierGroup.BLUETOOTH, "Nearby.getSharing", logcat = listOf("NearbyShare", "QuickShare", "com.google.android.gms.nearby.sharing")),
        id("nearby.fastpair", "Fast Pair", IdentifierGroup.BLUETOOTH, "FastPair / Nearby.fastPair", logcat = listOf("FastPair", "fastpair")),
        id("bt.advertise", "BLE advertise", IdentifierGroup.BLUETOOTH, "BluetoothLeAdvertiser.startAdvertising", logcat = listOf("startAdvertising", "BluetoothLeAdvertiser")),
        id("bt.gatt", "BLE GATT", IdentifierGroup.BLUETOOTH, "BluetoothGatt / BluetoothGattServer", logcat = listOf("BluetoothGatt", "connectGatt")),
        id("bt.beacon", "Beacon / iBeacon / Eddystone", IdentifierGroup.BLUETOOTH, "BeaconParser / Eddystone / AltBeacon", logcat = listOf("iBeacon", "Eddystone", "AltBeacon", "BeaconParser")),
        id("wifi.softap", "SoftAp / local hotspot", IdentifierGroup.WIFI, "WifiManager.startLocalOnlyHotspot / SoftAp", logcat = listOf("startLocalOnlyHotspot", "SoftApCallback")),
        id("wifi.suggestion", "WifiNetworkSuggestion", IdentifierGroup.WIFI, "WifiManager.addNetworkSuggestions", logcat = listOf("WifiNetworkSuggestion", "addNetworkSuggestions")),
        id("wifi.standard", "Wi‑Fi standard (6/7)", IdentifierGroup.WIFI, "WifiInfo.getWifiStandard / getFrequency", logcat = listOf("getWifiStandard", "FREQUENCY_6GHZ")),
        id("wifi.randomized_mac", "Randomized Wi‑Fi MAC", IdentifierGroup.WIFI, "WifiInfo.getRandomizedMacAddress", logcat = listOf("getRandomizedMacAddress", "MacRandomization")),
        id("net.captive", "Captive portal", IdentifierGroup.NETWORK, "NET_CAPABILITY_CAPTIVE_PORTAL / CaptivePortal", logcat = listOf("CAPTIVE_PORTAL", "CaptivePortal")),
        id("net.arp", "/proc/net/arp", IdentifierGroup.NETWORK, file = "/proc/net/arp", strace = listOf("/proc/net/arp")),
        id("net.route", "/proc/net/route", IdentifierGroup.NETWORK, file = "/proc/net/route", strace = listOf("/proc/net/route")),
        id("net.quic", "QUIC / HTTP3", IdentifierGroup.NETWORK, "Cronet / QUIC / Http3", logcat = listOf("QUIC", "HTTP/3", "Http3")),
        id("net.websocket", "WebSocket", IdentifierGroup.NETWORK, "WebSocket / OkHttp WebSocket", logcat = listOf("WebSocket", "newWebSocket")),
        id("hw.cutout", "DisplayCutout", IdentifierGroup.HARDWARE, "Display.getCutout / WindowInsets.getDisplayCutout", logcat = listOf("DisplayCutout", "getCutout")),
        id("hw.refresh", "Refresh rate / display mode", IdentifierGroup.HARDWARE, "Display.getRefreshRate / getMode", logcat = listOf("getRefreshRate", "Display.Mode")),
        id("hw.hdr", "HDR capabilities", IdentifierGroup.HARDWARE, "Display.getHdrCapabilities / isHdr", logcat = listOf("getHdrCapabilities", "isHdr")),
        id("hw.thermal", "Thermal status", IdentifierGroup.HARDWARE, "PowerManager.getCurrentThermalStatus", logcat = listOf("getCurrentThermalStatus", "THERMAL_STATUS")),
        id("hw.fold", "Fold / device state", IdentifierGroup.HARDWARE, "DeviceStateManager / FoldState", logcat = listOf("DeviceStateManager", "FoldStateListener")),
        id("hw.wallpaper", "WallpaperColors", IdentifierGroup.HARDWARE, "WallpaperManager.getWallpaperColors", logcat = listOf("WallpaperColors", "getWallpaperColors")),
        id("hw.camera_chars", "CameraCharacteristics", IdentifierGroup.HARDWARE, "CameraManager.getCameraCharacteristics", logcat = listOf("getCameraCharacteristics", "CameraCharacteristics")),
        id("hw.midi", "MIDI devices", IdentifierGroup.HARDWARE, "MidiManager.getDevices", logcat = listOf("MidiManager")),
        id("hw.ir", "IR blaster", IdentifierGroup.HARDWARE, "ConsumerIrManager", logcat = listOf("ConsumerIrManager", "transmit")),
        id("hw.vibrator", "Vibrator id / Q-factor", IdentifierGroup.HARDWARE, "Vibrator.getId / getQFactor / getResonantFrequency", logcat = listOf("getQFactor", "getResonantFrequency", "VibratorManager")),
        id("hw.spatializer", "Spatializer", IdentifierGroup.HARDWARE, "AudioManager.getSpatializer", logcat = listOf("Spatializer")),
        id("hw.tts", "TTS engines / voices", IdentifierGroup.HARDWARE, "TextToSpeech.getEngines / getVoices", logcat = listOf("TextToSpeech", "getVoices", "TtsEngines")),
        id("hw.speech_rec", "SpeechRecognizer", IdentifierGroup.HARDWARE, "SpeechRecognizer.createSpeechRecognizer", logcat = listOf("SpeechRecognizer", "startListening")),
        id("hw.translation", "TranslationManager", IdentifierGroup.HARDWARE, "TranslationManager.createOnDeviceTranslator", logcat = listOf("TranslationManager", "OnDeviceTranslator")),
        id("hw.textclass", "TextClassifier", IdentifierGroup.HARDWARE, "TextClassificationManager.getTextClassifier", logcat = listOf("TextClassificationManager", "TextClassifier")),
        id("hw.exif", "EXIF GPS in photos", IdentifierGroup.HARDWARE, "ExifInterface.getLatLong / GPSLatitude", logcat = listOf("ExifInterface", "GPSLatitude", "getLatLong")),
        id("hw.saf", "SAF / DocumentsContract", IdentifierGroup.CONTENT_PROVIDER, "ACTION_OPEN_DOCUMENT / DocumentsContract", logcat = listOf("ACTION_OPEN_DOCUMENT", "DocumentsContract", "OPEN_DOCUMENT_TREE")),
        id("hw.partial_media", "Selected photos access", IdentifierGroup.CONTENT_PROVIDER, "READ_MEDIA_VISUAL_USER_SELECTED", logcat = listOf("READ_MEDIA_VISUAL_USER_SELECTED", "PickVisualMediaRequest")),
        id("hw.private_space", "Private Space (Android 15)", IdentifierGroup.SETTINGS, "UserManager / Private Space", logcat = listOf("PrivateSpace", "isPrivateProfile")),
        id("hw.start_info", "ApplicationStartInfo", IdentifierGroup.HARDWARE, "ActivityManager.getHistoricalProcessStartReasons", logcat = listOf("ApplicationStartInfo", "getHistoricalProcessStartReasons")),
        id("hw.game_mode", "GameManager", IdentifierGroup.HARDWARE, "GameManager.getGameMode", logcat = listOf("GameManager", "getGameMode")),
        id("hw.adpf", "PerformanceHintManager", IdentifierGroup.HARDWARE, "PerformanceHintManager.createHintSession", logcat = listOf("PerformanceHintManager", "HintSession")),
        id("hw.captioning", "CaptioningManager", IdentifierGroup.HARDWARE, "CaptioningManager.getLocale / getFontScale", logcat = listOf("CaptioningManager")),
        id("identity.mdoc", "mDoc / Identity Credential", IdentifierGroup.IDENTITY, "IdentityCredentialStore / PresentationSession", logcat = listOf("IdentityCredential", "PresentationSession", "mdoc")),
        id("identity.wallet", "Google Wallet / passes", IdentifierGroup.IDENTITY, "PayClient / WalletObjects", logcat = listOf("PayClient", "WalletObjects", "com.google.android.gms.wallet")),
        id("play.app_check", "Firebase App Check", IdentifierGroup.ATTESTATION, "FirebaseAppCheck.getToken", logcat = listOf("FirebaseAppCheck", "AppCheckToken", "PlayIntegrityAppCheck")),
        id("play.protect", "Play Protect / Verify apps", IdentifierGroup.ATTESTATION, "PackageManager / SafetyNet verify apps", logcat = listOf("PackageVerification", "PlayProtect", "verify.?apps")),
        id("attest.device_id", "Device ID attestation", IdentifierGroup.ATTESTATION, "setDevicePropertiesAttestationIncluded / ID attestation", logcat = listOf("DevicePropertiesAttestation", "attestationChallenge", "ATTESTATION_ID")),
        id("role.browser", "Default browser role", IdentifierGroup.IDENTITY, "RoleManager.ROLE_BROWSER", logcat = listOf("ROLE_BROWSER")),
        id("role.dialer", "Default dialer role", IdentifierGroup.IDENTITY, "RoleManager.ROLE_DIALER", logcat = listOf("ROLE_DIALER", "getDefaultDialerPackage")),
        id("role.home", "Default home / launcher", IdentifierGroup.IDENTITY, "RoleManager.ROLE_HOME", logcat = listOf("ROLE_HOME", "getHomeActivities")),
        id("call.screening", "CallScreeningService", IdentifierGroup.PERSONAL, "CallScreeningService.onScreenCall", logcat = listOf("CallScreeningService", "onScreenCall")),
        id("contacts.sim", "SIM phonebook", IdentifierGroup.PERSONAL, "content://icc/adn", logcat = listOf("content://icc", "SimContacts"), strace = listOf("content://icc")),
        id("version.mpc", "Media performance class", IdentifierGroup.OS_VERSION, "Build.VERSION.MEDIA_PERFORMANCE_CLASS", "ro.odm.build.media_performance_class"),
        id("prop.ril.serial", "Samsung ril.serialnumber", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ril.serialnumber", logcat = listOf("ril.serialnumber")),
        id("prop.timezone", "persist.sys.timezone", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "persist.sys.timezone"),
        id("prop.locale", "persist.sys.locale", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "persist.sys.locale"),
        id("prop.density", "LCD density", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.sf.lcd_density"),
        id("prop.opengles", "ro.opengles.version", IdentifierGroup.SYSTEM_PROPERTY, systemProp = "ro.opengles.version"),
        id("proc.net_arp", "/proc/net/arp", IdentifierGroup.PROC_SYS, file = "/proc/net/arp", strace = listOf("/proc/net/arp")),
        id("proc.mountinfo", "/proc/self/mountinfo", IdentifierGroup.PROC_SYS, file = "/proc/self/mountinfo", strace = listOf("/proc/self/mountinfo")),
        id("sys.thermal", "thermal zones", IdentifierGroup.PROC_SYS, file = "/sys/class/thermal", strace = listOf("/sys/class/thermal")),
        id("sys.usb_serial", "USB serial sysfs", IdentifierGroup.PROC_SYS, file = "/sys/class/android_usb/android0/iSerial", strace = listOf("android_usb"))
    )

    // --- helpers ---

    private fun id(
        id: String,
        displayName: String,
        group: IdentifierGroup,
        api: String? = null,
        systemProp: String? = null,
        file: String? = null,
        logcat: List<String> = emptyList(),
        strace: List<String> = emptyList(),
        perm: String? = null,
        description: String? = null
    ) = IdentifierDefinition(
        id = id,
        displayName = displayName,
        group = group,
        api = api,
        systemProperty = systemProp,
        filePath = file,
        logcatPatterns = logcat.map { Regex(it, RegexOption.IGNORE_CASE) },
        stracePathPatterns = strace.map { Regex(it, RegexOption.IGNORE_CASE) },
        permission = perm,
        description = description
    )
}

fun IdentifierDefinition.toAccessCategory(): AccessCategory = when (group) {
    IdentifierGroup.LOCATION -> AccessCategory.LOCATION
    IdentifierGroup.TELEPHONY, IdentifierGroup.SUBSCRIPTION -> AccessCategory.TELEPHONY
    IdentifierGroup.WIFI, IdentifierGroup.NETWORK -> AccessCategory.NETWORK
    IdentifierGroup.BLUETOOTH -> AccessCategory.BLUETOOTH
    IdentifierGroup.ROOT, IdentifierGroup.ATTESTATION -> AccessCategory.SECURITY
    IdentifierGroup.FRAUD -> when {
        id.contains("clone") || id.contains("dual") || id.contains("mock") ||
            id.contains("vpn_apps") || id.contains("auto_click") || id.contains("work_profile") ->
            AccessCategory.SECURITY
        else -> AccessCategory.IDENTIFIER
    }
    IdentifierGroup.CONTENT_PROVIDER -> when {
        id.contains("telephony") || id.contains("icc") -> AccessCategory.TELEPHONY
        id.startsWith("storage.") -> AccessCategory.STORAGE
        else -> AccessCategory.IDENTIFIER
    }
    IdentifierGroup.ACCOUNT, IdentifierGroup.IDENTITY, IdentifierGroup.BROWSER -> AccessCategory.IDENTIFIER
    IdentifierGroup.PERSONAL -> when {
        id.startsWith("sms.") || id.startsWith("mms.") -> AccessCategory.SMS
        id.startsWith("calendar.") -> AccessCategory.CALENDAR
        else -> AccessCategory.CONTACTS
    }
    IdentifierGroup.HARDWARE -> when {
        id.startsWith("camera.") -> AccessCategory.CAMERA
        id.startsWith("mic.") -> AccessCategory.MICROPHONE
        id.startsWith("sensor.") -> AccessCategory.SENSOR
        id.startsWith("clipboard.") -> AccessCategory.CLIPBOARD
        else -> AccessCategory.SYSTEM_API
    }
    else -> AccessCategory.IDENTIFIER
}

fun categoryForIdentifierId(id: String?): AccessCategory? {
    if (id.isNullOrBlank()) return null
    return IdentifierCatalog.findById(id)?.toAccessCategory()
        ?: when {
            id.startsWith("tel.") || id.startsWith("sub.") -> AccessCategory.TELEPHONY
            id == "net.pin_fail" -> AccessCategory.SECURITY
            id.startsWith("net.") || id.startsWith("wifi.") -> AccessCategory.NETWORK
            id.startsWith("location.") -> AccessCategory.LOCATION
            id.startsWith("bt.") || id.startsWith("nearby.") -> AccessCategory.BLUETOOTH
            id.startsWith("root.") || id.startsWith("attest.") ||
                id == "ent.integrity" || id == "ent.safetynet" || id == "ent.verdict" -> AccessCategory.SECURITY
            id.startsWith("contacts.") || id.startsWith("call_log.") || id == "cp.contacts" -> AccessCategory.CONTACTS
            id.startsWith("sms.") || id.startsWith("mms.") || id == "cp.sms" -> AccessCategory.SMS
            id.startsWith("calendar.") || id == "cp.calendar" -> AccessCategory.CALENDAR
            id.startsWith("camera.") -> AccessCategory.CAMERA
            id.startsWith("mic.") -> AccessCategory.MICROPHONE
            id.startsWith("sensor.") -> AccessCategory.SENSOR
            id.startsWith("clipboard.") -> AccessCategory.CLIPBOARD
            id.startsWith("perm.") || id.startsWith("pkg.") -> AccessCategory.SYSTEM_API
            id.startsWith("fcm.") || id.startsWith("cred.") || id.startsWith("play.") ||
                id.startsWith("ad.") || id.startsWith("fido.") || id.startsWith("games.") ||
                id.startsWith("identity.") -> AccessCategory.IDENTIFIER
            id.startsWith("call.") -> AccessCategory.TELEPHONY
            id.startsWith("health.") -> AccessCategory.SENSOR
            id.startsWith("cell.") -> AccessCategory.LOCATION
            id.startsWith("hw.") || id.startsWith("oem.") || id.startsWith("dpm.") ||
                id.startsWith("user.") || id.startsWith("role.") || id.startsWith("notify.") ->
                AccessCategory.SYSTEM_API
            id.startsWith("browser.") -> AccessCategory.IDENTIFIER
            id.startsWith("fraud.") -> when {
                id.contains("clone") || id.contains("dual") || id.contains("mock") ||
                    id.contains("vpn_apps") || id.contains("auto_click") || id.contains("work_profile") ->
                    AccessCategory.SECURITY
                else -> AccessCategory.IDENTIFIER
            }
            else -> null
        }
}
