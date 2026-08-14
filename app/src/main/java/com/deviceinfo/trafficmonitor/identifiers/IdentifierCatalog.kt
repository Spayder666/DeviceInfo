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
    IDENTITY("Токены / credentials / FCM")
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
        id("settings.overlay", "SYSTEM_ALERT_WINDOW", IdentifierGroup.SETTINGS, "Settings.canDrawOverlays", logcat = listOf("canDrawOverlays", "SYSTEM_ALERT_WINDOW"))
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
        id("tel.phone_interface", "PhoneInterfaceManager", IdentifierGroup.TELEPHONY, logcat = listOf("PhoneInterfaceManager", "ITelephony", "TelephonyPermissions"))
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
        id("sub.port_index", "eSIM port index", IdentifierGroup.SUBSCRIPTION, "SubscriptionInfo.getPortIndex()", logcat = listOf("getPortIndex"))
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
        id("ad.limit_tracking", "Limit ad tracking flag", IdentifierGroup.ADVERTISING, logcat = listOf("limit ad tracking", "isLimitAdTrackingEnabled"))
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
        id("install.application_info", "getApplicationInfo", IdentifierGroup.INSTALL, "PackageManager.getApplicationInfo", logcat = listOf("getApplicationInfo"))
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
        id("oem.huawei_oaid", "Huawei OAID", IdentifierGroup.OEM, logcat = listOf("HmsAdsIdentifier"))
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
    IdentifierGroup.CONTENT_PROVIDER -> when {
        id.contains("telephony") || id.contains("icc") -> AccessCategory.TELEPHONY
        id.startsWith("storage.") -> AccessCategory.STORAGE
        else -> AccessCategory.IDENTIFIER
    }
    IdentifierGroup.ACCOUNT, IdentifierGroup.IDENTITY -> AccessCategory.IDENTIFIER
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
            id.startsWith("bt.") -> AccessCategory.BLUETOOTH
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
            id.startsWith("fcm.") || id.startsWith("cred.") || id.startsWith("play.") -> AccessCategory.IDENTIFIER
            else -> null
        }
}
