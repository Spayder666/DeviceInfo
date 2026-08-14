package com.deviceinfo.trafficmonitor.identifiers

/**
 * Полный каталог идентификаторов Android (AOSP API 33–35).
 * Источники: Build.java, TelephonyManager, SettingsProvider, MediaDrm, AOSP docs.
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
    LOCATION("GPS / локация")
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
        id("settings.system", "Settings.System (bulk)", IdentifierGroup.SETTINGS, "content://settings/system", strace = listOf("content://settings/system"))
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
        id("tel.voicemail", "Голосовая почта", IdentifierGroup.TELEPHONY, "TelephonyManager.getVoiceMailNumber()", logcat = listOf("getVoiceMailNumber")),
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
        id("install.signing_cert", "Signing certificate hash", IdentifierGroup.INSTALL, "PackageManager GET_SIGNING_CERTIFICATES", logcat = listOf("GET_SIGNING_CERTIFICATES", "signatures"))
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
        id("cp.icc", "SIM ICC provider", IdentifierGroup.CONTENT_PROVIDER, "content://icc/adn", strace = listOf("content://icc"))
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
        id("storage.sqlite", "SQLite query", IdentifierGroup.CONTENT_PROVIDER, "SQLiteDatabase.rawQuery", logcat = listOf("SQLiteDatabase", "SQLiteLog")),
        id("storage.prefs", "SharedPreferences", IdentifierGroup.CONTENT_PROVIDER, "SharedPreferences.getString", logcat = listOf("SharedPreferences")),
        id("storage.file", "Файлы приложения", IdentifierGroup.PROC_SYS, "FileInputStream / FileOutputStream", strace = listOf("/data/data/"))
    )

    private fun enterpriseIdentifiers() = listOf(
        id("ent.esid", "Enrollment Specific ID", IdentifierGroup.ENTERPRISE, "DevicePolicyManager.getEnrollmentSpecificId()", logcat = listOf("getEnrollmentSpecificId", "enterpriseSpecificId")),
        id("ent.org_id", "Organization ID", IdentifierGroup.ENTERPRISE, "DevicePolicyManager.setOrganizationId()", logcat = listOf("setOrganizationId")),
        id("ent.integrity", "Play Integrity token", IdentifierGroup.ATTESTATION, "IntegrityManager.requestIntegrityToken()", logcat = listOf("IntegrityService", "PlayIntegrity")),
        id("ent.safetynet", "SafetyNet attestation", IdentifierGroup.ATTESTATION, "SafetyNetClient.attest()", logcat = listOf("SafetyNet"))
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
        id("attest.verified_boot", "Verified boot state", IdentifierGroup.ATTESTATION, logcat = listOf("verifiedbootstate", "vbmeta"))
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
