package com.deviceinfo.trafficmonitor.identifiers

object IdentifierMatcher {

    private val logcatRules: List<Pair<IdentifierDefinition, Regex>> =
        IdentifierCatalog.all.flatMap { def ->
            def.logcatPatterns.map { pattern -> def to pattern }
        }

    private val straceRules: List<Pair<IdentifierDefinition, Regex>> =
        IdentifierCatalog.all.flatMap { def ->
            def.stracePathPatterns.map { pattern -> def to pattern }
        }

    private val propertyRules: List<Pair<IdentifierDefinition, Regex>> =
        IdentifierCatalog.all
            .filter { it.systemProperty != null }
            .map { def ->
                def to Regex(Regex.escape(def.systemProperty!!), RegexOption.IGNORE_CASE)
            }

    fun matchLogcat(line: String): IdentifierDefinition? {
        for ((def, pattern) in logcatRules) {
            if (pattern.containsMatchIn(line)) return def
        }
        return matchBuildReflection(line) ?: matchGenericIdentifier(line)
    }

    fun matchStrace(line: String): IdentifierDefinition? {
        for ((def, pattern) in straceRules) {
            if (pattern.containsMatchIn(line)) return def
        }
        if (line.contains("getprop", ignoreCase = true) || line.contains("__system_property_get")) {
            return IdentifierCatalog.findById("getprop.shell")
        }
        for ((def, pattern) in propertyRules) {
            if (pattern.containsMatchIn(line)) return def
        }
        return null
    }

    fun matchPath(path: String): IdentifierDefinition? {
        for ((def, pattern) in straceRules) {
            if (pattern.containsMatchIn(path)) return def
        }
        return null
    }

    private fun matchBuildReflection(line: String): IdentifierDefinition? {
        val buildFields = mapOf(
            "MODEL" to "build.model",
            "MANUFACTURER" to "build.manufacturer",
            "DEVICE" to "build.device",
            "BRAND" to "build.brand",
            "PRODUCT" to "build.product",
            "HARDWARE" to "build.hardware",
            "BOARD" to "build.board",
            "FINGERPRINT" to "build.fingerprint",
            "SERIAL" to "build.serial",
            "ID" to "build.id",
            "DISPLAY" to "build.display",
            "HOST" to "build.host",
            "TAGS" to "build.tags",
            "TYPE" to "build.type",
            "USER" to "build.user",
            "RADIO" to "build.radio",
            "BOOTLOADER" to "build.bootloader",
            "SOC_MANUFACTURER" to "build.soc_manufacturer",
            "SOC_MODEL" to "build.soc_model",
            "SKU" to "build.sku",
            "ODM_SKU" to "build.odm_sku",
            "SUPPORTED_ABIS" to "build.supported_abis",
            "IS_EMULATOR" to "build.is_emulator"
        )
        for ((field, id) in buildFields) {
            if (Regex("Build\\.$field|Build\\.VERSION\\.", RegexOption.IGNORE_CASE).containsMatchIn(line)) {
                return IdentifierCatalog.findById(id)
            }
        }
        if (Regex("Build\\.VERSION\\.", RegexOption.IGNORE_CASE).containsMatchIn(line)) {
            return IdentifierCatalog.findById("version.sdk")
        }
        return null
    }

    private fun matchGenericIdentifier(line: String): IdentifierDefinition? {
        if (Regex("(?i)getSerial|IDeviceIdentifiersPolicy|READ_PRIVILEGED_PHONE_STATE").containsMatchIn(line)) {
            return IdentifierCatalog.findById("build.serial")
        }
        if (Regex("(?i)Settings\\.Secure|Settings\\.Global|Settings\\.System").containsMatchIn(line)) {
            return IdentifierCatalog.findById("settings.secure")
        }
        return null
    }
}
