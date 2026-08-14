package com.deviceinfo.trafficmonitor.analysis

import android.util.Base64
import org.json.JSONObject

/** Разбор Play Integrity / SafetyNet из plaintext MITM или Frida. Токен PI зашифрован — verdict только если сервер вернул JSON. */
object IntegrityVerdict {

    private val labels = listOf(
        "MEETS_STRONG_INTEGRITY",
        "MEETS_DEVICE_INTEGRITY",
        "MEETS_BASIC_INTEGRITY",
        "MEETS_VIRTUAL_INTEGRITY",
        "NO_INTEGRITY",
        "PLAY_RECOGNIZED",
        "UNRECOGNIZED_VERSION",
        "UNEVALUATED",
        "LICENSED",
        "UNLICENSED",
        "HARDWARE_BACKED",
        "PLAY_PROTECT",
        "NO_ISSUES",
        "POSSIBLE_RISK",
        "MEDIUM_RISK",
        "HIGH_RISK"
    )

    fun summarize(text: String): String? {
        if (text.isBlank()) return null
        val found = labels.filter { text.contains(it) }
        val jws = decodeSafetyNetJws(text)
        val json = extractPlainFields(text)
        val bits = buildList {
            addAll(found)
            addAll(json)
            if (jws != null) add(jws)
        }
        if (bits.isEmpty()) return null
        return bits.distinct().joinToString(" · ")
    }

    private fun extractPlainFields(text: String): List<String> {
        return listOf(
            "ctsProfileMatch",
            "basicIntegrity",
            "evaluationType",
            "appRecognitionVerdict",
            "appLicensingVerdict",
            "deviceRecognitionVerdict",
            "playProtectVerdict"
        ).mapNotNull { key ->
            Regex("""$key"\s*:\s*(true|false|"[^"]+"|\[[^\]]*\])""")
                .find(text)
                ?.groupValues
                ?.getOrNull(1)
                ?.let { "$key=$it".take(80) }
        }
    }

    fun decodeSafetyNetJws(blob: String): String? {
        val token = Regex("""eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+""").find(blob)?.value ?: return null
        val parts = token.split('.')
        if (parts.size < 2) return null
        return runCatching {
            val json = String(Base64.decode(pad(parts[1]), Base64.URL_SAFE or Base64.NO_WRAP))
            val o = JSONObject(json)
            buildList {
                if (o.has("ctsProfileMatch")) add("ctsProfileMatch=${o.optBoolean("ctsProfileMatch")}")
                if (o.has("basicIntegrity")) add("basicIntegrity=${o.optBoolean("basicIntegrity")}")
                o.optJSONObject("deviceIntegrity")?.optJSONArray("deviceRecognitionVerdict")?.let { arr ->
                    add((0 until arr.length()).joinToString(",") { arr.optString(it) })
                }
                o.optString("apkPackageName").takeIf { it.isNotBlank() }?.let { add("apk=$it") }
            }.joinToString(" · ").ifBlank { null }
        }.getOrNull()
    }

    private fun pad(s: String): String {
        val n = (4 - s.length % 4) % 4
        return s + "=".repeat(n)
    }
}
