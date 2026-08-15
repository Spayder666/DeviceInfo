package com.deviceinfo.trafficmonitor.ui

import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.IdentifierGroup

data class AskedGot(
    val asked: String,
    val api: String?,
    val got: String
)

private val INTERNAL_IDS = setOf(
    "root.inject", "root.decision", "root.ports", "frida.init"
)

private val DUMP_NOISE = Regex(
    """(?i)m[A-Z]\w+:|dumpsys |Unknown command|IllegalArgument|VirtualDisplayAdapter|lshal |mRttRequesterInfo|mOverlays:"""
)

private val FRIDA_JSON = Regex("""^\s*\{"identifierId":""")

fun isInternalNoise(event: CaptureEvent): Boolean =
    event.identifierName in INTERNAL_IDS ||
        event.action.startsWith("Frida: хуки")

fun looksLikeDumpText(text: String): Boolean {
    if (FRIDA_JSON.containsMatchIn(text)) return true
    if (text.lines().count { it.isNotBlank() } > 3) return true
    return DUMP_NOISE.containsMatchIn(text)
}

fun describeAskedGot(event: CaptureEvent): AskedGot {
    val def = event.identifierName?.let { IdentifierCatalog.findById(it) }
    val asked = def?.displayName
        ?: humanizeAction(event.action)
    val api = def?.api
        ?: firstUsefulLine(event.requestDetails)
        ?: event.action.takeIf { it.contains('.') || '(' in it }
    val got = extractGot(event) ?: inferStatus(event) ?: "нет значения"
    return AskedGot(asked = asked, api = api, got = got)
}

fun eventTitle(event: CaptureEvent): String = describeAskedGot(event).asked

fun eventPreviewLine(event: CaptureEvent): String {
    val io = describeAskedGot(event)
    return "→ ${io.got}"
}

fun eventAsText(event: CaptureEvent): String {
    val io = describeAskedGot(event)
    return buildString {
        appendLine(io.asked)
        io.api?.let { appendLine("API: $it") }
        appendLine("${event.category} · ${event.source}")
        event.identifierName?.let { appendLine("ID: $it") }
        event.permission?.let { appendLine("Право: $it") }
        appendLine("Что спросили:")
        appendLine(event.requestDetails?.takeIf { it.isNotBlank() } ?: io.asked)
        appendLine("Что получили:")
        appendLine(io.got)
        event.rawData?.let { appendLine("Raw:\n$it") }
    }
}

fun buildAskedDigest(events: List<CaptureEvent>): List<AskedItem> {
    val byKey = linkedMapOf<String, AskedItem>()
    for (event in events) {
        if (isInternalNoise(event)) continue
        val io = describeAskedGot(event)
        val key = event.identifierName ?: io.asked
        val existing = byKey[key]
        val meaningful = io.got != "нет значения"
        if (existing == null) {
            byKey[key] = AskedItem(
                id = key,
                title = io.asked,
                value = io.got,
                api = io.api,
                group = event.identifierGroup ?: IdentifierCatalog.findById(event.identifierName.orEmpty())?.group?.name,
                count = 1
            )
        } else {
            byKey[key] = existing.copy(
                count = existing.count + 1,
                value = if (meaningful) io.got else existing.value
            )
        }
    }
    val order = listOf(
        IdentifierGroup.BUILD.name,
        IdentifierGroup.OS_VERSION.name,
        IdentifierGroup.SETTINGS.name,
        IdentifierGroup.TELEPHONY.name,
        IdentifierGroup.SUBSCRIPTION.name,
        IdentifierGroup.WIFI.name,
        IdentifierGroup.DRM.name,
        IdentifierGroup.ADVERTISING.name,
        IdentifierGroup.SYSTEM_PROPERTY.name
    )
    return byKey.values.sortedWith(
        compareBy<AskedItem> { item ->
            val i = order.indexOf(item.group)
            if (i < 0) 100 else i
        }.thenBy { it.title }
    )
}

private fun humanizeAction(action: String): String {
    val trimmed = action.trim()
    if (trimmed.isEmpty()) return "Запрос"
    IdentifierCatalog.findById(trimmed)?.displayName?.let { return it }
    return trimmed
        .removePrefix("fd:")
        .replace('_', ' ')
        .replace(Regex("""\s+"""), " ")
}

private fun firstUsefulLine(text: String?): String? {
    if (text.isNullOrBlank() || looksLikeDumpText(text)) return null
    return text.lineSequence().firstOrNull { it.isNotBlank() }?.trim()?.take(120)
}

private fun extractGot(event: CaptureEvent): String? {
    val chunks = listOfNotNull(event.responseDetails, event.requestDetails)
    for (raw in chunks) {
        cleanValue(raw)?.let { return it }
    }
    event.rawData?.let { raw ->
        if (!FRIDA_JSON.containsMatchIn(raw)) cleanValue(raw)?.let { return it }
        Regex(""""response"\s*:\s*"((?:\\.|[^"\\])*)"""").find(raw)
            ?.groupValues?.get(1)
            ?.replace("\\n", " ")
            ?.replace("\\\"", "\"")
            ?.trim()
            ?.takeIf { it.isNotEmpty() && it != "(пусто)" }
            ?.let { return it.take(120) }
    }
    return null
}

private fun cleanValue(raw: String): String? {
    val t = raw.trim()
    if (t.isEmpty() || FRIDA_JSON.containsMatchIn(t)) return null
    Regex("""(?i)Значение:\s*(.+)""").find(t)?.groupValues?.get(1)?.trim()?.let {
        if (it.isNotEmpty()) return it.take(120)
    }
    Regex("""lat=([-\d.]+)\s+lon=([-\d.]+)""").find(t)?.let {
        return "lat=${it.groupValues[1]} lon=${it.groupValues[2]}"
    }
    if (looksLikeDumpText(t)) {
        return t.lineSequence()
            .map { it.trim() }
            .firstOrNull { line ->
                line.length in 3..80 &&
                    '=' in line &&
                    !DUMP_NOISE.containsMatchIn(line)
            }
    }
    val first = t.lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: return null
    if (first.startsWith("API:") || first.startsWith("dumpsys") || first.startsWith("logcat")) {
        return null
    }
    return first.take(120)
}

private fun inferStatus(event: CaptureEvent): String? {
    val blob = listOfNotNull(event.action, event.responseDetails, event.requestDetails).joinToString(" ")
    return when {
        Regex("(?i)отклонен|denied|reject").containsMatchIn(blob) -> "отклонено"
        Regex("(?i)recording").containsMatchIn(blob) -> "идёт запись"
        Regex("(?i)opened|openCamera").containsMatchIn(blob) -> "открыто"
        event.source == EventSource.APPOPS -> "доступ зафиксирован"
        else -> null
    }
}
