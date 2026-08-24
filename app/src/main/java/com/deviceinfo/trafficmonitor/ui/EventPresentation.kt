package com.deviceinfo.trafficmonitor.ui

import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.IdentifierGroup

data class AskedGot(
    val asked: String,
    val api: String?,
    val got: String
)

private val INTERNAL_IDS = setOf(
    "root.inject", "root.decision", "root.ports", "frida.init", "frida.boot"
)

fun isInternalNoise(event: CaptureEvent): Boolean =
    event.identifierName in INTERNAL_IDS ||
        event.action.startsWith("Frida: хуки")

/**
 * Как в v19: заголовок = action, превью = сохранённый ответ (или запрос).
 * Никакой подмены живого значения на «нет значения».
 */
fun describeAskedGot(event: CaptureEvent): AskedGot {
    val def = event.identifierName?.let { IdentifierCatalog.findById(it) }
    val asked = event.action.ifBlank { def?.displayName ?: "Запрос" }
    val api = firstLine(event.requestDetails)
        ?: def?.api
        ?: event.action.takeIf { it.contains('.') || '(' in it }
    val got = firstLine(event.responseDetails).orEmpty()
    return AskedGot(asked = asked, api = api, got = got)
}

fun eventTitle(event: CaptureEvent): String = event.action

fun eventPreviewLine(event: CaptureEvent): String =
    firstLine(event.responseDetails)
        ?: firstLine(event.requestDetails)
        ?: event.action

fun eventAsText(event: CaptureEvent): String = buildString {
    appendLine(event.action)
    appendLine("${event.category} · ${event.source}")
    event.identifierName?.let { appendLine("ID: $it") }
    event.permission?.let { appendLine("Право: $it") }
    event.requestDetails?.takeIf { it.isNotBlank() }?.let {
        appendLine("Запрос:")
        appendLine(it)
    }
    event.responseDetails?.takeIf { it.isNotBlank() }?.let {
        appendLine("Ответ:")
        appendLine(it)
    }
    event.rawData?.let { appendLine("Raw:\n$it") }
}

fun buildAskedDigest(events: List<CaptureEvent>): List<AskedItem> =
    buildAskedSections(events).flatMap { it.items }

fun buildAskedSections(events: List<CaptureEvent>): List<DigestSection> {
    val byKey = linkedMapOf<String, AskedItem>()
    for (event in events) {
        if (isInternalNoise(event)) continue
        if (event.identifierName == "frida.boot" || event.identifierName == "frida.init") continue
        if (event.action.startsWith("Frida:")) continue
        val io = describeAskedGot(event)
        if (io.asked.isBlank()) continue
        val group = resolveEventGroup(event)
        val key = event.identifierName?.takeIf { it.isNotBlank() } ?: "${group?.name}|${io.asked}"
        val existing = byKey[key]
        val value = io.got.ifBlank { io.api.orEmpty() }
        if (existing == null) {
            byKey[key] = AskedItem(
                id = key,
                title = io.asked,
                value = value,
                api = io.api,
                group = group?.name,
                count = 1,
                eventId = event.id
            )
        } else {
            byKey[key] = existing.copy(
                count = existing.count + 1,
                value = if (io.got.isNotBlank()) io.got else existing.value,
                eventId = event.id
            )
        }
    }
    val buckets = linkedMapOf<IdentifierGroup?, MutableList<AskedItem>>()
    for (item in byKey.values) {
        val group = item.group?.let { runCatching { IdentifierGroup.valueOf(it) }.getOrNull() }
        buckets.getOrPut(group) { mutableListOf() }.add(item)
    }
    return FINGERPRINT_GROUP_ORDER.mapNotNull { group ->
        buckets.remove(group)?.let { DigestSection(group, it.sortedBy { item -> item.title }) }
    } + buckets.map { (group, items) -> DigestSection(group, items.sortedBy { it.title }) }
}

private fun firstLine(text: String?): String? {
    if (text.isNullOrBlank()) return null
    return text.lineSequence().firstOrNull { it.isNotBlank() }?.trim()?.take(200)
}
