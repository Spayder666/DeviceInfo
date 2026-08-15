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
    "root.inject", "root.decision", "root.ports", "frida.init"
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

fun buildAskedDigest(events: List<CaptureEvent>): List<AskedItem> {
    val byKey = linkedMapOf<String, AskedItem>()
    for (event in events) {
        if (isInternalNoise(event)) continue
        val io = describeAskedGot(event)
        val key = event.identifierName ?: io.asked
        val existing = byKey[key]
        val hasValue = io.got.isNotBlank()
        if (existing == null) {
            byKey[key] = AskedItem(
                id = key,
                title = io.asked,
                value = io.got.ifBlank { io.api.orEmpty() },
                api = io.api,
                group = event.identifierGroup ?: IdentifierCatalog.findById(event.identifierName.orEmpty())?.group?.name,
                count = 1
            )
        } else {
            byKey[key] = existing.copy(
                count = existing.count + 1,
                value = if (hasValue) io.got else existing.value
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

private fun firstLine(text: String?): String? {
    if (text.isNullOrBlank()) return null
    return text.lineSequence().firstOrNull { it.isNotBlank() }?.trim()?.take(200)
}
