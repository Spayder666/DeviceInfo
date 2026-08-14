package com.deviceinfo.trafficmonitor.ui

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.EventSource

data class DisplayEvent(
    val event: CaptureEvent,
    val repeats: Int = 1
)

data class SessionStats(
    val total: Int = 0,
    val uniqueIdentifiers: List<String> = emptyList(),
    val categoryCounts: Map<AccessCategory, Int> = emptyMap(),
    val sourceCounts: Map<EventSource, Int> = emptyMap(),
    val riskTotal: Int = 0,
    val topHosts: List<String> = emptyList(),
    val topActions: List<Pair<String, Int>> = emptyList()
)

fun isHighRisk(category: AccessCategory): Boolean = when (category) {
    AccessCategory.LOCATION,
    AccessCategory.CAMERA,
    AccessCategory.MICROPHONE,
    AccessCategory.TELEPHONY,
    AccessCategory.IDENTIFIER,
    AccessCategory.CONTACTS,
    AccessCategory.SMS,
    AccessCategory.CLIPBOARD -> true
    else -> false
}

fun eventMatchesQuery(event: CaptureEvent, query: String): Boolean {
    if (query.isBlank()) return true
    val q = query.trim()
    return event.action.contains(q, ignoreCase = true) ||
        event.requestDetails?.contains(q, ignoreCase = true) == true ||
        event.responseDetails?.contains(q, ignoreCase = true) == true ||
        event.identifierName?.contains(q, ignoreCase = true) == true ||
        event.identifierGroup?.contains(q, ignoreCase = true) == true ||
        event.permission?.contains(q, ignoreCase = true) == true ||
        event.rawData?.contains(q, ignoreCase = true) == true ||
        event.category.name.contains(q, ignoreCase = true) ||
        event.source.name.contains(q, ignoreCase = true)
}

fun collapseRepeats(events: List<CaptureEvent>): List<DisplayEvent> {
    if (events.isEmpty()) return emptyList()
    val out = ArrayList<DisplayEvent>(events.size)
    for (event in events) {
        val last = out.lastOrNull()
        if (last != null &&
            last.event.action == event.action &&
            last.event.category == event.category &&
            last.event.source == event.source &&
            last.event.identifierName == event.identifierName
        ) {
            out[out.lastIndex] = last.copy(repeats = last.repeats + 1)
        } else {
            out.add(DisplayEvent(event))
        }
    }
    return out
}

fun buildSessionStats(events: List<CaptureEvent>): SessionStats {
    val hostRegex = Regex("""(?i)(?:https?://|sni[=: ]+|host[=: ]+)([a-z0-9.-]+\.[a-z]{2,})""")
    val hosts = linkedMapOf<String, Int>()
    val actions = linkedMapOf<String, Int>()
    val ids = linkedSetOf<String>()
    var risk = 0
    for (event in events) {
        event.identifierName?.let { ids.add(it) }
        if (isHighRisk(event.category)) risk++
        actions[event.action] = (actions[event.action] ?: 0) + 1
        val blob = listOfNotNull(event.requestDetails, event.responseDetails, event.rawData, event.action)
            .joinToString("\n")
        hostRegex.findAll(blob).forEach { match ->
            val host = match.groupValues[1].lowercase()
            hosts[host] = (hosts[host] ?: 0) + 1
        }
    }
    return SessionStats(
        total = events.size,
        uniqueIdentifiers = ids.toList(),
        categoryCounts = events.groupingBy { it.category }.eachCount(),
        sourceCounts = events.groupingBy { it.source }.eachCount(),
        riskTotal = risk,
        topHosts = hosts.entries.sortedByDescending { it.value }.take(8).map { "${it.key} · ${it.value}" },
        topActions = actions.entries.sortedByDescending { it.value }.take(6).map { it.key to it.value }
    )
}

fun eventAsText(event: CaptureEvent): String = buildString {
    appendLine(event.action)
    appendLine("${event.category} · ${event.source}")
    event.identifierName?.let { appendLine("ID: $it") }
    event.permission?.let { appendLine("Право: $it") }
    event.requestDetails?.let { appendLine("Запрос:\n$it") }
    event.responseDetails?.let { appendLine("Ответ:\n$it") }
    event.rawData?.let { appendLine("Raw:\n$it") }
}
