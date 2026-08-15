package com.deviceinfo.trafficmonitor.ui

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.EventSource

data class DisplayEvent(
    val event: CaptureEvent,
    val repeats: Int = 1,
    val pinned: Boolean = false
)

data class AskedItem(
    val id: String,
    val title: String,
    val value: String,
    val api: String?,
    val group: String?,
    val count: Int
)

data class SessionStats(
    val total: Int = 0,
    val uniqueIdentifiers: List<String> = emptyList(),
    val categoryCounts: Map<AccessCategory, Int> = emptyMap(),
    val sourceCounts: Map<EventSource, Int> = emptyMap(),
    val riskTotal: Int = 0,
    val topHosts: List<String> = emptyList(),
    val topActions: List<Pair<String, Int>> = emptyList(),
    val startedAt: Long = 0L,
    val durationMs: Long = 0L,
    val eventsPerMin: Double = 0.0
)

fun pinKey(event: CaptureEvent): String =
    "${event.source}|${event.action}|${event.identifierName.orEmpty()}"

fun formatDuration(ms: Long): String {
    val totalSec = (ms / 1000).coerceAtLeast(0)
    val h = totalSec / 3600
    val m = (totalSec % 3600) / 60
    val s = totalSec % 60
    return if (h > 0) "%d:%02d:%02d".format(h, m, s) else "%d:%02d".format(m, s)
}

fun isHighRisk(category: AccessCategory): Boolean = when (category) {
    AccessCategory.LOCATION,
    AccessCategory.CAMERA,
    AccessCategory.MICROPHONE,
    AccessCategory.TELEPHONY,
    AccessCategory.IDENTIFIER,
    AccessCategory.CONTACTS,
    AccessCategory.SMS,
    AccessCategory.CLIPBOARD,
    AccessCategory.SECURITY -> true
    else -> false
}

fun isIdentifierEvent(event: CaptureEvent): Boolean =
    event.category == AccessCategory.IDENTIFIER ||
        !event.identifierName.isNullOrBlank() ||
        !event.identifierGroup.isNullOrBlank()

fun eventMatchesCategory(event: CaptureEvent, category: AccessCategory?): Boolean {
    if (category == null) return true
    if (category == AccessCategory.IDENTIFIER) return isIdentifierEvent(event)
    return event.category == category
}

fun eventMatchesQuery(event: CaptureEvent, query: String): Boolean {
    if (query.isBlank()) return true
    val q = query.trim()
    if (event.action.contains(q, ignoreCase = true) ||
        event.identifierName?.contains(q, ignoreCase = true) == true ||
        event.requestDetails?.contains(q, ignoreCase = true) == true ||
        event.responseDetails?.contains(q, ignoreCase = true) == true
    ) return true
    val io = describeAskedGot(event)
    return event.action.contains(q, ignoreCase = true) ||
        io.asked.contains(q, ignoreCase = true) ||
        io.got.contains(q, ignoreCase = true) ||
        io.api?.contains(q, ignoreCase = true) == true ||
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
    val startedAt = events.minOfOrNull { it.timestamp } ?: System.currentTimeMillis()
    val duration = (System.currentTimeMillis() - startedAt).coerceAtLeast(1)
    return SessionStats(
        total = events.size,
        uniqueIdentifiers = ids.toList(),
        categoryCounts = events.groupingBy { it.category }.eachCount(),
        sourceCounts = events.groupingBy { it.source }.eachCount(),
        riskTotal = risk,
        topHosts = hosts.entries.sortedByDescending { it.value }.take(8).map { "${it.key} · ${it.value}" },
        topActions = actions.entries.sortedByDescending { it.value }.take(6).map { it.key to it.value },
        startedAt = startedAt,
        durationMs = duration,
        eventsPerMin = events.size * 60_000.0 / duration
    )
}

