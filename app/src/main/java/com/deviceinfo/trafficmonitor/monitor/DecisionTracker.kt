package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * После root/integrity-проверки смотрит, ушёл ли логин / 403 / finish.
 */
class DecisionTracker(
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null
    private var lastId = 0L
    private var lastProbe: CaptureEvent? = null
    private var primed = false

    fun start() {
        job = scope.launch {
            repository.observeEvents(packageName).collect { list ->
                if (!primed) {
                    lastId = list.maxOfOrNull { it.id } ?: 0L
                    primed = true
                    return@collect
                }
                val fresh = list.filter { it.id > lastId }.sortedBy { it.id }
                if (fresh.isNotEmpty()) lastId = fresh.maxOf { it.id }
                for (event in fresh) handle(event)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun handle(event: CaptureEvent) {
        if (event.identifierName == "root.decision") return
        if (isProbe(event)) {
            lastProbe = event
            return
        }
        val probe = lastProbe ?: return
        if (event.timestamp - probe.timestamp !in 0..25_000) return
        if (!isOutcome(event)) return
        val action = "После «${probe.action.take(40)}» → ${event.action.take(40)}"
        if (repository.isDuplicate(packageName, action, event.rawData, sinceMs = 8000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.SECURITY,
                source = EventSource.DUMPSYS,
                action = action,
                requestDetails = "${probe.identifierName ?: probe.action} @ ${probe.timestamp}",
                responseDetails = listOfNotNull(event.action, event.responseDetails).joinToString(" · ").take(400),
                rawData = "probe=${probe.id} outcome=${event.id} src=${event.source}",
                identifierName = "root.decision",
                identifierGroup = "ROOT"
            )
        )
        lastProbe = null
    }

    private fun isProbe(event: CaptureEvent): Boolean {
        val id = event.identifierName.orEmpty()
        if (id in SKIP_PROBE) return false
        if (event.category == AccessCategory.SECURITY) return true
        return id.startsWith("root.") || id.startsWith("attest.") ||
            id == "ent.integrity" || id == "ent.safetynet" || id == "ent.verdict"
    }

    private fun isOutcome(event: CaptureEvent): Boolean {
        val text = listOfNotNull(event.action, event.responseDetails, event.requestDetails, event.rawData)
            .joinToString(" ").lowercase()
        return listOf(
            "403", "401", "login", "signin", "auth", "denied", "blocked", "finish",
            "rooted", "jailbreak", "integrity", "unlicensed", "no_integrity",
            "meets_device", "ctsprofile", "pinning", "sslpeer"
        ).any { it in text } ||
            (event.source == EventSource.MITM && Regex("""HTTP [45]\d\d""").containsMatchIn(text))
    }

    companion object {
        private val SKIP_PROBE = setOf(
            "root.hide", "root.isolated", "root.text", "root.decision", "net.user_ca"
        )
    }
}
