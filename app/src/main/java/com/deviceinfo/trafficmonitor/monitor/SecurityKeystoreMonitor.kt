package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/** logcat -b security, Android Keystore / Credential Manager, ANR и tombstones пакета. */
class SecurityKeystoreMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var streamJob: Job? = null
    private var pollJob: Job? = null
    private val seen = ConcurrentHashMap<String, String>()

    fun start() {
        streamJob = scope.launch(Dispatchers.IO) {
            try {
                RootShell.execStreaming("logcat -v threadtime -b security -T 1 2>&1") { line ->
                    if (isActive) scope.launch { parseSecurity(line) }
                }
            } catch (_: Exception) {
            }
        }
        pollJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                pollKeystore()
                pollAnr()
                delay(5000)
            }
        }
    }

    fun stop() {
        streamJob?.cancel()
        pollJob?.cancel()
        streamJob = null
        pollJob = null
    }

    private suspend fun parseSecurity(line: String) {
        if (line.isBlank()) return
        val mentions = line.contains(packageName) || (uid > 0 && line.contains("uid=$uid"))
        if (!mentions && !SENSITIVE.containsMatchIn(line)) return
        if (!mentions && !line.contains("keystore", ignoreCase = true) &&
            !line.contains("credential", ignoreCase = true)
        ) return
        emit(AccessCategory.IDENTIFIER, "security buffer", line, "attest.key", EventSource.LOGCAT)
    }

    private suspend fun pollKeystore() {
        val dump = RootShell.execAndRead(
            "dumpsys android.security.keystore 2>/dev/null | grep -A3 -E '$packageName|uid=$uid' | head -n 20; " +
                "dumpsys credstore 2>/dev/null | grep -A3 -F '$packageName' | head -n 16; " +
                "dumpsys credentials 2>/dev/null | grep -A3 -F '$packageName' | head -n 16",
            timeoutSec = 10
        )
        emit(AccessCategory.IDENTIFIER, "Keystore / credentials", dump, "attest.key", EventSource.DUMPSYS)
    }

    private suspend fun pollAnr() {
        val dump = RootShell.execAndRead(
            "ls -lt /data/anr /data/tombstones 2>/dev/null | head -n 12; " +
                "grep -l -F '$packageName' /data/anr/* /data/tombstones/tombstone_* 2>/dev/null | head -n 6",
            timeoutSec = 8
        )
        if (!dump.contains(packageName) && !dump.contains("tombstone")) return
        val hit = dump.lineSequence().filter { it.contains(packageName) || it.contains("tombstone") }
            .take(8).joinToString("\n")
        emit(AccessCategory.SYSTEM_API, "ANR / tombstone", hit, null, EventSource.PROC)
    }

    private suspend fun emit(
        category: AccessCategory,
        action: String,
        dump: String,
        id: String?,
        source: EventSource
    ) {
        if (dump.isBlank()) return
        val snippet = dump.trim().take(600)
        val key = "$action:${snippet.hashCode()}"
        if (seen.put(key, "1") != null) return
        if (repository.isDuplicate(packageName, action, snippet, sinceMs = 8000)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = source,
                action = action,
                requestDetails = action,
                responseDetails = snippet.take(400),
                rawData = snippet.take(1500),
                identifierName = id,
                identifierGroup = if (id?.startsWith("attest") == true) "ATTESTATION" else null
            )
        )
    }

    companion object {
        private val SENSITIVE = Regex("(?i)keystore|attestation|credential|passkey|identity")
    }
}
