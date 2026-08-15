package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.toAccessCategory
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Чекеры железа читают Settings / getprop / libc без AppOps и без UID-logcat цели.
 * Слушаем SettingsProvider и libc отдельно и привязываем по uid/пакету.
 */
class IdentifierAccessMonitor(
    private val packageName: String,
    private val uid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private val jobs = mutableListOf<Job>()

    fun start() {
        val libcCmd = if (uid > 0) {
            "logcat -v threadtime --uid=$uid -T 1 libc:V SystemProperties:V *:S 2>&1"
        } else {
            "logcat -v threadtime -T 1 libc:V SystemProperties:V *:S 2>&1"
        }
        jobs += scope.launch(Dispatchers.IO) {
            try {
                RootShell.execStreaming(libcCmd) { line ->
                    if (isActive) scope.launch { parseLibc(line) }
                }
            } catch (_: Exception) {
            }
        }
        jobs += scope.launch(Dispatchers.IO) {
            try {
                RootShell.execStreaming(
                    "logcat -v threadtime -T 1 SettingsProvider:V Settings:V *:S 2>&1"
                ) { line ->
                    if (isActive) scope.launch { parseSettings(line) }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun stop() {
        jobs.forEach { it.cancel() }
        jobs.clear()
    }

    private suspend fun parseLibc(line: String) {
        if (line.isBlank()) return
        val denied = PROPERTY_DENIED.find(line)
        if (denied != null) {
            emitProperty(denied.groupValues[1], "ОТКЛОНЕНО (Access denied)", line)
            return
        }
        val found = PROPERTY_FOUND.find(line) ?: return
        val value = found.groupValues.getOrNull(2)?.trim().orEmpty()
        emitProperty(
            found.groupValues[1],
            value.ifBlank { "(значение не показано в logcat)" },
            line
        )
    }

    private suspend fun parseSettings(line: String) {
        if (line.isBlank()) return
        val mentionsPkg = line.contains(packageName)
        val mentionsUid = uid > 0 && (
            line.contains("uid=$uid") ||
                line.contains("callingUid=$uid") ||
                line.contains("callingUid: $uid")
            )
        if (!mentionsPkg && !mentionsUid) return

        val name = SETTING_NAME.find(line)?.groupValues?.get(1)
            ?: return
        val def = IdentifierCatalog.all.firstOrNull { catalog ->
            catalog.id.endsWith(".$name") ||
                catalog.systemProperty == name ||
                catalog.api?.contains(name, ignoreCase = true) == true ||
                catalog.logcatPatterns.any { it.containsMatchIn(name) }
        } ?: IdentifierCatalog.findById("settings.secure")
        val value = SETTING_VALUE.find(line)?.groupValues?.get(1)
        emit(
            action = def?.displayName ?: "Settings.$name",
            request = "Settings: $name",
            response = value ?: line.substringAfter(": ").take(240),
            raw = line,
            identifierId = def?.id ?: "settings.secure",
            group = def?.group?.name ?: "SETTINGS",
            category = def?.toAccessCategory() ?: AccessCategory.IDENTIFIER
        )
    }

    private suspend fun emitProperty(property: String, response: String, line: String) {
        val def = IdentifierCatalog.all.firstOrNull { it.systemProperty == property }
        emit(
            action = def?.displayName ?: "getprop $property",
            request = "Property: $property",
            response = response,
            raw = line,
            identifierId = def?.id ?: "getprop.shell",
            group = def?.group?.name ?: "SYSTEM_PROPERTY",
            category = def?.toAccessCategory() ?: AccessCategory.IDENTIFIER
        )
    }

    private suspend fun emit(
        action: String,
        request: String,
        response: String,
        raw: String,
        identifierId: String,
        group: String,
        category: AccessCategory
    ) {
        if (repository.isDuplicate(packageName, action, raw, sinceMs = 800)) return
        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = category,
                source = EventSource.LOGCAT,
                action = action,
                requestDetails = request,
                responseDetails = response.take(400),
                rawData = raw.trim(),
                identifierName = identifierId,
                identifierGroup = group
            )
        )
    }

    companion object {
        private val PROPERTY_DENIED = Regex("""Access denied finding property "([^"]+)"""")
        private val PROPERTY_FOUND = Regex(
            """(?:read|access|found) property "([^"]+)"(?:[=:]\s*"?([^"\n]+)"?)?""",
            RegexOption.IGNORE_CASE
        )
        private val SETTING_NAME = Regex("""(?i)(?:name|key)[=:]\s*([A-Za-z0-9._]+)""")
        private val SETTING_VALUE = Regex("""(?i)(?:value|val)[=:]\s*"?([^"\s,;]+)""")
    }
}
