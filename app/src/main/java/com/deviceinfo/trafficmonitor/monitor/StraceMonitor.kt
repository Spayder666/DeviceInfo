package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierDefinition
import com.deviceinfo.trafficmonitor.identifiers.IdentifierMatcher
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class StraceMonitor(
    private val packageName: String,
    private val pid: Int,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var job: Job? = null

    fun start() {
        val stracePath = RootShell.resolveStracePath() ?: return

        job = scope.launch(Dispatchers.IO) {
            val cmd = buildString {
                append("$stracePath -p $pid -f ")
                append("-e trace=network,file,desc,ipc,signal,process ")
                append("-s 512 -tt -y 2>&1")
            }
            try {
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) scope.launch { parseLine(line) }
                }
            } catch (_: Exception) {
                // Process ended or strace detached
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun parseLine(line: String) {
        if (line.isBlank() || line.startsWith("strace:")) return

        IdentifierMatcher.matchStrace(line)?.let { def ->
            recordIdentifier(def, line)
            return
        }

        val path = extractPath(line)
        if (path != null) {
            IdentifierMatcher.matchPath(path)?.let { def ->
                recordIdentifier(def, line, path)
                return
            }
        }

        classifySyscall(line)?.let { info ->
            if (repository.isDuplicate(packageName, info.action, line, sinceMs = 500)) return
            val returnInfo = parseSyscallReturn(line)
            repository.insert(
                CaptureEvent(
                    targetPackage = packageName,
                    category = info.category,
                    source = EventSource.STRACE,
                    action = info.action,
                    requestDetails = info.request,
                    responseDetails = returnInfo ?: info.response,
                    rawData = line.trim(),
                    processId = pid
                )
            )
        }
    }

    private suspend fun recordIdentifier(def: IdentifierDefinition, line: String, path: String? = null) {
        val action = def.displayName
        if (repository.isDuplicate(packageName, action, line, sinceMs = 500)) return

        val returnInfo = parseSyscallReturn(line)

        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.IDENTIFIER,
                source = EventSource.STRACE,
                action = action,
                permission = def.permission,
                requestDetails = path?.let { "Доступ к файлу: $it" }
                    ?: def.filePath?.let { "File: $it" }
                    ?: def.systemProperty?.let { "Property: $it" }
                    ?: "Системный вызов: ${def.api ?: def.id}",
                responseDetails = returnInfo ?: if (line.contains("= -1")) "Ошибка доступа" else "Успешно",
                rawData = line.trim(),
                processId = pid,
                identifierName = def.id,
                identifierGroup = def.group.name
            )
        )
    }

    private data class SyscallInfo(
        val category: AccessCategory,
        val action: String,
        val request: String?,
        val response: String?
    )

    private fun classifySyscall(line: String): SyscallInfo? {
        return when {
            line.contains("openat") || line.contains("open(") -> classifyOpen(line)
            line.contains("connect(") -> classifyConnect(line)
            line.contains("ioctl(") -> classifyIoctl(line)
            line.contains("execve") && line.contains("getprop") -> SyscallInfo(
                AccessCategory.IDENTIFIER,
                "getprop",
                extractBetween(line, "execve("),
                null
            )
            line.contains("read(") && isSensitiveRead(line) -> SyscallInfo(
                AccessCategory.STORAGE,
                "read()",
                extractBetween(line, "read("),
                "Чтение данных"
            )
            line.contains("socket(") -> SyscallInfo(
                AccessCategory.NETWORK,
                "socket()",
                extractBetween(line, "socket("),
                "Создание сокета"
            )
            else -> null
        }
    }

    private fun classifyOpen(line: String): SyscallInfo? {
        val path = extractPath(line) ?: return null
        val category = when {
            path.contains("camera", ignoreCase = true) -> AccessCategory.CAMERA
            path.contains("gps", ignoreCase = true) || path.contains("location", ignoreCase = true) -> AccessCategory.LOCATION
            path.contains("audio", ignoreCase = true) || path.contains("mic", ignoreCase = true) -> AccessCategory.MICROPHONE
            path.contains("bluetooth", ignoreCase = true) -> AccessCategory.BLUETOOTH
            path.contains("telephony", ignoreCase = true) || path.contains("radio", ignoreCase = true) -> AccessCategory.TELEPHONY
            path.contains("contacts", ignoreCase = true) -> AccessCategory.CONTACTS
            path.contains("sms", ignoreCase = true) || path.contains("mms", ignoreCase = true) -> AccessCategory.SMS
            path.contains("sensor", ignoreCase = true) -> AccessCategory.SENSOR
            path.contains("/data/", ignoreCase = true) || path.contains("/storage/", ignoreCase = true) -> AccessCategory.STORAGE
            else -> return null
        }
        return SyscallInfo(
            category = category,
            action = "open($path)",
            request = "Открытие: $path",
            response = parseSyscallReturn(line) ?: if (line.contains("= -1")) "Ошибка" else "Успешно"
        )
    }

    private fun classifyConnect(line: String): SyscallInfo {
        val dest = extractBetween(line, "connect(") ?: line
        return SyscallInfo(
            category = AccessCategory.NETWORK,
            action = "connect()",
            request = "Подключение: $dest",
            response = parseSyscallReturn(line) ?: if (line.contains("= -1")) "Не удалось" else "Подключено"
        )
    }

    private fun classifyIoctl(line: String): SyscallInfo? {
        val lower = line.lowercase()
        val category = when {
            "camera" in lower -> AccessCategory.CAMERA
            "gps" in lower || "gnss" in lower -> AccessCategory.LOCATION
            "audio" in lower -> AccessCategory.MICROPHONE
            "sensor" in lower -> AccessCategory.SENSOR
            else -> return null
        }
        return SyscallInfo(
            category = category,
            action = "ioctl()",
            request = extractBetween(line, "ioctl("),
            response = null
        )
    }

    private fun isSensitiveRead(line: String): Boolean {
        val lower = line.lowercase()
        return listOf("settings", "telephony", "contacts", "sms", "imei", "android_id", "sim", "gservices")
            .any { it in lower }
    }

    private fun extractPath(line: String): String? {
        val quoted = Regex("\"([^\"]+)\"").findAll(line).map { it.groupValues[1] }.toList()
        return quoted.lastOrNull { it.startsWith("/") || it.startsWith("content://") }
    }

    private fun extractBetween(line: String, prefix: String): String? {
        val idx = line.indexOf(prefix)
        if (idx < 0) return null
        return line.substring(idx).take(300)
    }

    /** Парсит «= 42», «= -1 EACCES (Permission denied)» из строки strace. */
    private fun parseSyscallReturn(line: String): String? {
        val match = Regex("=\\s*(-?\\d+)(?:\\s+([A-Z]+(?:\\s+\\([^)]+\\))?))?").find(line) ?: return null
        val code = match.groupValues[1].toIntOrNull() ?: return null
        val err = match.groupValues.getOrNull(2)?.trim().orEmpty()

        return when {
            code >= 0 -> "Возврат: $code"
            err.isNotEmpty() -> "Ошибка: $err (код $code)"
            else -> "Ошибка (код $code)"
        }
    }
}
