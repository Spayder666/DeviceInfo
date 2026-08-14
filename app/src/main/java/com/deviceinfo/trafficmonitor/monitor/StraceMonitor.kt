package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
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
                append("-e trace=network,file,desc,ipc,signal ")
                append("-s 512 -tt -y 2>&1")
            }
            try {
                RootShell.execStreaming(cmd) { line ->
                    if (isActive) {
                        scope.launch { parseLine(line) }
                    }
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

        val parsed = classifySyscall(line) ?: return
        if (repository.isDuplicate(packageName, parsed.action, line, sinceMs = 500)) return

        repository.insert(
            CaptureEvent(
                targetPackage = packageName,
                category = parsed.category,
                source = EventSource.STRACE,
                action = parsed.action,
                requestDetails = parsed.request,
                responseDetails = parsed.response,
                rawData = line.trim(),
                processId = pid
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
            line.contains("read(") && isSensitiveRead(line) -> SyscallInfo(
                AccessCategory.STORAGE,
                "read()",
                extractBetween(line, "read("),
                "Чтение данных из файла/дескриптора"
            )
            line.contains("write(") && line.contains("/dev/") -> SyscallInfo(
                AccessCategory.SYSTEM_API,
                "write()",
                extractBetween(line, "write("),
                "Запись в системное устройство"
            )
            line.contains("socket(") -> SyscallInfo(
                AccessCategory.NETWORK,
                "socket()",
                extractBetween(line, "socket("),
                "Создание сетевого сокета"
            )
            line.contains("getsockopt") || line.contains("setsockopt") -> SyscallInfo(
                AccessCategory.NETWORK,
                "socket option",
                line.substringAfter("=").take(200),
                null
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
            path.contains("android_id", ignoreCase = true) || path.contains("settings", ignoreCase = true) -> AccessCategory.IDENTIFIER
            path.contains("sensor", ignoreCase = true) -> AccessCategory.SENSOR
            path.contains("/proc/", ignoreCase = true) || path.contains("/sys/", ignoreCase = true) -> AccessCategory.SYSTEM_API
            path.contains("/data/", ignoreCase = true) || path.contains("/storage/", ignoreCase = true) -> AccessCategory.STORAGE
            else -> AccessCategory.SYSCALL
        }
        return SyscallInfo(
            category = category,
            action = "open($path)",
            request = "Открытие: $path",
            response = if (line.contains("= -1")) "Ошибка доступа" else "Успешно"
        )
    }

    private fun classifyConnect(line: String): SyscallInfo {
        val dest = extractBetween(line, "connect(") ?: line
        return SyscallInfo(
            category = AccessCategory.NETWORK,
            action = "connect()",
            request = "Подключение: $dest",
            response = if (line.contains("= -1")) "Не удалось подключиться" else "Подключено"
        )
    }

    private fun classifyIoctl(line: String): SyscallInfo? {
        val lower = line.lowercase()
        val category = when {
            "camera" in lower -> AccessCategory.CAMERA
            "gps" in lower || "gnss" in lower -> AccessCategory.LOCATION
            "audio" in lower -> AccessCategory.MICROPHONE
            "sensor" in lower -> AccessCategory.SENSOR
            else -> AccessCategory.SYSCALL
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
        return listOf("settings", "telephony", "contacts", "sms", "imei", "android_id", "sim")
            .any { it in lower }
    }

    private fun extractPath(line: String): String? {
        val quoted = Regex("\"([^\"]+)\"").findAll(line).map { it.groupValues[1] }.toList()
        return quoted.lastOrNull { it.startsWith("/") }
    }

    private fun extractBetween(line: String, prefix: String): String? {
        val idx = line.indexOf(prefix)
        if (idx < 0) return null
        return line.substring(idx).take(300)
    }
}
