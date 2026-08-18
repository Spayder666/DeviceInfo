package com.deviceinfo.trafficmonitor.probe

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.root.RootShell

data class ProbeResult(
    val requestLabel: String,
    val valueAsRoot: String,
    val valueInTargetContext: String?,
    val note: String
)

object IdentifierProbe {

    fun probe(event: CaptureEvent): ProbeResult {
        val def = event.identifierName?.let { IdentifierCatalog.findById(it) }

        if (event.category == AccessCategory.IDENTIFIER) {
            val property = resolveProperty(event, def)
            if (property != null) {
                return probeProperty(property, event.processId, event.targetPackage)
            }
            if (def?.filePath != null && def.group != com.deviceinfo.trafficmonitor.identifiers.IdentifierGroup.LOCATION) {
                return probeFile(def.filePath, event.processId)
            }
        }

        val values = IdentifierReader.readForEvent(event)
        if (values.isNotEmpty()) {
            val original = listOfNotNull(event.action, event.requestDetails)
                .filter { it.isNotBlank() }
                .distinct()
                .joinToString(" · ")
            return ProbeResult(
                requestLabel = "Повтор: $original",
                valueAsRoot = IdentifierReader.format(values),
                valueInTargetContext = event.responseDetails?.takeIf { it.isNotBlank() && !it.startsWith("FD=") },
                note = noteFor(event)
            )
        }

        probeFdEvent(event)?.let { return it }

        event.responseDetails?.takeIf { it.isNotBlank() && !it.startsWith("FD=") && !it.startsWith("/") }?.let { response ->
            return ProbeResult(
                requestLabel = event.action,
                valueAsRoot = response,
                valueInTargetContext = null,
                note = "Значение из перехвата (${event.source.name.lowercase()})."
            )
        }

        return ProbeResult(
            requestLabel = event.action,
            valueAsRoot = "Не удалось прочитать значение",
            valueInTargetContext = null,
            note = "Для этого типа события нет системного API. Нажмите «Запустить + Frida», чтобы перехватывать ответы внутри приложения."
        )
    }

    private fun noteFor(event: CaptureEvent): String = when (event.category) {
        AccessCategory.LOCATION -> "Координаты провайдеров gps/fused/network — ответ на запрос локации."
        AccessCategory.CAMERA -> "Состояние камер из media.camera, не идентификаторы устройства."
        AccessCategory.MICROPHONE -> "Активные аудиовходы / запись из AudioFlinger."
        AccessCategory.TELEPHONY -> "IMEI / IMSI / ICCID / номер — ответ на телефонный запрос."
        AccessCategory.CONTACTS -> "Данные контактов (content://contacts)."
        AccessCategory.SMS -> "SMS inbox (content://sms)."
        AccessCategory.CALENDAR -> "События календаря."
        AccessCategory.CLIPBOARD -> "Текущий буфер обмена."
        AccessCategory.SENSOR -> "Активные сенсоры из sensorservice."
        AccessCategory.BLUETOOTH -> "BT MAC / имя."
        AccessCategory.NETWORK -> "Повтор того же DNS/HTTP запроса (хост из события), не соседние идентификаторы."
        AccessCategory.STORAGE -> "MediaStore / БД пакета."
        AccessCategory.PERMISSION -> "Статус AppOps / grant для этого разрешения."
        AccessCategory.IDENTIFIER -> "Идентификатор того же типа, что в запросе."
        AccessCategory.SYSTEM_API -> "Системные сервисы пакета."
        AccessCategory.SECURITY -> "Что устройство отвечает на ту же проверку root/integrity (su, props, SELinux, verified boot)."
        else -> "Ответ того же типа, что и запрос."
    }

    private fun looksLikeCapturedValue(text: String): Boolean {
        if (text.isBlank() || text.startsWith("/") || text.startsWith("FD=")) return false
        if (text.contains("читаются из dumpsys", ignoreCase = true)) return false
        if (text.contains("Монитор локации", ignoreCase = true)) return false
        return text.contains("lat=") ||
            text.contains("Location[") ||
            Regex("-?\\d+\\.\\d+\\s*,\\s*-?\\d+\\.\\d+").containsMatchIn(text)
    }

    private fun probeFdEvent(event: CaptureEvent): ProbeResult? {
        val fdMatch = Regex("^fd:(\\d+)$").find(event.action) ?: return null
        val fd = fdMatch.groupValues[1]
        val pid = event.processId ?: return ProbeResult(
            requestLabel = event.action,
            valueAsRoot = event.responseDetails ?: "(PID неизвестен)",
            valueInTargetContext = null,
            note = "Путь fd виден в ответе. Для повторной проверки нужен PID процесса."
        )

        val link = RootShell.execAndRead("readlink /proc/$pid/fd/$fd 2>&1").trim()
        val pathFromRequest = event.requestDetails
            ?.substringAfter("Открытый дескриптор: ")
            ?.trim()

        return ProbeResult(
            requestLabel = "fd:$fd",
            valueAsRoot = link.ifBlank { pathFromRequest ?: "(не удалось прочитать)" },
            valueInTargetContext = pathFromRequest?.takeIf { it != link },
            note = "Текущий путь файлового дескриптора в /proc/$pid/fd/$fd."
        )
    }

    private fun resolveProperty(event: CaptureEvent, def: com.deviceinfo.trafficmonitor.identifiers.IdentifierDefinition?): String? {
        def?.systemProperty?.let { return it }

        val raw = event.rawData ?: return null
        Regex("Access denied finding property \"([^\"]+)\"").find(raw)?.let {
            return it.groupValues[1]
        }
        Regex("property \"([^\"]+)\"").find(raw)?.let {
            return it.groupValues[1]
        }
        Regex("Property:\\s*(\\S+)").find(event.requestDetails ?: "")?.let {
            return it.groupValues[1]
        }
        return null
    }

    private fun probeProperty(property: String, pid: Int?, packageName: String): ProbeResult {
        val asRoot = readProperty("getprop $property")

        val inTarget = when {
            pid != null && pid > 0 -> probeInProcess(pid, property)
            else -> probeAsAppUid(packageName, property)
        }

        val note = buildString {
            append("«От root» — что вернёт getprop с правами root. ")
            append("«В контексте приложения» — запрос из namespace процесса (ближе к тому, что видит приложение). ")
            append("Точный ответ в момент вызова фиксирует Frida (Java + native hooks).")
        }

        return ProbeResult(
            requestLabel = property,
            valueAsRoot = asRoot,
            valueInTargetContext = inTarget,
            note = note
        )
    }

    private fun probeInProcess(pid: Int, property: String): String {
        val viaNsenter = readProperty("nsenter -t $pid -m sh -c 'getprop $property' 2>&1")
        if (viaNsenter.isNotBlank() && !viaNsenter.contains("cannot open")) {
            return formatPropertyResult(viaNsenter)
        }
        return "(не удалось войти в namespace PID=$pid)"
    }

    private fun probeAsAppUid(packageName: String, property: String): String {
        val uid = RootShell.getUid(packageName)
        if (uid == null) return "(UID приложения неизвестен)"

        val viaRunAs = readProperty("run-as $packageName getprop $property 2>&1")
        if (!viaRunAs.contains("not debuggable") && !viaRunAs.contains("Permission denied")) {
            return formatPropertyResult(viaRunAs)
        }

        val viaSu = readProperty("su --mount-master -c 'getprop $property' 2>&1")
        return formatPropertyResult(viaSu) + " (через root, UID=$uid)"
    }

    private fun probeFile(path: String, pid: Int?): ProbeResult {
        val asRoot = readProperty("cat $path 2>&1 | head -c 500")
        val inTarget = pid?.let {
            readProperty("nsenter -t $it -m cat $path 2>&1 | head -c 500")
        }

        return ProbeResult(
            requestLabel = path,
            valueAsRoot = asRoot.ifBlank { "(пусто / недоступно)" },
            valueInTargetContext = inTarget?.ifBlank { "(пусто / недоступно)" },
            note = "Чтение файла напрямую. SELinux может блокировать доступ приложения."
        )
    }

    private fun readProperty(command: String): String {
        return RootShell.execAndRead(command, timeoutSec = 8).trim()
    }

    private fun formatPropertyResult(raw: String): String {
        return when {
            raw.isBlank() -> "(пусто — свойство не найдено или доступ запрещён)"
            raw.contains("Access denied", ignoreCase = true) -> "ОТКЛОНЕНО: $raw"
            else -> raw
        }
    }
}
