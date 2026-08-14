package com.deviceinfo.trafficmonitor.probe

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
        val property = resolveProperty(event, def)

        if (property != null) {
            return probeProperty(property, event.processId, event.targetPackage)
        }

        if (def?.filePath != null) {
            return probeFile(def.filePath, event.processId)
        }

        return ProbeResult(
            requestLabel = event.action,
            valueAsRoot = "Повтор недоступен для этого типа запроса",
            valueInTargetContext = null,
            note = "Для точного перехвата ответа используйте Frida-хуки (источник Frida в списке событий)."
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
