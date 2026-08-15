package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.categoryForIdentifierId
import com.deviceinfo.trafficmonitor.probe.IdentifierReader

/**
 * Чекеры читают Build.MODEL / Android ID / IMEI / last location / Wi‑Fi
 * через getstatic и API в первые миллисекунды. Frida (ptrace после старта)
 * и logcat это часто пропускают. Снимок — только пока процесс цели жив:
 * до запуска список пустой.
 */
object IdentifierSnapshot {

    private const val REQUEST =
        "прочитано после запуска цели (доступно процессу)"

    suspend fun record(packageName: String, pid: Int, repository: CaptureRepository) {
        if (pid <= 0) return

        val values = IdentifierReader.readVisibleToProcess()
        if (values.isEmpty()) return

        repository.insertSnapshot(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.IDENTIFIER,
                source = EventSource.DUMPSYS,
                action = "Снимок после запуска",
                requestDetails = REQUEST,
                responseDetails = IdentifierReader.format(values),
                rawData = values.joinToString("\n") { "${it.id}=${it.value}" },
                processId = pid,
                identifierName = "settings.android_id",
                identifierGroup = "SETTINGS"
            )
        )

        for (value in values) {
            val def = IdentifierCatalog.findById(value.id)
            val category = when {
                value.id.startsWith("location.") -> AccessCategory.LOCATION
                value.id.startsWith("wifi.") -> AccessCategory.NETWORK
                else -> categoryForIdentifierId(value.id) ?: AccessCategory.IDENTIFIER
            }.let { mapped ->
                if (mapped == AccessCategory.TELEPHONY) AccessCategory.IDENTIFIER else mapped
            }
            repository.insertSnapshot(
                CaptureEvent(
                    targetPackage = packageName,
                    category = category,
                    source = EventSource.DUMPSYS,
                    action = value.label,
                    permission = def?.permission,
                    requestDetails = def?.api ?: def?.systemProperty ?: REQUEST,
                    responseDetails = value.value,
                    rawData = "${value.id}=${value.value}",
                    processId = pid,
                    identifierName = value.id,
                    identifierGroup = def?.group?.name
                )
            )
        }
    }
}
