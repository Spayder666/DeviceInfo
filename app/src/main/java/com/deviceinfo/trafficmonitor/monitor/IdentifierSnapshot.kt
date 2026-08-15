package com.deviceinfo.trafficmonitor.monitor

import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.probe.IdentifierReader

/**
 * Как в v1.0.32: при старте сессии один раз читаем модель, Android ID, IMEI
 * и остальные обычные идентификаторы с устройства и кладём их в список ID.
 */
object IdentifierSnapshot {

    suspend fun record(packageName: String, pid: Int, repository: CaptureRepository) {
        val values = IdentifierReader.readCommon()
        if (values.isEmpty()) return

        repository.insertSnapshot(
            CaptureEvent(
                targetPackage = packageName,
                category = AccessCategory.IDENTIFIER,
                source = EventSource.DUMPSYS,
                action = "Снимок идентификаторов",
                requestDetails = "Текущие значения устройства (прочитаны от root)",
                responseDetails = IdentifierReader.format(values),
                rawData = values.joinToString("\n") { "${it.id}=${it.value}" },
                processId = pid.takeIf { it > 0 },
                identifierName = "settings.android_id",
                identifierGroup = "SETTINGS"
            )
        )

        for (value in values) {
            val def = IdentifierCatalog.findById(value.id)
            repository.insertSnapshot(
                CaptureEvent(
                    targetPackage = packageName,
                    category = AccessCategory.IDENTIFIER,
                    source = EventSource.DUMPSYS,
                    action = value.label,
                    permission = def?.permission,
                    requestDetails = def?.api ?: def?.systemProperty ?: value.id,
                    responseDetails = value.value,
                    rawData = "${value.id}=${value.value}",
                    processId = pid.takeIf { it > 0 },
                    identifierName = value.id,
                    identifierGroup = def?.group?.name
                )
            )
        }
    }
}
