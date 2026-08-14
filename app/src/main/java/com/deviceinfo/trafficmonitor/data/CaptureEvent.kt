package com.deviceinfo.trafficmonitor.data

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class AccessCategory {
    PERMISSION,
    LOCATION,
    CAMERA,
    MICROPHONE,
    TELEPHONY,
    IDENTIFIER,
    CONTACTS,
    SMS,
    STORAGE,
    NETWORK,
    SENSOR,
    BLUETOOTH,
    CALENDAR,
    CLIPBOARD,
    SYSTEM_API,
    SYSCALL,
    SECURITY,
    OTHER
}

enum class EventSource {
    APPOPS,
    LOGCAT,
    STRACE,
    PROC,
    DUMPSYS,
    FRIDA,
    PERFETTO,
    TCPDUMP,
    STATSD,
    EBPF,
    MITM
}

@Entity(tableName = "capture_events")
data class CaptureEvent(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val targetPackage: String,
    val category: AccessCategory,
    val source: EventSource,
    val action: String,
    val permission: String? = null,
    val requestDetails: String? = null,
    val responseDetails: String? = null,
    val rawData: String? = null,
    val processId: Int? = null,
    /** Конкретный идентификатор из [IdentifierCatalog], напр. "tel.imei", "build.model" */
    val identifierName: String? = null,
    /** Группа идентификатора: BUILD, TELEPHONY, SETTINGS и т.д. */
    val identifierGroup: String? = null
)
