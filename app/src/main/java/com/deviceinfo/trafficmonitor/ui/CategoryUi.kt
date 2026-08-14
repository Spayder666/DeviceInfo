package com.deviceinfo.trafficmonitor.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.BarChart
import androidx.compose.material.icons.outlined.Bluetooth
import androidx.compose.material.icons.outlined.CalendarMonth
import androidx.compose.material.icons.outlined.Code
import androidx.compose.material.icons.outlined.Contacts
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Mic
import androidx.compose.material.icons.outlined.MoreHoriz
import androidx.compose.material.icons.outlined.MyLocation
import androidx.compose.material.icons.outlined.PhotoCamera
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.Sensors
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.SimCard
import androidx.compose.material.icons.outlined.Sms
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.Timeline
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.EventSource

fun categoryColor(category: AccessCategory): Color = when (category) {
    AccessCategory.LOCATION -> Color(0xFF3DDC97)
    AccessCategory.CAMERA -> Color(0xFFFF6B6B)
    AccessCategory.MICROPHONE -> Color(0xFFFF8FAB)
    AccessCategory.TELEPHONY -> Color(0xFF58A6FF)
    AccessCategory.IDENTIFIER -> Color(0xFFD2A8FF)
    AccessCategory.CONTACTS -> Color(0xFF39D0D8)
    AccessCategory.SMS -> Color(0xFFFFB347)
    AccessCategory.STORAGE -> Color(0xFF8BC34A)
    AccessCategory.NETWORK -> Color(0xFF79C0FF)
    AccessCategory.SENSOR -> Color(0xFFB388FF)
    AccessCategory.BLUETOOTH -> Color(0xFF82B1FF)
    AccessCategory.CALENDAR -> Color(0xFF80CBC4)
    AccessCategory.CLIPBOARD -> Color(0xFFBCAAA4)
    AccessCategory.PERMISSION -> Color(0xFFFFD54F)
    AccessCategory.SYSTEM_API -> Color(0xFF8B949E)
    AccessCategory.SYSCALL -> Color(0xFF9E9E9E)
    AccessCategory.OTHER -> Color(0xFF757575)
}

fun categoryIcon(category: AccessCategory): ImageVector = when (category) {
    AccessCategory.LOCATION -> Icons.Outlined.MyLocation
    AccessCategory.CAMERA -> Icons.Outlined.PhotoCamera
    AccessCategory.MICROPHONE -> Icons.Outlined.Mic
    AccessCategory.TELEPHONY -> Icons.Outlined.SimCard
    AccessCategory.IDENTIFIER -> Icons.Outlined.Fingerprint
    AccessCategory.CONTACTS -> Icons.Outlined.Contacts
    AccessCategory.SMS -> Icons.Outlined.Sms
    AccessCategory.STORAGE -> Icons.Outlined.Folder
    AccessCategory.NETWORK -> Icons.Outlined.Language
    AccessCategory.SENSOR -> Icons.Outlined.Sensors
    AccessCategory.BLUETOOTH -> Icons.Outlined.Bluetooth
    AccessCategory.CALENDAR -> Icons.Outlined.CalendarMonth
    AccessCategory.CLIPBOARD -> Icons.Outlined.ContentPaste
    AccessCategory.PERMISSION -> Icons.Outlined.Lock
    AccessCategory.SYSTEM_API -> Icons.Outlined.Settings
    AccessCategory.SYSCALL -> Icons.Outlined.Code
    AccessCategory.OTHER -> Icons.Outlined.MoreHoriz
}

fun categoryLabel(category: AccessCategory): String = when (category) {
    AccessCategory.LOCATION -> "GPS"
    AccessCategory.CAMERA -> "Камера"
    AccessCategory.MICROPHONE -> "Мик"
    AccessCategory.TELEPHONY -> "SIM"
    AccessCategory.IDENTIFIER -> "ID"
    AccessCategory.CONTACTS -> "Контакты"
    AccessCategory.SMS -> "SMS"
    AccessCategory.STORAGE -> "Файлы"
    AccessCategory.NETWORK -> "Сеть"
    AccessCategory.SENSOR -> "Датчики"
    AccessCategory.BLUETOOTH -> "BT"
    AccessCategory.CALENDAR -> "Календарь"
    AccessCategory.CLIPBOARD -> "Буфер"
    AccessCategory.PERMISSION -> "Права"
    AccessCategory.SYSTEM_API -> "Система"
    AccessCategory.SYSCALL -> "syscall"
    AccessCategory.OTHER -> "Прочее"
}

fun categoryFullLabel(category: AccessCategory): String = when (category) {
    AccessCategory.LOCATION -> "GPS / геолокация"
    AccessCategory.CAMERA -> "Камера"
    AccessCategory.MICROPHONE -> "Микрофон"
    AccessCategory.TELEPHONY -> "Телефон / SIM"
    AccessCategory.IDENTIFIER -> "Идентификаторы"
    AccessCategory.CONTACTS -> "Контакты"
    AccessCategory.SMS -> "SMS"
    AccessCategory.STORAGE -> "Хранилище"
    AccessCategory.NETWORK -> "Сеть / HTTPS"
    AccessCategory.SENSOR -> "Датчики"
    AccessCategory.BLUETOOTH -> "Bluetooth"
    AccessCategory.CALENDAR -> "Календарь"
    AccessCategory.CLIPBOARD -> "Буфер обмена"
    AccessCategory.PERMISSION -> "Разрешения"
    AccessCategory.SYSTEM_API -> "Системные API"
    AccessCategory.SYSCALL -> "Системные вызовы"
    AccessCategory.OTHER -> "Прочее"
}

fun sourceLabel(source: EventSource): String = when (source) {
    EventSource.APPOPS -> "AppOps"
    EventSource.LOGCAT -> "Logcat"
    EventSource.STRACE -> "strace"
    EventSource.PROC -> "/proc"
    EventSource.DUMPSYS -> "dumpsys"
    EventSource.FRIDA -> "Frida"
    EventSource.PERFETTO -> "Perfetto"
    EventSource.TCPDUMP -> "tcpdump"
    EventSource.STATSD -> "statsd"
    EventSource.EBPF -> "eBPF"
    EventSource.MITM -> "MITM"
}

fun sourceIcon(source: EventSource): ImageVector = when (source) {
    EventSource.APPOPS -> Icons.Outlined.VerifiedUser
    EventSource.LOGCAT -> Icons.Outlined.Description
    EventSource.STRACE -> Icons.Outlined.Code
    EventSource.PROC -> Icons.Outlined.Memory
    EventSource.DUMPSYS -> Icons.Outlined.Storage
    EventSource.FRIDA -> Icons.Outlined.Science
    EventSource.PERFETTO -> Icons.Outlined.Timeline
    EventSource.TCPDUMP -> Icons.Outlined.Wifi
    EventSource.STATSD -> Icons.Outlined.BarChart
    EventSource.EBPF -> Icons.Outlined.Hub
    EventSource.MITM -> Icons.Outlined.VpnKey
}

fun allIcon(): ImageVector = Icons.Outlined.Apps
