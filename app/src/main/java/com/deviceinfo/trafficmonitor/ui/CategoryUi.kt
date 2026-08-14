package com.deviceinfo.trafficmonitor.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.deviceinfo.trafficmonitor.data.AccessCategory

@Composable
fun categoryColor(category: AccessCategory): Color = when (category) {
    AccessCategory.LOCATION -> Color(0xFF2E7D32)
    AccessCategory.CAMERA -> Color(0xFFC62828)
    AccessCategory.MICROPHONE -> Color(0xFFAD1457)
    AccessCategory.TELEPHONY -> Color(0xFF1565C0)
    AccessCategory.IDENTIFIER -> Color(0xFF6A1B9A)
    AccessCategory.CONTACTS -> Color(0xFF00838F)
    AccessCategory.SMS -> Color(0xFFEF6C00)
    AccessCategory.STORAGE -> Color(0xFF558B2F)
    AccessCategory.NETWORK -> Color(0xFF0277BD)
    AccessCategory.SENSOR -> Color(0xFF4527A0)
    AccessCategory.BLUETOOTH -> Color(0xFF283593)
    AccessCategory.CALENDAR -> Color(0xFF00695C)
    AccessCategory.CLIPBOARD -> Color(0xFF795548)
    AccessCategory.PERMISSION -> Color(0xFFF57F17)
    AccessCategory.SYSTEM_API -> Color(0xFF37474F)
    AccessCategory.SYSCALL -> Color(0xFF616161)
    AccessCategory.OTHER -> Color(0xFF757575)
}

fun categoryLabel(category: AccessCategory): String = when (category) {
    AccessCategory.LOCATION -> "GPS / Геолокация"
    AccessCategory.CAMERA -> "Камера"
    AccessCategory.MICROPHONE -> "Микрофон"
    AccessCategory.TELEPHONY -> "Телефон / SIM"
    AccessCategory.IDENTIFIER -> "Идентификаторы"
    AccessCategory.CONTACTS -> "Контакты"
    AccessCategory.SMS -> "SMS"
    AccessCategory.STORAGE -> "Хранилище"
    AccessCategory.NETWORK -> "Сеть / API"
    AccessCategory.SENSOR -> "Датчики"
    AccessCategory.BLUETOOTH -> "Bluetooth"
    AccessCategory.CALENDAR -> "Календарь"
    AccessCategory.CLIPBOARD -> "Буфер обмена"
    AccessCategory.PERMISSION -> "Разрешения"
    AccessCategory.SYSTEM_API -> "Системные API"
    AccessCategory.SYSCALL -> "Системные вызовы"
    AccessCategory.OTHER -> "Прочее"
}

fun sourceLabel(source: com.deviceinfo.trafficmonitor.data.EventSource): String = when (source) {
    com.deviceinfo.trafficmonitor.data.EventSource.APPOPS -> "AppOps"
    com.deviceinfo.trafficmonitor.data.EventSource.LOGCAT -> "Logcat"
    com.deviceinfo.trafficmonitor.data.EventSource.STRACE -> "strace"
    com.deviceinfo.trafficmonitor.data.EventSource.PROC -> "/proc"
    com.deviceinfo.trafficmonitor.data.    EventSource.DUMPSYS -> "dumpsys"
    EventSource.FRIDA -> "Frida"
}
