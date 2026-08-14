package com.deviceinfo.trafficmonitor.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.Code
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.KeyboardArrowDown
import androidx.compose.material.icons.outlined.KeyboardArrowUp
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.Sensors
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.IdentifierGroup
import com.deviceinfo.trafficmonitor.probe.ProbeResult
import com.deviceinfo.trafficmonitor.ui.theme.Accent
import com.deviceinfo.trafficmonitor.ui.theme.SurfaceLift
import com.deviceinfo.trafficmonitor.ui.theme.TextMuted
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val primaryFilters = listOf(
    AccessCategory.LOCATION,
    AccessCategory.CAMERA,
    AccessCategory.TELEPHONY,
    AccessCategory.IDENTIFIER,
    AccessCategory.SECURITY,
    AccessCategory.NETWORK
)

private val extraFilters = listOf(
    AccessCategory.PERMISSION,
    AccessCategory.MICROPHONE,
    AccessCategory.STORAGE,
    AccessCategory.SENSOR,
    AccessCategory.BLUETOOTH,
    AccessCategory.CONTACTS,
    AccessCategory.SMS,
    AccessCategory.CLIPBOARD,
    AccessCategory.CALENDAR,
    AccessCategory.SYSTEM_API,
    AccessCategory.SYSCALL,
    AccessCategory.OTHER
)

@Composable
fun CategoryFilterRow(
    selected: AccessCategory?,
    counts: Map<AccessCategory, Int>,
    total: Int,
    onSelect: (AccessCategory?) -> Unit
) {
    val visible = buildList {
        add(null)
        addAll(primaryFilters)
        extraFilters.filter { cat ->
            cat == selected || (counts[cat] ?: 0) > 0
        }.forEach { add(it) }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        visible.forEach { cat ->
            val count = if (cat == null) total else counts[cat] ?: 0
            IconFilter(
                icon = cat?.let { categoryIcon(it) } ?: allIcon(),
                label = if (cat == null) "Все" else categoryLabel(cat),
                count = count,
                selected = selected == cat,
                color = cat?.let { categoryColor(it) } ?: Accent,
                onClick = { onSelect(cat) }
            )
        }
    }
}

@Composable
private fun IconFilter(
    icon: ImageVector,
    label: String,
    count: Int,
    selected: Boolean,
    color: Color,
    onClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .widthIn(min = 40.dp)
            .clip(RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 2.dp, vertical = 2.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(contentAlignment = Alignment.TopEnd) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(if (selected) color.copy(alpha = 0.22f) else SurfaceLift)
                    .then(
                        if (selected) Modifier.border(1.5.dp, color, CircleShape)
                        else Modifier
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, null, tint = if (selected || count > 0) color else TextMuted, modifier = Modifier.size(16.dp))
            }
            if (count > 0) {
                Box(
                    modifier = Modifier
                        .padding(start = 22.dp)
                        .height(14.dp)
                        .clip(RoundedCornerShape(7.dp))
                        .background(if (selected) color else SurfaceLift)
                        .padding(horizontal = 4.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        if (count > 99) "99+" else count.toString(),
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (selected) Color(0xFF003821) else MaterialTheme.colorScheme.onSurface,
                        lineHeight = 10.sp
                    )
                }
            }
        }
        Text(
            label,
            fontSize = 9.sp,
            color = if (selected) color else TextMuted,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            maxLines = 1
        )
    }
}

@Composable
fun IdentifierGroupFilterRow(
    selected: String?,
    counts: Map<String, Int>,
    onSelect: (String?) -> Unit
) {
    val groups = buildList {
        add(null)
        IdentifierGroup.entries
            .filter { selected == it.name || (counts[it.name] ?: 0) > 0 }
            .forEach { add(it) }
    }
    if (groups.size <= 1) return
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        groups.forEach { group ->
            val name = group?.name
            val count = if (group == null) counts.values.sum() else counts[group.name] ?: 0
            val active = selected == name
            val color = group?.let { categoryColor(AccessCategory.IDENTIFIER) } ?: Accent
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp))
                    .background(if (active) color.copy(alpha = 0.18f) else SurfaceLift)
                    .clickable { onSelect(name) }
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    group?.let { identifierGroupIcon(it) } ?: allIcon(),
                    null,
                    modifier = Modifier.size(12.dp),
                    tint = if (active) color else TextMuted
                )
                Spacer(Modifier.width(4.dp))
                Text(
                    if (group == null) "Все ID" else identifierGroupShort(group),
                    fontSize = 10.sp,
                    color = if (active) MaterialTheme.colorScheme.onSurface else TextMuted
                )
                if (count > 0) {
                    Spacer(Modifier.width(4.dp))
                    Text(count.toString(), fontSize = 9.sp, color = color, fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}

@Composable
fun ToolStrip(
    fridaStatus: FridaInstaller.FridaStatus,
    isInjecting: Boolean,
    mitmActive: Boolean,
    isMitmStarting: Boolean,
    onAttach: () -> Unit,
    onWrap: () -> Unit,
    onMitm: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        ToolPill(
            modifier = Modifier.weight(1f),
            icon = Icons.Outlined.Link,
            label = "Frida",
            hint = when (fridaStatus) {
                FridaInstaller.FridaStatus.INJECTED -> "on"
                FridaInstaller.FridaStatus.READY -> "attach"
                else -> fridaStatusLabel(fridaStatus).removePrefix("Frida ").ifBlank { "…" }
            },
            active = fridaStatus == FridaInstaller.FridaStatus.INJECTED,
            loading = isInjecting,
            enabled = !isInjecting && fridaStatus != FridaInstaller.FridaStatus.INJECTED,
            onClick = onAttach
        )
        ToolPill(
            modifier = Modifier.weight(1f),
            icon = Icons.Outlined.PlayArrow,
            label = "+ Frida",
            hint = "запуск",
            active = false,
            loading = isInjecting,
            enabled = !isInjecting,
            onClick = onWrap
        )
        ToolPill(
            modifier = Modifier.weight(1f),
            icon = Icons.Outlined.VpnKey,
            label = "MITM",
            hint = if (mitmActive) "выкл" else "HTTPS",
            active = mitmActive,
            loading = isMitmStarting,
            enabled = !isMitmStarting,
            onClick = onMitm
        )
    }
}

@Composable
private fun ToolPill(
    modifier: Modifier = Modifier,
    icon: ImageVector,
    label: String,
    hint: String,
    active: Boolean,
    loading: Boolean,
    enabled: Boolean,
    onClick: () -> Unit
) {
    val tint = when {
        active -> Accent
        enabled -> MaterialTheme.colorScheme.onSurface
        else -> TextMuted
    }
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(if (active) Accent.copy(alpha = 0.14f) else SurfaceLift)
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center
    ) {
        if (loading) {
            CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 1.5.dp, color = Accent)
        } else {
            Icon(icon, contentDescription = label, tint = tint, modifier = Modifier.size(15.dp))
        }
        Spacer(Modifier.width(6.dp))
        Column {
            Text(label, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = tint, lineHeight = 12.sp)
            Text(hint, fontSize = 9.sp, color = TextMuted, lineHeight = 10.sp)
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun EventRow(item: DisplayEvent, onClick: () -> Unit, onLongClick: () -> Unit = {}) {
    val event = item.event
    val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(event.timestamp))
    val color = categoryColor(event.category)
    val preview = event.responseDetails ?: event.requestDetails ?: event.action
    val risk = isHighRisk(event.category)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .background(
                when {
                    item.pinned -> Accent.copy(alpha = 0.08f)
                    risk -> color.copy(alpha = 0.05f)
                    else -> Color.Transparent
                }
            )
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(28.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.16f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(categoryIcon(event.category), null, tint = color, modifier = Modifier.size(14.dp))
        }
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = event.action,
                    fontWeight = FontWeight.Medium,
                    fontSize = 13.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                if (item.pinned) {
                    Icon(Icons.Outlined.PushPin, null, modifier = Modifier.size(11.dp).padding(end = 4.dp), tint = Accent)
                }
                if (item.repeats > 1) {
                    Text(
                        "×${item.repeats}",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = color,
                        modifier = Modifier.padding(end = 6.dp)
                    )
                }
                Text(time, fontSize = 10.sp, color = TextMuted)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = preview,
                    fontSize = 11.sp,
                    color = TextMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(6.dp))
                Icon(sourceIcon(event.source), null, modifier = Modifier.size(10.dp), tint = TextMuted)
                Spacer(Modifier.width(2.dp))
                Text(sourceLabel(event.source), fontSize = 9.sp, color = TextMuted)
                event.identifierName?.let {
                    Text(" · $it", fontSize = 9.sp, fontFamily = FontFamily.Monospace, color = Accent, maxLines = 1)
                }
            }
        }
    }
}

@Composable
fun EmptyMonitorHint() {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
        Icon(Icons.Outlined.Sensors, null, tint = Accent, modifier = Modifier.size(32.dp))
        Spacer(Modifier.height(10.dp))
        Text("Пока тихо", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            HintStep(Icons.Outlined.PlayArrow, "Запуск")
            HintStep(Icons.Outlined.Link, "Frida")
            HintStep(Icons.Outlined.VpnKey, "MITM")
        }
    }
}

@Composable
private fun HintStep(icon: ImageVector, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(CircleShape)
                .background(SurfaceLift),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, null, tint = Accent, modifier = Modifier.size(16.dp))
        }
        Spacer(Modifier.height(4.dp))
        Text(label, fontSize = 10.sp, color = TextMuted)
    }
}

@Composable
fun EventDetailSheet(
    event: CaptureEvent,
    probeResult: ProbeResult?,
    isProbing: Boolean,
    canPrev: Boolean,
    canNext: Boolean,
    pinned: Boolean = false,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onProbe: () -> Unit,
    onPin: () -> Unit = {}
) {
    val timeFormat = SimpleDateFormat("dd.MM.yyyy HH:mm:ss.SSS", Locale.getDefault())
    val color = categoryColor(event.category)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(color.copy(alpha = 0.18f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(categoryIcon(event.category), null, tint = color, modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(event.action, style = MaterialTheme.typography.titleMedium, maxLines = 2)
                Text(categoryFullLabel(event.category), style = MaterialTheme.typography.bodySmall)
            }
            IconButton(onClick = onPrev, enabled = canPrev, modifier = Modifier.size(32.dp)) {
                Icon(Icons.Outlined.KeyboardArrowUp, "Новее", modifier = Modifier.size(20.dp), tint = if (canPrev) Accent else TextMuted)
            }
            IconButton(onClick = onNext, enabled = canNext, modifier = Modifier.size(32.dp)) {
                Icon(Icons.Outlined.KeyboardArrowDown, "Старее", modifier = Modifier.size(20.dp), tint = if (canNext) Accent else TextMuted)
            }
            IconButton(onClick = onPin, modifier = Modifier.size(32.dp)) {
                Icon(
                    if (pinned) Icons.Outlined.Star else Icons.Outlined.StarBorder,
                    if (pinned) "Открепить" else "Закрепить",
                    modifier = Modifier.size(16.dp),
                    tint = if (pinned) Accent else TextMuted
                )
            }
            val clipboard = LocalClipboardManager.current
            IconButton(
                onClick = { clipboard.setText(AnnotatedString(eventAsText(event))) },
                modifier = Modifier.size(32.dp)
            ) {
                Icon(Icons.Outlined.ContentCopy, "Копировать всё", modifier = Modifier.size(16.dp), tint = TextMuted)
            }
        }
        Spacer(Modifier.height(12.dp))
        DetailRow("Источник", sourceLabel(event.source), sourceIcon(event.source))
        DetailRow("Время", timeFormat.format(Date(event.timestamp)))
        event.identifierName?.let { id ->
            DetailRow("ID", id, categoryIcon(AccessCategory.IDENTIFIER))
            IdentifierCatalog.findById(id)?.let { def ->
                def.api?.let { DetailRow("API", it, Icons.Outlined.Code) }
                def.systemProperty?.let { DetailRow("prop", it) }
                DetailRow("Группа", def.group.label, identifierGroupIcon(def.group))
            }
        }
        event.permission?.let { DetailRow("Право", it, Icons.Outlined.Bolt) }
        event.processId?.let { DetailRow("PID", it.toString()) }

        event.requestDetails?.let { CopySection("Запрос", it) }
        event.responseDetails?.let { CopySection("Ответ", it, Accent.copy(alpha = 0.12f)) }

        Button(
            onClick = onProbe,
            enabled = !isProbing,
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(vertical = 8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color(0xFF003821))
        ) {
            if (isProbing) {
                CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp, color = Color(0xFF003821))
                Spacer(Modifier.width(8.dp))
            } else {
                Icon(Icons.Outlined.Science, null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
            }
            Text("Проверить ответ", fontSize = 13.sp)
        }

        probeResult?.let { probe ->
            Spacer(Modifier.height(8.dp))
            Text(probe.requestLabel, style = MaterialTheme.typography.bodySmall)
            CopySection(null, probe.valueAsRoot, Accent.copy(alpha = 0.12f))
            probe.valueInTargetContext?.let {
                Text("В приложении", fontWeight = FontWeight.Medium, fontSize = 12.sp)
                Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            }
            Text(probe.note, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 6.dp))
        }

        event.rawData?.let { CopySection("Raw", it) }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun CopySection(title: String?, body: String, bg: Color = SurfaceLift) {
    val clipboard = LocalClipboardManager.current
    if (title != null) {
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(title, fontWeight = FontWeight.SemiBold, fontSize = 12.sp, modifier = Modifier.weight(1f))
            IconButton(onClick = { clipboard.setText(AnnotatedString(body)) }, modifier = Modifier.size(28.dp)) {
                Icon(Icons.Outlined.ContentCopy, "Копировать", modifier = Modifier.size(14.dp), tint = TextMuted)
            }
        }
    } else {
        Spacer(Modifier.height(4.dp))
    }
    Surface(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        shape = RoundedCornerShape(10.dp),
        color = bg
    ) {
        Text(body, modifier = Modifier.padding(10.dp), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
    }
}

@Composable
fun DetailRow(label: String, value: String, icon: ImageVector? = null) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) {
            Icon(icon, null, modifier = Modifier.size(13.dp), tint = TextMuted)
            Spacer(Modifier.width(6.dp))
        } else {
            Spacer(Modifier.width(19.dp))
        }
        Text(label, modifier = Modifier.width(68.dp), fontSize = 11.sp, color = TextMuted)
        Text(value, fontSize = 12.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

fun fridaStatusLabel(status: FridaInstaller.FridaStatus): String = when (status) {
    FridaInstaller.FridaStatus.NOT_INSTALLED -> "Frida нет"
    FridaInstaller.FridaStatus.EXTRACTING -> "Frida…"
    FridaInstaller.FridaStatus.DOWNLOADING -> "Frida ↓"
    FridaInstaller.FridaStatus.READY -> "Frida ready"
    FridaInstaller.FridaStatus.INJECTED -> "Frida on"
    FridaInstaller.FridaStatus.ERROR -> "Frida err"
}
