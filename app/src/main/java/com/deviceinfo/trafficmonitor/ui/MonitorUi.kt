package com.deviceinfo.trafficmonitor.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val filterCategories = listOf(
    null,
    AccessCategory.LOCATION,
    AccessCategory.CAMERA,
    AccessCategory.TELEPHONY,
    AccessCategory.IDENTIFIER,
    AccessCategory.NETWORK,
    AccessCategory.PERMISSION,
    AccessCategory.MICROPHONE,
    AccessCategory.STORAGE,
    AccessCategory.SENSOR,
    AccessCategory.BLUETOOTH,
    AccessCategory.CONTACTS,
    AccessCategory.SMS,
    AccessCategory.CLIPBOARD,
    AccessCategory.CALENDAR,
    AccessCategory.SYSTEM_API
)

@Composable
fun CategoryFilterRow(
    selected: AccessCategory?,
    counts: Map<AccessCategory, Int>,
    total: Int,
    onSelect: (AccessCategory?) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        filterCategories.forEach { cat ->
            val label = if (cat == null) "Все" else categoryLabel(cat)
            val count = if (cat == null) total else counts[cat] ?: 0
            val selectedNow = selected == cat
            FilterChip(
                selected = selectedNow,
                onClick = { onSelect(cat) },
                label = {
                    Text(
                        if (count > 0) "$label $count" else label,
                        fontSize = 11.sp,
                        maxLines = 1
                    )
                },
                leadingIcon = {
                    Icon(
                        imageVector = cat?.let { categoryIcon(it) } ?: allIcon(),
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = (cat?.let { categoryColor(it) } ?: Accent).copy(alpha = 0.22f),
                    selectedLabelColor = MaterialTheme.colorScheme.onSurface,
                    selectedLeadingIconColor = cat?.let { categoryColor(it) } ?: Accent
                )
            )
        }
    }
}

@Composable
fun IdentifierGroupFilterRow(selected: String?, onSelect: (String?) -> Unit) {
    val groups = listOf(null to "Все ID") + IdentifierGroup.entries.map { it.name to it.label }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        groups.forEach { (name, label) ->
            FilterChip(
                selected = selected == name,
                onClick = { onSelect(name) },
                label = { Text(label, fontSize = 10.sp, maxLines = 1) }
            )
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
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 4.dp),
        shape = RoundedCornerShape(12.dp),
        color = SurfaceLift
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            ToolButton(
                icon = Icons.Outlined.Link,
                label = "Frida",
                hint = if (fridaStatus == FridaInstaller.FridaStatus.INJECTED) "on" else "attach",
                active = fridaStatus == FridaInstaller.FridaStatus.INJECTED,
                loading = isInjecting,
                enabled = !isInjecting && fridaStatus != FridaInstaller.FridaStatus.INJECTED,
                onClick = onAttach
            )
            ToolButton(
                icon = Icons.Outlined.PlayArrow,
                label = "+ Frida",
                hint = "запуск",
                active = false,
                loading = isInjecting,
                enabled = !isInjecting,
                onClick = onWrap
            )
            ToolButton(
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
}

@Composable
private fun ToolButton(
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
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Column(
        modifier = Modifier
            .clip(RoundedCornerShape(10.dp))
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (loading) {
            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = Accent)
        } else {
            Icon(icon, contentDescription = label, tint = tint, modifier = Modifier.size(18.dp))
        }
        Text(label, fontSize = 11.sp, fontWeight = FontWeight.Medium, color = tint)
        Text(hint, fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
fun EventRow(event: CaptureEvent, onClick: () -> Unit) {
    val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(event.timestamp))
    val color = categoryColor(event.category)
    val preview = event.responseDetails ?: event.requestDetails ?: event.action
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.16f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(categoryIcon(event.category), null, tint = color, modifier = Modifier.size(16.dp))
        }
        Spacer(Modifier.width(10.dp))
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
                Text(time, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                text = preview,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    sourceIcon(event.source),
                    null,
                    modifier = Modifier.size(11.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.width(3.dp))
                Text(sourceLabel(event.source), fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                event.identifierName?.let {
                    Text("  ·  $it", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = Accent)
                }
            }
        }
    }
}

@Composable
fun EventDetailSheet(
    event: CaptureEvent,
    probeResult: ProbeResult?,
    isProbing: Boolean,
    onProbe: () -> Unit
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
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(color.copy(alpha = 0.18f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(categoryIcon(event.category), null, tint = color, modifier = Modifier.size(18.dp))
            }
            Spacer(Modifier.width(10.dp))
            Column {
                Text(event.action, style = MaterialTheme.typography.titleMedium)
                Text(categoryFullLabel(event.category), style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(12.dp))
        DetailRow("Источник", sourceLabel(event.source), sourceIcon(event.source))
        DetailRow("Время", timeFormat.format(Date(event.timestamp)))
        event.identifierName?.let { id ->
            DetailRow("ID", id)
            IdentifierCatalog.findById(id)?.let { def ->
                def.api?.let { DetailRow("API", it) }
                def.systemProperty?.let { DetailRow("prop", it) }
                DetailRow("Группа", def.group.label)
            }
        }
        event.permission?.let { DetailRow("Право", it, Icons.Outlined.Bolt) }
        event.processId?.let { DetailRow("PID", it.toString()) }

        event.requestDetails?.let {
            Section("Запрос", it)
        }
        event.responseDetails?.let {
            Section("Ответ", it, Accent.copy(alpha = 0.12f))
        }

        Button(
            onClick = onProbe,
            enabled = !isProbing,
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(vertical = 8.dp)
        ) {
            if (isProbing) {
                CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
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
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                colors = CardDefaults.cardColors(containerColor = Accent.copy(alpha = 0.12f))
            ) {
                Text(
                    probe.valueAsRoot,
                    modifier = Modifier.padding(10.dp),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp
                )
            }
            probe.valueInTargetContext?.let {
                Text("В приложении", fontWeight = FontWeight.Medium, fontSize = 12.sp)
                Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            }
            Text(probe.note, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 6.dp))
        }

        event.rawData?.let { Section("Raw", it) }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun Section(title: String, body: String, bg: Color = SurfaceLift) {
    Spacer(Modifier.height(8.dp))
    Text(title, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = bg)
    ) {
        Text(body, modifier = Modifier.padding(10.dp), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
    }
}

@Composable
fun DetailRow(label: String, value: String, icon: ImageVector? = null) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) {
            Icon(icon, null, modifier = Modifier.size(13.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(6.dp))
        }
        Text(label, modifier = Modifier.width(72.dp), fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
