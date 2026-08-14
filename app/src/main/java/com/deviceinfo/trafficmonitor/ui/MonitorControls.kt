package com.deviceinfo.trafficmonitor.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.ui.theme.Accent
import com.deviceinfo.trafficmonitor.ui.theme.Danger
import com.deviceinfo.trafficmonitor.ui.theme.SurfaceLift
import com.deviceinfo.trafficmonitor.ui.theme.TextMuted

@Composable
fun EventSearchBar(query: String, onQuery: (String) -> Unit, onClose: () -> Unit) {
    OutlinedTextField(
        value = query,
        onValueChange = onQuery,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 2.dp)
            .height(48.dp),
        placeholder = { Text("Поиск: IMEI, host, GPS…", fontSize = 13.sp) },
        leadingIcon = { Icon(Icons.Outlined.Search, null, modifier = Modifier.size(18.dp), tint = TextMuted) },
        trailingIcon = {
            Icon(
                Icons.Outlined.Close,
                "Закрыть",
                modifier = Modifier
                    .size(18.dp)
                    .clickable(onClick = onClose),
                tint = TextMuted
            )
        },
        singleLine = true,
        shape = RoundedCornerShape(10.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Accent,
            unfocusedBorderColor = MaterialTheme.colorScheme.outline,
            focusedContainerColor = SurfaceLift,
            unfocusedContainerColor = SurfaceLift
        )
    )
}

@Composable
fun SourceFilterRow(
    selected: EventSource?,
    counts: Map<EventSource, Int>,
    onSelect: (EventSource?) -> Unit
) {
    val visible = EventSource.entries.filter { it == selected || (counts[it] ?: 0) > 0 }
    if (visible.isEmpty()) return
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        SourcePill("Все", null, selected == null, counts.values.sum(), Accent, onSelect)
        visible.forEach { source ->
            SourcePill(
                label = sourceLabel(source),
                source = source,
                selected = selected == source,
                count = counts[source] ?: 0,
                color = Accent,
                onSelect = onSelect,
                icon = { Icon(sourceIcon(source), null, modifier = Modifier.size(12.dp), tint = if (selected == source) Accent else TextMuted) }
            )
        }
    }
}

@Composable
private fun SourcePill(
    label: String,
    source: EventSource?,
    selected: Boolean,
    count: Int,
    color: androidx.compose.ui.graphics.Color,
    onSelect: (EventSource?) -> Unit,
    icon: (@Composable () -> Unit)? = null
) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(if (selected) color.copy(alpha = 0.18f) else SurfaceLift)
            .clickable { onSelect(source) }
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        icon?.invoke()
        if (icon != null) Spacer(Modifier.width(4.dp))
        Text(label, fontSize = 10.sp, color = if (selected) MaterialTheme.colorScheme.onSurface else TextMuted)
        if (count > 0) {
            Spacer(Modifier.width(4.dp))
            Text(count.toString(), fontSize = 9.sp, color = color, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
fun StatsSheet(stats: SessionStats) {
    val maxCat = (stats.categoryCounts.values.maxOrNull() ?: 1).coerceAtLeast(1)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Text("Сессия", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatCard("События", stats.total.toString(), Modifier.weight(1f))
            StatCard("Риск", stats.riskTotal.toString(), Modifier.weight(1f), danger = stats.riskTotal > 0)
            StatCard("ID", stats.uniqueIdentifiers.size.toString(), Modifier.weight(1f))
        }
        if (stats.categoryCounts.isNotEmpty()) {
            Spacer(Modifier.height(14.dp))
            Text("Категории", fontWeight = FontWeight.Medium, fontSize = 12.sp, color = TextMuted)
            stats.categoryCounts.entries.sortedByDescending { it.value }.forEach { (cat, count) ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(categoryIcon(cat), null, modifier = Modifier.size(14.dp), tint = categoryColor(cat))
                    Spacer(Modifier.width(6.dp))
                    Text(categoryLabel(cat), modifier = Modifier.width(72.dp), fontSize = 11.sp)
                    LinearProgressIndicator(
                        progress = { count.toFloat() / maxCat },
                        modifier = Modifier.weight(1f).height(6.dp).clip(RoundedCornerShape(3.dp)),
                        color = categoryColor(cat),
                        trackColor = SurfaceLift
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(count.toString(), fontSize = 11.sp, fontWeight = FontWeight.Medium)
                }
            }
        }
        if (stats.uniqueIdentifiers.isNotEmpty()) {
            Spacer(Modifier.height(14.dp))
            Text("Идентификаторы", fontWeight = FontWeight.Medium, fontSize = 12.sp, color = TextMuted)
            Text(
                stats.uniqueIdentifiers.joinToString("  ·  "),
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                color = Accent
            )
        }
        if (stats.topHosts.isNotEmpty()) {
            Spacer(Modifier.height(14.dp))
            Text("Хосты", fontWeight = FontWeight.Medium, fontSize = 12.sp, color = TextMuted)
            stats.topHosts.forEach {
                Text(it, fontSize = 11.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(vertical = 1.dp))
            }
        }
        if (stats.topActions.isNotEmpty()) {
            Spacer(Modifier.height(14.dp))
            Text("Частые действия", fontWeight = FontWeight.Medium, fontSize = 12.sp, color = TextMuted)
            stats.topActions.forEach { (action, count) ->
                Text("$count  $action", fontSize = 11.sp, maxLines = 1, modifier = Modifier.padding(vertical = 1.dp))
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier, danger: Boolean = false) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(if (danger) Danger.copy(alpha = 0.12f) else SurfaceLift)
            .padding(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (danger) {
                Icon(Icons.Outlined.WarningAmber, null, tint = Danger, modifier = Modifier.size(12.dp))
                Spacer(Modifier.width(4.dp))
            }
            Text(label, fontSize = 10.sp, color = TextMuted)
        }
        Text(value, fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = if (danger) Danger else Accent)
    }
}
