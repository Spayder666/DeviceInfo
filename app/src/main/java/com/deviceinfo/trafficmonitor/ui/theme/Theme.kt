package com.deviceinfo.trafficmonitor.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Primary = Color(0xFF1565C0)
private val Secondary = Color(0xFF0277BD)

private val LightColors = lightColorScheme(
    primary = Primary,
    secondary = Secondary
)

@Composable
fun TrafficMonitorTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = LightColors,
        content = content
    )
}
