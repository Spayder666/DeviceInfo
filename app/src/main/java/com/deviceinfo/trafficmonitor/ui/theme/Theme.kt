package com.deviceinfo.trafficmonitor.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

val Accent = Color(0xFF3DDC97)
val AccentDim = Color(0xFF1B4332)
val Danger = Color(0xFFFF6B6B)
val SurfaceDeep = Color(0xFF0D1117)
val SurfaceCard = Color(0xFF161B22)
val SurfaceLift = Color(0xFF21262D)
val TextMuted = Color(0xFF8B949E)

private val DarkColors = darkColorScheme(
    primary = Accent,
    onPrimary = Color(0xFF003821),
    primaryContainer = AccentDim,
    onPrimaryContainer = Accent,
    secondary = Color(0xFF58A6FF),
    onSecondary = Color(0xFF0D1117),
    background = SurfaceDeep,
    onBackground = Color(0xFFE6EDF3),
    surface = SurfaceCard,
    onSurface = Color(0xFFE6EDF3),
    surfaceVariant = SurfaceLift,
    onSurfaceVariant = TextMuted,
    outline = Color(0xFF30363D),
    error = Danger,
    onError = Color.White
)

private val CompactTypography = Typography(
    titleLarge = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 18.sp, lineHeight = 22.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 15.sp, lineHeight = 20.sp),
    titleSmall = TextStyle(fontWeight = FontWeight.Medium, fontSize = 13.sp, lineHeight = 16.sp),
    bodyLarge = TextStyle(fontSize = 14.sp, lineHeight = 18.sp),
    bodyMedium = TextStyle(fontSize = 13.sp, lineHeight = 16.sp),
    bodySmall = TextStyle(fontSize = 11.sp, lineHeight = 14.sp, color = TextMuted),
    labelLarge = TextStyle(fontWeight = FontWeight.Medium, fontSize = 12.sp),
    labelMedium = TextStyle(fontWeight = FontWeight.Medium, fontSize = 11.sp),
    labelSmall = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 10.sp, color = TextMuted)
)

@Composable
fun TrafficMonitorTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColors,
        typography = CompactTypography,
        content = content
    )
}
