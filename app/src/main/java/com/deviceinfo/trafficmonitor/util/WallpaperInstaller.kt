package com.deviceinfo.trafficmonitor.util

import android.app.WallpaperManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.graphics.Typeface
import kotlin.math.max

/**
 * Обычное приложение не может сменить обои в момент установки APK
 * (процесс ещё в stopped). Ставим при первом запуске, один раз.
 */
object WallpaperInstaller {
    private const val PREFS = "access_monitor_session"
    private const val KEY_APPLIED = "wallpaper_applied"

    fun applyOnFirstLaunch(context: Context) {
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getBoolean(KEY_APPLIED, false)) return
        runCatching {
            val wm = WallpaperManager.getInstance(context)
            val dm = context.resources.displayMetrics
            val width = max(wm.desiredMinimumWidth, dm.widthPixels).coerceAtLeast(1080)
            val height = max(wm.desiredMinimumHeight, dm.heightPixels).coerceAtLeast(1920)
            val bitmap = render(width, height)
            wm.setBitmap(bitmap, null, true, WallpaperManager.FLAG_SYSTEM)
            runCatching { wm.setBitmap(bitmap, null, true, WallpaperManager.FLAG_LOCK) }
            prefs.edit().putBoolean(KEY_APPLIED, true).apply()
        }
    }

    private fun render(width: Int, height: Int): Bitmap {
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        val cx = width / 2f
        val cy = height * 0.42f

        canvas.drawRect(
            0f,
            0f,
            width.toFloat(),
            height.toFloat(),
            Paint().apply {
                shader = LinearGradient(
                    0f,
                    0f,
                    0f,
                    height.toFloat(),
                    intArrayOf(0xFF0D1117.toInt(), 0xFF0B1A14.toInt(), 0xFF0D1117.toInt()),
                    floatArrayOf(0f, 0.45f, 1f),
                    Shader.TileMode.CLAMP
                )
            }
        )

        canvas.drawCircle(
            cx,
            cy,
            width * 0.55f,
            Paint(Paint.ANTI_ALIAS_FLAG).apply {
                shader = RadialGradient(
                    cx,
                    cy,
                    width * 0.55f,
                    intArrayOf(0x333DDC97, 0x000D1117),
                    floatArrayOf(0f, 1f),
                    Shader.TileMode.CLAMP
                )
            }
        )

        val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            color = 0x663DDC97
            strokeWidth = width * 0.008f
        }
        val radii = floatArrayOf(0.16f, 0.24f, 0.33f, 0.42f)
        for (r in radii) {
            canvas.drawCircle(cx, cy, width * r, ring)
        }

        canvas.drawCircle(
            cx,
            cy,
            width * 0.028f,
            Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF3DDC97.toInt() }
        )

        val sweep = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0x553DDC97
            strokeWidth = width * 0.004f
        }
        canvas.drawLine(cx - width * 0.42f, cy, cx + width * 0.42f, cy, sweep)

        val title = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFFE6EDF3.toInt()
            textAlign = Paint.Align.CENTER
            textSize = width * 0.062f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
        }
        canvas.drawText("Access Monitor", cx, height * 0.72f, title)

        val subtitle = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = 0xFF8B949E.toInt()
            textAlign = Paint.Align.CENTER
            textSize = width * 0.032f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
        }
        canvas.drawText("что приложение спросило", cx, height * 0.76f, subtitle)
        return bitmap
    }
}
