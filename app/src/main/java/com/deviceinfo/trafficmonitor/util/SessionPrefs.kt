package com.deviceinfo.trafficmonitor.util

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

data class RecentApp(
    val packageName: String,
    val appName: String,
    val lastUsed: Long,
    val eventCount: Int
)

object SessionPrefs {
    private const val PREFS = "access_monitor_session"
    private const val KEY_RECENTS = "recents"
    private const val MAX = 8

    fun recents(context: Context): List<RecentApp> {
        val raw = prefs(context).getString(KEY_RECENTS, "[]") ?: "[]"
        return runCatching {
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    add(
                        RecentApp(
                            packageName = o.getString("pkg"),
                            appName = o.optString("name", o.getString("pkg")),
                            lastUsed = o.optLong("ts", 0L),
                            eventCount = o.optInt("count", 0)
                        )
                    )
                }
            }
        }.getOrElse { emptyList() }
    }

    fun remember(context: Context, packageName: String, appName: String, eventCount: Int) {
        val now = System.currentTimeMillis()
        val next = recents(context)
            .filter { it.packageName != packageName }
            .toMutableList()
        next.add(0, RecentApp(packageName, appName, now, eventCount))
        val arr = JSONArray()
        next.take(MAX).forEach { app ->
            arr.put(
                JSONObject()
                    .put("pkg", app.packageName)
                    .put("name", app.appName)
                    .put("ts", app.lastUsed)
                    .put("count", app.eventCount)
            )
        }
        prefs(context).edit().putString(KEY_RECENTS, arr.toString()).apply()
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
