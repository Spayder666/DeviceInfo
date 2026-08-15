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
    private const val KEY_PINS = "pins"
    private const val KEY_SHOW_SYSTEM = "show_system"
    private const val KEY_DEDUP = "dedup"
    private const val KEY_LAST_CAT = "last_cat"
    private const val KEY_LAST_SRC = "last_src"
    private const val KEY_LAST_IDG = "last_idg"
    private const val KEY_LIST_MODE = "list_mode"
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

    fun pins(context: Context): Set<String> {
        val raw = prefs(context).getString(KEY_PINS, "[]") ?: "[]"
        return runCatching {
            val arr = JSONArray(raw)
            buildSet {
                for (i in 0 until arr.length()) add(arr.getString(i))
            }
        }.getOrElse { emptySet() }
    }

    fun togglePin(context: Context, key: String): Boolean {
        val next = pins(context).toMutableSet()
        val nowPinned = if (next.contains(key)) {
            next.remove(key)
            false
        } else {
            next.add(key)
            true
        }
        val arr = JSONArray()
        next.forEach { arr.put(it) }
        prefs(context).edit().putString(KEY_PINS, arr.toString()).apply()
        return nowPinned
    }

    fun showSystem(context: Context): Boolean = prefs(context).getBoolean(KEY_SHOW_SYSTEM, false)

    fun setShowSystem(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_SHOW_SYSTEM, value).apply()
    }

    fun dedup(context: Context): Boolean = prefs(context).getBoolean(KEY_DEDUP, true)

    fun setDedup(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_DEDUP, value).apply()
    }

    fun lastCategory(context: Context): String? = prefs(context).getString(KEY_LAST_CAT, null)

    fun lastSource(context: Context): String? = prefs(context).getString(KEY_LAST_SRC, null)

    fun lastIdentifierGroup(context: Context): String? = prefs(context).getString(KEY_LAST_IDG, null)

    fun listMode(context: Context): String = prefs(context).getString(KEY_LIST_MODE, "DIGEST") ?: "DIGEST"

    fun setListMode(context: Context, mode: String) {
        prefs(context).edit().putString(KEY_LIST_MODE, mode).apply()
    }

    fun saveFilters(context: Context, category: String?, source: String?, identifierGroup: String?) {
        prefs(context).edit()
            .putString(KEY_LAST_CAT, category)
            .putString(KEY_LAST_SRC, source)
            .putString(KEY_LAST_IDG, identifierGroup)
            .apply()
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
