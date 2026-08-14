package com.deviceinfo.trafficmonitor.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.deviceinfo.trafficmonitor.model.InstalledApp

object AppListLoader {

    fun loadInstalledApps(context: Context): List<InstalledApp> {
        val pm = context.packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 || isUpdatedSystemApp(it) }
            .filter { it.packageName != context.packageName }
            .map { info ->
                InstalledApp(
                    packageName = info.packageName,
                    appName = pm.getApplicationLabel(info).toString(),
                    icon = runCatching { pm.getApplicationIcon(info) }.getOrNull()
                )
            }
            .sortedBy { it.appName.lowercase() }
        return apps
    }

    private fun isUpdatedSystemApp(info: ApplicationInfo): Boolean {
        return info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }

    fun getAppName(context: Context, packageName: String): String {
        return try {
            val pm = context.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
        } catch (_: Exception) {
            packageName
        }
    }
}
