package com.deviceinfo.trafficmonitor.monitor

internal fun dumpMentionsTarget(dump: String, packageName: String, uid: Int = 0): Boolean {
    if (dump.contains(packageName)) return true
    if (uid > 0) {
        if (dump.contains("uid=$uid") || dump.contains("callingUid=$uid")) return true
        val appId = uid % 100_000
        if (dump.contains("u0a$appId")) return true
    }
    return false
}

internal fun isUselessDump(dump: String): Boolean {
    val t = dump.trim()
    if (t.isEmpty()) return true
    if (t.contains("Unknown command", ignoreCase = true)) return true
    if (t.contains("Can't find service", ignoreCase = true)) return true
    if (t.contains("Permission Denial", ignoreCase = true)) return true
    if (t.contains("IllegalArgumentException")) return true
    if (t.contains("mRttRequesterInfo: {}") && t.contains("mRttRequestQueue: []")) return true
    if (t.contains("mOverlays: size=0") && t.contains("VirtualDisplayAdapter")) return true
    return false
}

internal fun isRecentAccessStamp(accessTime: String): Boolean {
    if (Regex("""\+\d+ms""").containsMatchIn(accessTime)) return true
    val seconds = Regex("""\+(\d+)s""").find(accessTime)?.groupValues?.get(1)?.toIntOrNull()
    if (seconds != null) return seconds <= 180
    if (Regex("""\+\d+h""").containsMatchIn(accessTime)) return false
    val minutes = Regex("""\+(\d+)m""").find(accessTime)?.groupValues?.get(1)?.toIntOrNull()
    return minutes != null && minutes <= 3
}
