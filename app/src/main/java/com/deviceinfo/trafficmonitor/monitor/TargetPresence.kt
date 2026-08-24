package com.deviceinfo.trafficmonitor.monitor

import android.os.SystemClock
import com.deviceinfo.trafficmonitor.data.EventSource

/**
 * Событие = запрос живого процесса цели.
 * Пока приложения нет (force-stop / не запущено) — в лог ничего не пишем:
 * dumpsys/logcat всё равно упоминают пакет часами после остановки.
 */
object TargetPresence {
    @Volatile
    var packageName: String = ""
        private set

    @Volatile
    private var lastAliveElapsed = 0L

    private const val GRACE_MS = 3_000L

    fun begin(pkg: String) {
        packageName = pkg
        lastAliveElapsed = 0L
    }

    fun setAlive(alive: Boolean) {
        if (alive) lastAliveElapsed = SystemClock.elapsedRealtime()
    }

    fun isAliveNow(): Boolean {
        val last = lastAliveElapsed
        if (last == 0L) return false
        return SystemClock.elapsedRealtime() - last <= GRACE_MS
    }

    fun shouldAccept(pkg: String, source: EventSource? = null): Boolean {
        val current = packageName
        if (current.isEmpty() || pkg != current) return false
        if (isAliveNow()) return true
        // Frida пишет только из живого процесса; pid-watch 1.5с не должен выкидывать эти строки.
        return source == EventSource.FRIDA
    }

    fun end() {
        packageName = ""
        lastAliveElapsed = 0L
    }
}
