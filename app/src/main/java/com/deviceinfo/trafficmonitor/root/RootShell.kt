package com.deviceinfo.trafficmonitor.root

import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

object RootShell {

    fun isRootAvailable(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor(5, TimeUnit.SECONDS)
            output.contains("uid=0")
        } catch (_: Exception) {
            false
        }
    }

    fun exec(command: String): Process {
        return Runtime.getRuntime().exec(arrayOf("su", "-c", command))
    }

    fun execAndRead(command: String, timeoutSec: Long = 10): String {
        val process = exec(command)
        val output = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor(timeoutSec, TimeUnit.SECONDS)
        return output
    }

    suspend fun execStreaming(command: String, onLine: (String) -> Unit) = coroutineScope {
        val process = exec(command)
        val readerJob = launch(Dispatchers.IO) {
            try {
                BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        onLine(line!!)
                    }
                }
            } catch (_: Exception) {
            }
        }
        try {
            readerJob.join()
        } finally {
            runCatching { process.destroyForcibly() }
            readerJob.cancel()
        }
    }

    fun findPid(packageName: String): Int? = findAllPids(packageName).firstOrNull()

    fun findAllPids(packageName: String): List<Int> {
        val pids = linkedSetOf<Int>()
        execAndRead("pidof $packageName").trim()
            .split("\\s+".toRegex())
            .mapNotNull { it.toIntOrNull() }
            .forEach { pids.add(it) }
        if (pids.isNotEmpty()) return pids.toList()

        val ps = execAndRead("ps -A -o PID,NAME 2>/dev/null")
        for (line in ps.lines()) {
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size != 2) continue
            val pid = parts[0].toIntOrNull() ?: continue
            if (isAppProcessName(parts[1], packageName)) pids.add(pid)
        }
        return pids.toList()
    }

    fun isAppProcessName(name: String, packageName: String): Boolean {
        if (name.isBlank()) return false
        if (name == packageName || name.startsWith("$packageName:")) return true
        // Linux comm is 15 bytes; long package names truncate.
        return name.length == 15 && packageName.startsWith(name) && !name.contains(':')
    }

    fun pidBelongsToPackage(pid: Int, packageName: String): Boolean {
        if (pid <= 0) return false
        val comm = execAndRead("cat /proc/$pid/comm 2>/dev/null").trim()
        if (isAppProcessName(comm, packageName)) return true
        val cmd0 = execAndRead("tr '\\0' '\\n' < /proc/$pid/cmdline 2>/dev/null | head -n1").trim()
        return isAppProcessName(cmd0, packageName)
    }

    fun getUid(packageName: String): Int? {
        val output = execAndRead("dumpsys package $packageName | grep userId=")
        val match = Regex("userId=(\\d+)").find(output)
        return match?.groupValues?.get(1)?.toIntOrNull()
    }

    fun forceStop(packageName: String): Boolean {
        return try {
            execAndRead("am force-stop $packageName", timeoutSec = 8)
            true
        } catch (_: Exception) {
            false
        }
    }

    fun isAppRunning(packageName: String): Boolean = findPid(packageName) != null

    fun launchApp(packageName: String): Boolean {
        return try {
            val component = execAndRead(
                "cmd package resolve-activity --brief $packageName 2>/dev/null | tail -n 1"
            ).trim()
            if (component.contains("/")) {
                execAndRead("am start -n $component", timeoutSec = 8)
                return true
            }
            val process = exec("monkey -p $packageName -c android.intent.category.LAUNCHER 1")
            process.waitFor(5, TimeUnit.SECONDS)
            true
        } catch (_: Exception) {
            false
        }
    }

    /** Запускает команду в фоне (не убивается при выходе su). */
    fun execDetached(command: String) {
        execAndRead(
            "setsid sh -c ${shellQuote(command)} </dev/null >/dev/null 2>&1 &",
            timeoutSec = 5
        )
    }

    /**
     * Держит сессию su открытой. Magisk часто убивает дерево, если `su -c 'cmd &'` сразу выходит —
     * frida-inject тогда пишет только Aborted.
     */
    fun execKeepAlive(command: String): Process {
        val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
        Thread {
            runCatching { process.inputStream.copyTo(java.io.OutputStream.nullOutputStream()) }
        }.apply { isDaemon = true; start() }
        Thread {
            runCatching { process.errorStream.copyTo(java.io.OutputStream.nullOutputStream()) }
        }.apply { isDaemon = true; start() }
        return process
    }

    fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\\''") + "'"
    }

    fun resolveStracePath(): String? = resolveBinary("strace")

    fun resolveBinary(vararg names: String): String? {
        val prefixes = listOf("/system/bin/", "/system/xbin/", "/vendor/bin/", "/data/local/tmp/")
        for (name in names) {
            for (prefix in prefixes) {
                val path = "$prefix$name"
                if (execAndRead("test -x $path && echo ok").trim() == "ok") return path
            }
            val which = execAndRead("command -v $name 2>/dev/null").trim()
            if (which.startsWith("/") && !which.contains("not found")) return which
        }
        return null
    }
}
