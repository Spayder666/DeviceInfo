package com.deviceinfo.trafficmonitor.root

import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

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

    fun execStreaming(command: String, onLine: (String) -> Unit) {
        val process = exec(command)
        BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                onLine(line!!)
            }
        }
    }

    fun findPid(packageName: String): Int? = findAllPids(packageName).firstOrNull()

    fun findAllPids(packageName: String): List<Int> {
        val pids = linkedSetOf<Int>()
        execAndRead("pidof $packageName").trim()
            .split("\\s+".toRegex())
            .mapNotNull { it.toIntOrNull() }
            .forEach { pids.add(it) }

        val ps = execAndRead("ps -A -o PID,NAME 2>/dev/null")
        for (line in ps.lines()) {
            val trimmed = line.trim()
            if (!trimmed.contains(packageName)) continue
            trimmed.split("\\s+".toRegex()).firstOrNull()?.toIntOrNull()?.let { pids.add(it) }
        }
        return pids.toList()
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
