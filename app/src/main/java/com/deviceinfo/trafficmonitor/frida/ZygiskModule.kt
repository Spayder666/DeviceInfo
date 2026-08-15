package com.deviceinfo.trafficmonitor.frida

import android.content.Context
import android.os.Build
import com.deviceinfo.trafficmonitor.root.RootShell
import java.io.File

/**
 * Magisk/Zygisk module that dlopen's Frida gadget in the target after specialize.
 * ptrace (frida-inject) is dead on many Magisk+Android 13 devices; this does not use it.
 */
object ZygiskModule {
    const val MODULE_DIR = "/data/adb/modules/access_monitor"
    const val TARGET_PATH = "$MODULE_DIR/target"
    const val MODULE_GADGET = "$MODULE_DIR/libfrida-gadget.so"
    const val MODULE_HOOKS = "$MODULE_DIR/hooks.js"
    const val MODULE_PROP = "$MODULE_DIR/module.prop"

    fun hasMagiskTree(): Boolean {
        val out = RootShell.execAndRead(
            "if [ -d /data/adb/modules ] || [ -d /data/adb/magisk ] || [ -d /data/adb/ksu ]; " +
                "then echo ok; fi"
        )
        return out.contains("ok")
    }

    fun isZygiskEnabled(): Boolean {
        val sql = RootShell.execAndRead(
            "magisk --sqlite \"SELECT value FROM settings WHERE key='zygisk'\" 2>/dev/null"
        )
        if (sql.contains("1")) return true
        val next = RootShell.execAndRead(
            "if [ -d /data/adb/modules/zygisksu ] || [ -d /data/adb/modules/zygisk_next ] || " +
                "[ -d /data/adb/modules/zygisk-next ]; then echo next; fi"
        )
        if (next.contains("next")) return true
        val cfg = RootShell.execAndRead(
            "grep -E 'zygisk *= *true|zygisk *= *1' /data/adb/magisk/.magisk/config 2>/dev/null; " +
                "getprop persist.sys.zygisk; getprop persist.magisk.zygisk"
        )
        if (cfg.contains("true") || cfg.contains("1")) return true
        val maps = RootShell.execAndRead(
            "for p in \$(pidof zygote64 zygote 2>/dev/null); do " +
                "grep -l zygisk /proc/\$p/maps 2>/dev/null && echo mapped; done"
        )
        return maps.contains("mapped")
    }

    fun isOnDenyList(packageName: String): Boolean {
        val list = RootShell.execAndRead("magisk --denylist ls 2>/dev/null")
        return list.lineSequence().any { line ->
            line.trim() == packageName || line.trim().startsWith("$packageName|") ||
                line.trim().startsWith("$packageName ")
        }
    }

    fun zygiskLogPath(packageName: String): String =
        "/data/user/0/$packageName/cache/access_monitor_zygisk.log"

    fun readLog(packageName: String): String =
        RootShell.execAndRead("cat ${zygiskLogPath(packageName)} 2>/dev/null").trim()

    fun needsReboot(): Boolean {
        val so = moduleSoPath()
        val out = RootShell.execAndRead(
            "SO=$so; " +
                "B=\$(awk '/btime/{print \$2}' /proc/stat); " +
                "M=\$(stat -c %Y \"\$SO\" 2>/dev/null || echo 9999999999); " +
                "echo \"\$M \$B\""
        ).trim()
        val parts = out.split("\\s+".toRegex())
        val mtime = parts.getOrNull(0)?.toLongOrNull() ?: return true
        val btime = parts.getOrNull(1)?.toLongOrNull() ?: return true
        return mtime > btime
    }

    fun install(context: Context): Boolean {
        return try {
            val copied = mutableListOf<String>()
            for (abi in listOf("arm64-v8a", "armeabi-v7a")) {
                val localSo = File(context.filesDir, "zygisk-$abi.so")
                try {
                    context.assets.open("zygisk/$abi.so").use { input ->
                        localSo.outputStream().use { output -> input.copyTo(output) }
                    }
                } catch (_: Exception) {
                    continue
                }
                val dest = "$MODULE_DIR/zygisk/$abi.so"
                // Do not touch mtime if the binary is unchanged — otherwise +Frida
                // after reboot would look like a new module and ask to reboot again.
                RootShell.execAndRead(
                    "mkdir -p $MODULE_DIR/zygisk && " +
                        "NEW=\$(sha256sum ${localSo.absolutePath} | awk '{print \$1}'); " +
                        "OLD=\$(sha256sum $dest 2>/dev/null | awk '{print \$1}'); " +
                        "if [ \"\$NEW\" != \"\$OLD\" ]; then cp ${localSo.absolutePath} $dest; fi && " +
                        "chmod 755 $dest"
                )
                copied += dest
            }
            if (copied.isEmpty()) {
                FridaInstaller.lastError = "В APK нет zygisk/*.so"
                return false
            }
            val prop = """
                id=access_monitor
                name=Access Monitor
                version=v1.0.61
                versionCode=61
                author=AccessMonitor
                description=Loads Frida gadget into the monitored app
            """.trimIndent()
            val localProp = File(context.filesDir, "access_monitor_module.prop")
            localProp.writeText(prop)
            val primary = "$MODULE_DIR/zygisk/${resolveAbiFolder()}.so"
            val out = RootShell.execAndRead(
                "cp ${localProp.absolutePath} $MODULE_PROP && " +
                    "cp ${FridaInstaller.GADGET_PATH} $MODULE_GADGET && " +
                    "chmod 755 $MODULE_GADGET && chmod 644 $MODULE_PROP && " +
                    "touch $MODULE_DIR/skip_mount && " +
                    "rm -f $MODULE_DIR/disable && " +
                    "chcon -R u:object_r:system_file:s0 $MODULE_DIR 2>/dev/null; " +
                    "test -s $primary && test -s $MODULE_GADGET && echo ok"
            )
            out.trim().endsWith("ok")
        } catch (e: Exception) {
            FridaInstaller.lastError = "Модуль Zygisk: ${e.message}"
            false
        }
    }

    fun writePayload(packageName: String) {
        val uid = RootShell.getUid(packageName)
        val hookInApp = "/data/user/0/$packageName/cache/access_monitor_hooks.js"
        val cfgInApp = "/data/user/0/$packageName/cache/libfrida-gadget.config.so"
        val cfg = """{"interaction":{"type":"script","path":"$hookInApp"}}"""
        val localCfg = File.createTempFile("am_zg", ".json")
        localCfg.writeText(cfg)
        val chown = if (uid != null) {
            "chown $uid:$uid $hookInApp $cfgInApp ${zygiskLogPath(packageName)} 2>/dev/null"
        } else {
            "true"
        }
        RootShell.execAndRead(
            "mkdir -p /data/user/0/$packageName/cache && " +
                "printf '%s\\n' ${RootShell.shellQuote(packageName)} > $TARGET_PATH && " +
                "cp ${FridaInstaller.HOOKS_PATH} $MODULE_HOOKS && " +
                "cp ${FridaInstaller.HOOKS_PATH} $hookInApp && " +
                "cp ${localCfg.absolutePath} $cfgInApp && " +
                "chmod 644 $TARGET_PATH $MODULE_HOOKS $hookInApp $cfgInApp && " +
                "rm -f ${zygiskLogPath(packageName)} && " +
                chown
        )
        localCfg.delete()
    }

    fun clearTarget() {
        RootShell.execAndRead("rm -f $TARGET_PATH")
    }

    private fun moduleSoPath(): String = "$MODULE_DIR/zygisk/${resolveAbiFolder()}.so"

    private fun resolveAbiFolder(): String {
        val primary = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        return when {
            primary.contains("arm64") -> "arm64-v8a"
            primary.contains("armeabi") || primary == "arm" -> "armeabi-v7a"
            else -> "arm64-v8a"
        }
    }
}
