package com.deviceinfo.trafficmonitor.frida

import android.content.Context
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Frida-мониторинг: gadget через wrap.+LD_PRELOAD (root) и опционально frida CLI attach.
 */
class FridaMonitor(
    private val context: Context,
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var poller: FridaEventPoller? = null
    private var cliJob: Job? = null

    fun start() {
        scope.launch(Dispatchers.IO) {
            if (!FridaInstaller.ensureReady(context)) return@launch

            FridaInstaller.prepareHooksForPackage(packageName, context)
            FridaInstaller.clearEvents()

            poller = FridaEventPoller(packageName, repository, scope).also {
                it.resetOffset()
                it.start()
            }

            if (FridaInstaller.injectViaWrap(packageName)) {
                tryFridaCliAttach()
            }
        }
    }

    fun stop() {
        cliJob?.cancel()
        poller?.stop()
        FridaInstaller.clearInjection(packageName)
    }

    private fun tryFridaCliAttach() {
        val fridaCli = FridaInstaller.resolveFridaCli() ?: return
        val pid = RootShell.findPid(packageName) ?: return

        cliJob = scope.launch(Dispatchers.IO) {
            try {
                val cmd = "$fridaCli -p $pid -l ${FridaInstaller.HOOKS_PATH} -q 2>&1"
                RootShell.execStreaming(cmd) { _ ->
                    // optional secondary channel
                }
            } catch (_: Exception) {
                // CLI attach optional; gadget wrap is primary
            }
        }
    }
}
