package com.deviceinfo.trafficmonitor.frida

import android.content.Context
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** Frida-мониторинг через встроенный frida-gadget (wrap.+LD_PRELOAD). */
class FridaMonitor(
    private val context: Context,
    private val packageName: String,
    private val repository: CaptureRepository,
    private val scope: CoroutineScope
) {
    private var poller: FridaEventPoller? = null

    fun start() {
        scope.launch(Dispatchers.IO) {
            if (!FridaInstaller.ensureReady(context)) return@launch

            FridaInstaller.prepareHooksForPackage(packageName, context)
            FridaInstaller.clearEvents()

            poller = FridaEventPoller(packageName, repository, scope).also {
                it.resetOffset()
                it.start()
            }

            FridaInstaller.injectViaWrap(packageName)
        }
    }

    fun stop() {
        poller?.stop()
        FridaInstaller.clearInjection(packageName)
    }
}
