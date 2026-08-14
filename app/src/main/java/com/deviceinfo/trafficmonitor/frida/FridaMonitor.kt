package com.deviceinfo.trafficmonitor.frida

import android.content.Context
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** Frida-мониторинг: poller событий + ручная инъекция (без auto wrap — иначе приложения зависают). */
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
        }
    }

    /** Ручная инъекция: attach к PID или перезапуск + inject. */
    fun requestInject(restartApp: Boolean) {
        scope.launch(Dispatchers.IO) {
            if (!FridaInstaller.ensureReady(context)) return@launch
            FridaInstaller.prepareHooksForPackage(packageName, context)
            FridaInstaller.injectManual(context, packageName, restartApp)
        }
    }

    fun stop() {
        poller?.stop()
        FridaInstaller.clearInjection(packageName)
    }
}
