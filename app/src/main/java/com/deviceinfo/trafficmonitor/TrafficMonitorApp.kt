package com.deviceinfo.trafficmonitor

import android.app.Application
import com.deviceinfo.trafficmonitor.data.AppDatabase
import com.deviceinfo.trafficmonitor.data.CaptureRepository
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.util.WallpaperInstaller
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class TrafficMonitorApp : Application() {

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    lateinit var repository: CaptureRepository
        private set

    override fun onCreate() {
        super.onCreate()
        val database = AppDatabase.getInstance(this)
        repository = CaptureRepository(database.captureEventDao())

        appScope.launch {
            WallpaperInstaller.applyOnFirstLaunch(applicationContext)
            FridaInstaller.prepareOnAppStart(applicationContext)
        }
    }
}
