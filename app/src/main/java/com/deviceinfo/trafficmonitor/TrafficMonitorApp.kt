package com.deviceinfo.trafficmonitor

import android.app.Application
import com.deviceinfo.trafficmonitor.data.AppDatabase
import com.deviceinfo.trafficmonitor.data.CaptureRepository

class TrafficMonitorApp : Application() {
    lateinit var repository: CaptureRepository
        private set

    override fun onCreate() {
        super.onCreate()
        val database = AppDatabase.getInstance(this)
        repository = CaptureRepository(database.captureEventDao())
    }
}
