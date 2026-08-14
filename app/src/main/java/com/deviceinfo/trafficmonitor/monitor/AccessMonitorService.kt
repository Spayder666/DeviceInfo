package com.deviceinfo.trafficmonitor.monitor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.deviceinfo.trafficmonitor.MainActivity
import com.deviceinfo.trafficmonitor.MonitorActivity
import com.deviceinfo.trafficmonitor.R
import com.deviceinfo.trafficmonitor.TrafficMonitorApp
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.frida.FridaMonitor
import com.deviceinfo.trafficmonitor.root.RootShell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class AccessMonitorService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var pidWatchJob: Job? = null

    private var appOpsMonitor: AppOpsMonitor? = null
    private var logcatMonitor: LogcatMonitor? = null
    private var straceMonitor: StraceMonitor? = null
    private var procMonitor: ProcMonitor? = null
    private var fridaMonitor: FridaMonitor? = null

    private var targetPackage: String = ""
    private var targetPid: Int = -1
    private var targetUid: Int = -1

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopMonitoring()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                targetPackage = intent.getStringExtra(EXTRA_PACKAGE) ?: return START_NOT_STICKY
                startForeground(NOTIFICATION_ID, buildNotification(targetPackage))
                startMonitoring()
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun startMonitoring() {
        val repository = (application as TrafficMonitorApp).repository

        serviceScope.launch {
            targetPid = waitForPid(targetPackage) ?: -1
            targetUid = RootShell.getUid(targetPackage) ?: -1

            fridaMonitor = FridaMonitor(applicationContext, targetPackage, repository, serviceScope)
                .also { it.start() }

            IdentifierSnapshot.record(targetPackage, targetPid, repository)

            if (targetPid > 0) {
                appOpsMonitor = AppOpsMonitor(targetPackage, targetUid, repository, serviceScope).also { it.start() }
                logcatMonitor = LogcatMonitor(targetPackage, targetPid, targetUid, repository, serviceScope).also { it.start() }
                straceMonitor = StraceMonitor(targetPackage, targetPid, repository, serviceScope).also { it.start() }
                procMonitor = ProcMonitor(targetPackage, targetPid, repository, serviceScope).also { it.start() }
            }

            pidWatchJob = serviceScope.launch {
                while (isActive) {
                    delay(3000)
                    val newPid = RootShell.findPid(targetPackage)
                    if (newPid != null && newPid != targetPid) {
                        targetPid = newPid
                        restartProcessMonitors(repository)
                    }
                }
            }
        }
    }

    private suspend fun waitForPid(packageName: String, attempts: Int = 20): Int? {
        repeat(attempts) {
            RootShell.findPid(packageName)?.let { return it }
            delay(500)
        }
        return null
    }

    private fun restartProcessMonitors(repository: com.deviceinfo.trafficmonitor.data.CaptureRepository) {
        logcatMonitor?.stop()
        straceMonitor?.stop()
        procMonitor?.stop()

        if (targetPid > 0) {
            logcatMonitor = LogcatMonitor(targetPackage, targetPid, targetUid, repository, serviceScope).also { it.start() }
            straceMonitor = StraceMonitor(targetPackage, targetPid, repository, serviceScope).also { it.start() }
            procMonitor = ProcMonitor(targetPackage, targetPid, repository, serviceScope).also { it.start() }
        }
    }

    private fun stopMonitoring() {
        pidWatchJob?.cancel()
        appOpsMonitor?.stop()
        logcatMonitor?.stop()
        straceMonitor?.stop()
        procMonitor?.stop()
        fridaMonitor?.stop()
        FridaInstaller.clearInjection(targetPackage)
        isRunning = false
    }

    override fun onDestroy() {
        stopMonitoring()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun buildNotification(packageName: String): Notification {
        createChannel()

        val openIntent = PendingIntent.getActivity(
            this, 0,
            MonitorActivity.createIntent(this, packageName, packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, AccessMonitorService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.monitor_notification_title, packageName))
            .setContentText(getString(R.string.monitor_notification_text))
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.stop_monitoring), stopIntent)
            .setOngoing(true)
            .build()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_desc)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    companion object {
        const val ACTION_START = "com.deviceinfo.trafficmonitor.START"
        const val ACTION_STOP = "com.deviceinfo.trafficmonitor.STOP"
        const val EXTRA_PACKAGE = "extra_package"
        const val EXTRA_APP_NAME = "extra_app_name"

        private const val CHANNEL_ID = "access_monitor"
        private const val NOTIFICATION_ID = 1001

        @Volatile
        var isRunning = false

        fun start(context: Context, packageName: String) {
            isRunning = true
            val intent = Intent(context, AccessMonitorService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PACKAGE, packageName)
            }
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, AccessMonitorService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
