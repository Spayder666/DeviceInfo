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
import com.deviceinfo.trafficmonitor.mitm.HttpsMitmController
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
    private var notifyJob: Job? = null
    private var delayedStartJob: Job? = null

    private var appOpsMonitor: AppOpsMonitor? = null
    private var logcatMonitor: LogcatMonitor? = null
    private var procMonitor: ProcMonitor? = null
    private var fridaMonitor: FridaMonitor? = null
    private var locationDumpMonitor: LocationDumpMonitor? = null
    private var systemLogcatMonitor: SystemLogcatMonitor? = null
    private var comprehensiveDumpMonitor: ComprehensiveDumpMonitor? = null
    private var extraChannelMonitor: ExtraChannelMonitor? = null
    private var extraLogcatMonitor: ExtraLogcatMonitor? = null
    private var kernelAuditMonitor: KernelAuditMonitor? = null
    private var cmdApiMonitor: CmdApiMonitor? = null
    private var inotifyDataMonitor: InotifyDataMonitor? = null
    private var perfettoMonitor: PerfettoMonitor? = null
    private var tcpdumpMonitor: TcpdumpMonitor? = null
    private var statsdMonitor: StatsdMonitor? = null
    private var ebpfMonitor: EbpfMonitor? = null
    private var gmsInternalsMonitor: GmsInternalsMonitor? = null
    private var workManagerMonitor: WorkManagerMonitor? = null
    private var halGnssMonitor: HalGnssMonitor? = null
    private var binderIpcMonitor: BinderIpcMonitor? = null
    private var unixNetdMonitor: UnixNetdMonitor? = null
    private var privacyFgsMonitor: PrivacyFgsMonitor? = null
    private var syncPushMonitor: SyncPushMonitor? = null
    private var securityKeystoreMonitor: SecurityKeystoreMonitor? = null
    private var oemIndoorMonitor: OemIndoorMonitor? = null
    private var telephonyAccessMonitor: TelephonyAccessMonitor? = null
    private var rootDetectionMonitor: RootDetectionMonitor? = null
    private var environmentAnalysisMonitor: EnvironmentAnalysisMonitor? = null
    private var networkEnvMonitor: NetworkEnvMonitor? = null
    private var decisionTracker: DecisionTracker? = null
    private var identifierAccessMonitor: IdentifierAccessMonitor? = null
    private val straceMonitors = mutableListOf<StraceMonitor>()

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
                val appName = intent.getStringExtra(EXTRA_APP_NAME) ?: targetPackage
                currentPackage = targetPackage
                currentAppName = appName
                startForeground(NOTIFICATION_ID, buildNotification(targetPackage, appName, 0))
                startMonitoring()
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun startMonitoring() {
        val repository = (application as TrafficMonitorApp).repository

        notifyJob?.cancel()
        notifyJob = serviceScope.launch {
            repository.observeCount(targetPackage).collect { count ->
                val nm = getSystemService(NotificationManager::class.java)
                nm.notify(
                    NOTIFICATION_ID,
                    buildNotification(targetPackage, currentAppName ?: targetPackage, count)
                )
            }
        }

        serviceScope.launch {
            TargetPresence.begin(targetPackage)
            targetUid = RootShell.getUid(targetPackage) ?: -1
            val pids = RootShell.findAllPids(targetPackage)
            targetPid = pids.firstOrNull() ?: -1
            TargetPresence.setAlive(pids.isNotEmpty())

            identifierAccessMonitor = IdentifierAccessMonitor(
                targetPackage, targetUid, repository, serviceScope
            ).also { it.start() }

            fridaMonitor = FridaMonitor(applicationContext, targetPackage, repository, serviceScope)
                .also { it.start() }

            appOpsMonitor = AppOpsMonitor(targetPackage, targetUid, repository, serviceScope).also { it.start() }
            locationDumpMonitor = LocationDumpMonitor(targetPackage, repository, serviceScope).also { it.start() }
            telephonyAccessMonitor = TelephonyAccessMonitor(targetPackage, targetUid, repository, serviceScope).also { it.start() }

            if (targetUid > 0 || targetPid > 0) {
                logcatMonitor = LogcatMonitor(targetPackage, targetPid, targetUid, repository, serviceScope).also { it.start() }
            }
            if (targetPid > 0) {
                procMonitor = ProcMonitor(targetPackage, targetPid, targetUid, repository, serviceScope).also { it.start() }
            }

            delayedStartJob = serviceScope.launch {
                repeat(30) {
                    delay(400)
                    if (!isActive) return@launch
                    if (TargetPresence.isAliveNow()) {
                        delay(2500)
                        if (isActive && TargetPresence.isAliveNow()) {
                            startHeavyMonitors(repository)
                        }
                        return@launch
                    }
                }
            }

            pidWatchJob = serviceScope.launch {
                while (isActive) {
                    val live = RootShell.findAllPids(targetPackage)
                    val alive = live.isNotEmpty()
                    TargetPresence.setAlive(alive)
                    val newPid = live.firstOrNull()
                    if (alive && newPid != null && (targetPid <= 0 || targetPid !in live)) {
                        val restarted = targetPid > 0
                        targetPid = newPid
                        if (restarted) {
                            appOpsMonitor?.resetForNewProcess()
                            locationDumpMonitor?.resetForNewProcess()
                            telephonyAccessMonitor?.resetForNewProcess()
                        }
                        restartProcessMonitors(repository)
                    } else if (!alive && targetPid > 0) {
                        targetPid = -1
                        stopProcessMonitors()
                    }
                    delay(1500)
                }
            }
        }
    }

    private fun startHeavyMonitors(repository: com.deviceinfo.trafficmonitor.data.CaptureRepository) {
        // dumpsys / events-buffer / maps / statsd не пишем как «цель спросила».
        if (FridaInstaller.status != FridaInstaller.FridaStatus.INJECTED) {
            startStraceForPids(repository)
        }
    }

    private fun restartProcessMonitors(repository: com.deviceinfo.trafficmonitor.data.CaptureRepository) {
        procMonitor?.stop()

        if (logcatMonitor == null && (targetUid > 0 || targetPid > 0)) {
            logcatMonitor = LogcatMonitor(targetPackage, targetPid, targetUid, repository, serviceScope).also { it.start() }
        }
        if (FridaInstaller.status != FridaInstaller.FridaStatus.INJECTED) {
            startStraceForPids(repository)
        }
        if (targetPid > 0) {
            procMonitor = ProcMonitor(targetPackage, targetPid, targetUid, repository, serviceScope).also { it.start() }
        }
    }

    private fun stopProcessMonitors() {
        procMonitor?.stop()
        procMonitor = null
        straceMonitors.forEach { it.stop() }
        straceMonitors.clear()
    }

    private fun startStraceForPids(repository: com.deviceinfo.trafficmonitor.data.CaptureRepository) {
        val pids = RootShell.findAllPids(targetPackage).ifEmpty {
            listOfNotNull(targetPid.takeIf { it > 0 })
        }.distinct().take(6)
        val already = straceMonitors.map { it.pid }.toSet()
        for (pid in pids) {
            if (pid in already) continue
            val monitor = StraceMonitor(targetPackage, pid, repository, serviceScope)
            monitor.start()
            straceMonitors += monitor
        }
    }

    private fun stopMonitoring() {
        TargetPresence.end()
        pidWatchJob?.cancel()
        notifyJob?.cancel()
        delayedStartJob?.cancel()
        appOpsMonitor?.stop()
        logcatMonitor?.stop()
        straceMonitors.forEach { it.stop() }
        straceMonitors.clear()
        identifierAccessMonitor?.stop()
        procMonitor?.stop()
        fridaMonitor?.stop()
        locationDumpMonitor?.stop()
        systemLogcatMonitor?.stop()
        comprehensiveDumpMonitor?.stop()
        extraChannelMonitor?.stop()
        extraLogcatMonitor?.stop()
        kernelAuditMonitor?.stop()
        cmdApiMonitor?.stop()
        inotifyDataMonitor?.stop()
        perfettoMonitor?.stop()
        tcpdumpMonitor?.stop()
        statsdMonitor?.stop()
        ebpfMonitor?.stop()
        gmsInternalsMonitor?.stop()
        workManagerMonitor?.stop()
        halGnssMonitor?.stop()
        binderIpcMonitor?.stop()
        unixNetdMonitor?.stop()
        privacyFgsMonitor?.stop()
        syncPushMonitor?.stop()
        securityKeystoreMonitor?.stop()
        oemIndoorMonitor?.stop()
        telephonyAccessMonitor?.stop()
        rootDetectionMonitor?.stop()
        environmentAnalysisMonitor?.stop()
        networkEnvMonitor?.stop()
        decisionTracker?.stop()
        HttpsMitmController.stop()
        FridaInstaller.clearInjection(targetPackage)
        isRunning = false
        currentPackage = null
        currentAppName = null
    }

    override fun onDestroy() {
        stopMonitoring()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun buildNotification(packageName: String, appName: String, eventCount: Int): Notification {
        createChannel()

        val openIntent = PendingIntent.getActivity(
            this, 0,
            MonitorActivity.createIntent(this, packageName, appName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, AccessMonitorService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.monitor_notification_title, appName))
            .setContentText(
                if (eventCount > 0) {
                    getString(R.string.monitor_notification_text_count, eventCount)
                } else {
                    getString(R.string.monitor_notification_text)
                }
            )
            .setNumber(eventCount)
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

        @Volatile
        var currentPackage: String? = null

        @Volatile
        var currentAppName: String? = null

        fun start(context: Context, packageName: String, appName: String = packageName) {
            isRunning = true
            currentPackage = packageName
            currentAppName = appName
            val intent = Intent(context, AccessMonitorService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PACKAGE, packageName)
                putExtra(EXTRA_APP_NAME, appName)
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
