package com.deviceinfo.trafficmonitor

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.IosShare
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.StopCircle
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.export.ExportHelper
import com.deviceinfo.trafficmonitor.monitor.AccessMonitorService
import com.deviceinfo.trafficmonitor.ui.CategoryFilterRow
import com.deviceinfo.trafficmonitor.ui.EmptyMonitorHint
import com.deviceinfo.trafficmonitor.ui.EventDetailSheet
import com.deviceinfo.trafficmonitor.ui.EventRow
import com.deviceinfo.trafficmonitor.ui.IdentifierGroupFilterRow
import com.deviceinfo.trafficmonitor.ui.ToolStrip
import com.deviceinfo.trafficmonitor.ui.fridaStatusLabel
import com.deviceinfo.trafficmonitor.ui.theme.Accent
import com.deviceinfo.trafficmonitor.ui.theme.SurfaceDeep
import com.deviceinfo.trafficmonitor.ui.theme.TrafficMonitorTheme
import com.deviceinfo.trafficmonitor.viewmodel.MonitorViewModel

class MonitorActivity : ComponentActivity() {

    private val viewModel: MonitorViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val packageName = intent.getStringExtra(EXTRA_PACKAGE) ?: finish().let { return }
        val appName = intent.getStringExtra(EXTRA_APP_NAME) ?: packageName
        viewModel.init(packageName)

        setContent {
            TrafficMonitorTheme {
                MonitorScreen(
                    appName = appName,
                    viewModel = viewModel,
                    onBack = { finish() },
                    onStop = {
                        AccessMonitorService.stop(this)
                        finish()
                    },
                    onLaunchApp = { viewModel.launchTargetApp() },
                    onClear = { viewModel.clearEvents() },
                    onShareExport = { file ->
                        startActivity(
                            Intent.createChooser(
                                ExportHelper.createShareIntent(this, file, "application/json"),
                                "Поделиться"
                            )
                        )
                    }
                )
            }
        }
    }

    companion object {
        private const val EXTRA_PACKAGE = "extra_package"
        private const val EXTRA_APP_NAME = "extra_app_name"

        fun createIntent(context: Context, packageName: String, appName: String): Intent {
            return Intent(context, MonitorActivity::class.java).apply {
                putExtra(EXTRA_PACKAGE, packageName)
                putExtra(EXTRA_APP_NAME, appName)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MonitorScreen(
    appName: String,
    viewModel: MonitorViewModel,
    onBack: () -> Unit,
    onStop: () -> Unit,
    onLaunchApp: () -> Unit,
    onClear: () -> Unit,
    onShareExport: (java.io.File) -> Unit
) {
    val events by viewModel.events.collectAsState()
    val selectedCategory by viewModel.selectedCategory.collectAsState()
    val selectedIdentifierGroup by viewModel.selectedIdentifierGroup.collectAsState()
    val selectedEvent by viewModel.selectedEvent.collectAsState()
    val eventCount by viewModel.eventCount.collectAsState()
    val categoryCounts by viewModel.categoryCounts.collectAsState()
    val identifierGroupCounts by viewModel.identifierGroupCounts.collectAsState()
    val probeResult by viewModel.probeResult.collectAsState()
    val isProbing by viewModel.isProbing.collectAsState()
    val exportResult by viewModel.exportResult.collectAsState()
    val isExporting by viewModel.isExporting.collectAsState()
    val fridaStatus by viewModel.fridaStatus.collectAsState()
    val isFridaInjecting by viewModel.isFridaInjecting.collectAsState()
    val fridaMessage by viewModel.fridaMessage.collectAsState()
    val mitmActive by viewModel.mitmActive.collectAsState()
    val isMitmStarting by viewModel.isMitmStarting.collectAsState()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) { viewModel.refreshFridaStatus() }
    LaunchedEffect(fridaMessage) {
        fridaMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearFridaMessage()
        }
    }
    LaunchedEffect(exportResult) {
        exportResult?.let { result ->
            val action = snackbarHostState.showSnackbar("Сохранено ${result.eventCount}", "Открыть")
            if (action == SnackbarResult.ActionPerformed) onShareExport(result.jsonFile)
            viewModel.clearExportResult()
        }
    }

    Scaffold(
        containerColor = SurfaceDeep,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(7.dp)
                                    .clip(CircleShape)
                                    .background(Accent)
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(appName, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        Text(
                            buildString {
                                append(eventCount)
                                append(" соб.")
                                append(" · ")
                                append(fridaStatusLabel(fridaStatus))
                                if (mitmActive) append(" · MITM")
                            },
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, "Назад")
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.exportAll(appName) }, enabled = !isExporting && eventCount > 0) {
                        if (isExporting) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
                        else Icon(Icons.Outlined.IosShare, "Экспорт")
                    }
                    IconButton(onClick = onLaunchApp) { Icon(Icons.Outlined.PlayArrow, "Запуск") }
                    IconButton(onClick = onClear) { Icon(Icons.Outlined.DeleteSweep, "Очистить") }
                    IconButton(onClick = onStop) { Icon(Icons.Outlined.StopCircle, "Стоп") }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceDeep)
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            CategoryFilterRow(
                selected = selectedCategory,
                counts = categoryCounts,
                total = eventCount,
                onSelect = viewModel::setCategoryFilter
            )
            if (selectedCategory == AccessCategory.IDENTIFIER || selectedIdentifierGroup != null) {
                IdentifierGroupFilterRow(
                    selected = selectedIdentifierGroup,
                    counts = identifierGroupCounts,
                    onSelect = viewModel::setIdentifierGroupFilter
                )
            }
            ToolStrip(
                fridaStatus = fridaStatus,
                isInjecting = isFridaInjecting,
                mitmActive = mitmActive,
                isMitmStarting = isMitmStarting,
                onAttach = { viewModel.injectFridaAttach() },
                onWrap = { viewModel.injectFridaWrap() },
                onMitm = { if (mitmActive) viewModel.stopMitm() else viewModel.startMitm() }
            )
            if (events.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    EmptyMonitorHint()
                }
            } else {
                LazyColumn {
                    items(events, key = { it.id }) { event ->
                        EventRow(event) { viewModel.selectEvent(event) }
                        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                    }
                }
            }
        }
    }

    if (selectedEvent != null) {
        ModalBottomSheet(
            onDismissRequest = {
                viewModel.selectEvent(null)
                viewModel.clearProbeResult()
            },
            sheetState = sheetState,
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            EventDetailSheet(
                event = selectedEvent!!,
                probeResult = probeResult,
                isProbing = isProbing,
                onProbe = { viewModel.probeEvent(selectedEvent!!) }
            )
        }
    }
}
