package com.deviceinfo.trafficmonitor

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.BarChart
import androidx.compose.material.icons.outlined.FilterList
import androidx.compose.material.icons.outlined.KeyboardArrowUp
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.PauseCircle
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.PlayCircle
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.StopCircle
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
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
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.ui.DisplayEvent
import com.deviceinfo.trafficmonitor.ui.HintBanner
import com.deviceinfo.trafficmonitor.ui.eventAsText
import com.deviceinfo.trafficmonitor.ui.formatDuration
import com.deviceinfo.trafficmonitor.ui.pinKey
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import com.deviceinfo.trafficmonitor.export.ExportHelper
import com.deviceinfo.trafficmonitor.monitor.AccessMonitorService
import com.deviceinfo.trafficmonitor.ui.CategoryFilterRow
import com.deviceinfo.trafficmonitor.ui.ClassSectionHeader
import com.deviceinfo.trafficmonitor.ui.DigestRow
import com.deviceinfo.trafficmonitor.ui.EmptyMonitorHint
import com.deviceinfo.trafficmonitor.ui.EventDetailSheet
import com.deviceinfo.trafficmonitor.ui.EventRow
import com.deviceinfo.trafficmonitor.ui.EventSearchBar
import com.deviceinfo.trafficmonitor.ui.IdentifierGroupFilterRow
import com.deviceinfo.trafficmonitor.ui.ListMode
import com.deviceinfo.trafficmonitor.ui.ListModeRow
import com.deviceinfo.trafficmonitor.ui.SourceFilterRow
import com.deviceinfo.trafficmonitor.ui.StatsSheet
import com.deviceinfo.trafficmonitor.ui.ToolStrip
import com.deviceinfo.trafficmonitor.ui.fridaStatusLabel
import com.deviceinfo.trafficmonitor.ui.groupDisplayEvents
import com.deviceinfo.trafficmonitor.ui.theme.Accent
import com.deviceinfo.trafficmonitor.ui.theme.SurfaceDeep
import com.deviceinfo.trafficmonitor.ui.theme.TextMuted
import com.deviceinfo.trafficmonitor.ui.theme.TrafficMonitorTheme
import com.deviceinfo.trafficmonitor.viewmodel.MonitorViewModel

class MonitorActivity : ComponentActivity() {

    private val viewModel: MonitorViewModel by viewModels()
    private var appName: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val packageName = intent.getStringExtra(EXTRA_PACKAGE) ?: finish().let { return }
        appName = intent.getStringExtra(EXTRA_APP_NAME) ?: packageName
        viewModel.init(packageName)

        setContent {
            TrafficMonitorTheme {
                MonitorScreen(
                    appName = appName,
                    viewModel = viewModel,
                    onBack = { finish() },
                    onStop = {
                        viewModel.rememberSession(appName)
                        AccessMonitorService.stop(this)
                        finish()
                    },
                    onLaunchApp = { viewModel.launchTargetApp() },
                    onShareExport = { file, mime ->
                        startActivity(
                            Intent.createChooser(
                                ExportHelper.createShareIntent(this, file, mime),
                                "Поделиться"
                            )
                        )
                    },
                    onShareText = { text ->
                        startActivity(
                            Intent.createChooser(
                                Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_TEXT, text)
                                },
                                "Поделиться"
                            )
                        )
                    }
                )
            }
        }
    }

    override fun onDestroy() {
        if (isFinishing) {
            viewModel.rememberSession(appName)
        }
        super.onDestroy()
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

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun MonitorScreen(
    appName: String,
    viewModel: MonitorViewModel,
    onBack: () -> Unit,
    onStop: () -> Unit,
    onLaunchApp: () -> Unit,
    onShareExport: (java.io.File, String) -> Unit,
    onShareText: (String) -> Unit
) {
    val events by viewModel.events.collectAsState()
    val selectedCategory by viewModel.selectedCategory.collectAsState()
    val selectedIdentifierGroup by viewModel.selectedIdentifierGroup.collectAsState()
    val listMode by viewModel.listMode.collectAsState()
    val askedSections by viewModel.askedSections.collectAsState()
    val selectedSource by viewModel.selectedSource.collectAsState()
    val selectedEvent by viewModel.selectedEvent.collectAsState()
    val eventCount by viewModel.eventCount.collectAsState()
    val categoryCounts by viewModel.categoryCounts.collectAsState()
    val identifierGroupCounts by viewModel.identifierGroupCounts.collectAsState()
    val sourceCounts by viewModel.sourceCounts.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    val showSearch by viewModel.showSearch.collectAsState()
    val paused by viewModel.paused.collectAsState()
    val missedWhilePaused by viewModel.missedWhilePaused.collectAsState()
    val dedupEnabled by viewModel.dedupEnabled.collectAsState()
    val showStats by viewModel.showStats.collectAsState()
    val sessionStats by viewModel.sessionStats.collectAsState()
    val targetRunning by viewModel.targetRunning.collectAsState()
    val probeResult by viewModel.probeResult.collectAsState()
    val isProbing by viewModel.isProbing.collectAsState()
    val exportResult by viewModel.exportResult.collectAsState()
    val isExporting by viewModel.isExporting.collectAsState()
    val fridaStatus by viewModel.fridaStatus.collectAsState()
    val isFridaInjecting by viewModel.isFridaInjecting.collectAsState()
    val fridaMessage by viewModel.fridaMessage.collectAsState()
    val mitmActive by viewModel.mitmActive.collectAsState()
    val isMitmStarting by viewModel.isMitmStarting.collectAsState()
    val pinnedOnly by viewModel.pinnedOnly.collectAsState()
    val pinnedKeys by viewModel.pinnedKeys.collectAsState()
    val sessionStartedAt by viewModel.sessionStartedAt.collectAsState()
    val targetDied by viewModel.targetDied.collectAsState()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val statsSheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val snackbarHostState = remember { SnackbarHostState() }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    var menuOpen by remember { mutableStateOf(false) }
    var contextEvent by remember { mutableStateOf<DisplayEvent?>(null) }
    var fridaHintDismissed by remember { mutableStateOf(false) }
    var showFridaHint by remember { mutableStateOf(false) }
    var stoppedHintDismissed by remember { mutableStateOf(false) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val showJump by remember { derivedStateOf { listState.firstVisibleItemIndex > 2 } }

    LaunchedEffect(Unit) {
        viewModel.refreshFridaStatus()
        while (true) {
            delay(1000)
            now = System.currentTimeMillis()
        }
    }
    LaunchedEffect(targetRunning) {
        if (targetRunning) stoppedHintDismissed = false
    }
    LaunchedEffect(fridaStatus, sourceCounts) {
        if (fridaStatus == FridaInstaller.FridaStatus.INJECTED || (sourceCounts[EventSource.FRIDA] ?: 0) > 0) {
            showFridaHint = false
            return@LaunchedEffect
        }
        delay(8000)
        if (fridaStatus != FridaInstaller.FridaStatus.INJECTED && (sourceCounts[EventSource.FRIDA] ?: 0) == 0) {
            showFridaHint = true
        }
    }
    LaunchedEffect(fridaMessage) {
        fridaMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearFridaMessage()
        }
    }
    LaunchedEffect(exportResult) {
        exportResult?.let { result ->
            val action = snackbarHostState.showSnackbar("${result.label} · ${result.eventCount}", "Открыть")
            if (action == SnackbarResult.ActionPerformed) onShareExport(result.jsonFile, result.mime)
            viewModel.clearExportResult()
        }
    }
    LaunchedEffect(targetDied) {
        if (targetDied) {
            val action = snackbarHostState.showSnackbar("Приложение закрыто", "Запуск")
            if (action == SnackbarResult.ActionPerformed) onLaunchApp()
            viewModel.consumeTargetDied()
        }
    }

    val selectedIndex = selectedEvent?.let { ev -> events.indexOfFirst { it.event.id == ev.id } } ?: -1

    Scaffold(
        containerColor = SurfaceDeep,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            if (showJump) {
                FloatingActionButton(
                    onClick = { scope.launch { listState.animateScrollToItem(0) } },
                    containerColor = Accent,
                    contentColor = androidx.compose.ui.graphics.Color(0xFF003821),
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(Icons.Outlined.KeyboardArrowUp, "К новым")
                }
            }
        },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(7.dp)
                                    .clip(CircleShape)
                                    .background(if (targetRunning) Accent else TextMuted)
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(appName, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        Text(
                            buildString {
                                append(eventCount)
                                append(" соб.")
                                append(" · ")
                                append(formatDuration(now - sessionStartedAt))
                                if (paused) {
                                    append(" · пауза")
                                    if (missedWhilePaused > 0) append(" +$missedWhilePaused")
                                }
                                append(" · ")
                                append(fridaStatusLabel(fridaStatus))
                                if (mitmActive) append(" · MITM")
                                if (pinnedOnly) append(" · ★")
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
                    IconButton(onClick = { viewModel.toggleSearch() }) {
                        Icon(Icons.Outlined.Search, "Поиск", tint = if (showSearch) Accent else MaterialTheme.colorScheme.onSurface)
                    }
                    IconButton(onClick = { viewModel.togglePause() }) {
                        Icon(
                            if (paused) Icons.Outlined.PlayCircle else Icons.Outlined.PauseCircle,
                            if (paused) "Продолжить" else "Пауза ленты",
                            tint = if (paused) Accent else MaterialTheme.colorScheme.onSurface
                        )
                    }
                    IconButton(onClick = onLaunchApp) { Icon(Icons.Outlined.PlayArrow, "Запуск") }
                    IconButton(onClick = onStop) { Icon(Icons.Outlined.StopCircle, "Стоп") }
                    Box {
                        IconButton(onClick = { menuOpen = true }) { Icon(Icons.Outlined.MoreVert, "Ещё") }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            DropdownMenuItem(
                                text = { Text("Статистика") },
                                leadingIcon = { Icon(Icons.Outlined.BarChart, null) },
                                onClick = { menuOpen = false; viewModel.toggleStats() }
                            )
                            DropdownMenuItem(
                                text = { Text(if (dedupEnabled) "Показать повторы" else "Свернуть повторы") },
                                leadingIcon = { Icon(Icons.Outlined.FilterList, null) },
                                onClick = { menuOpen = false; viewModel.toggleDedup() }
                            )
                            DropdownMenuItem(
                                text = { Text(if (pinnedOnly) "Все события" else "Только закреплённые") },
                                leadingIcon = { Icon(Icons.Outlined.PushPin, null) },
                                onClick = { menuOpen = false; viewModel.togglePinnedOnly() }
                            )
                            DropdownMenuItem(
                                text = { Text("Экспорт JSON+CSV") },
                                enabled = !isExporting && eventCount > 0,
                                onClick = { menuOpen = false; viewModel.exportAll(appName) }
                            )
                            DropdownMenuItem(
                                text = { Text("Экспорт фильтра") },
                                enabled = !isExporting && events.isNotEmpty(),
                                onClick = { menuOpen = false; viewModel.exportVisible(appName) }
                            )
                            DropdownMenuItem(
                                text = { Text("Экспорт HAR") },
                                enabled = !isExporting && eventCount > 0,
                                onClick = { menuOpen = false; viewModel.exportHar(appName) }
                            )
                            DropdownMenuItem(
                                text = { Text("Скопировать CA") },
                                leadingIcon = { Icon(Icons.Outlined.VpnKey, null) },
                                onClick = { menuOpen = false; viewModel.copyMitmCa() }
                            )
                            DropdownMenuItem(
                                text = { Text("Поделиться CA") },
                                onClick = {
                                    menuOpen = false
                                    viewModel.shareMitmCa()?.let { onShareExport(it, "application/x-pem-file") }
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Остановить приложение") },
                                onClick = { menuOpen = false; viewModel.forceStopTarget() }
                            )
                            DropdownMenuItem(
                                text = { Text("Очистить лог") },
                                onClick = { menuOpen = false; viewModel.clearEvents() }
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceDeep)
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (showSearch) {
                EventSearchBar(
                    query = searchQuery,
                    onQuery = viewModel::setSearchQuery,
                    onClose = { viewModel.toggleSearch() }
                )
            }
            ListModeRow(
                selected = listMode,
                onSelect = viewModel::setListMode
            )
            CategoryFilterRow(
                selected = selectedCategory,
                counts = categoryCounts,
                total = eventCount,
                onSelect = viewModel::setCategoryFilter
            )
            IdentifierGroupFilterRow(
                selected = selectedIdentifierGroup,
                counts = identifierGroupCounts,
                onSelect = viewModel::setIdentifierGroupFilter
            )
            if (listMode == ListMode.TIMELINE) {
                SourceFilterRow(
                    selected = selectedSource,
                    counts = sourceCounts,
                    onSelect = viewModel::setSourceFilter
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
            if (!targetRunning && !stoppedHintDismissed) {
                HintBanner(
                    text = "Приложение остановлено. Новые события не пишутся — оно ничего не спрашивает",
                    action = "Запуск",
                    onAction = onLaunchApp,
                    onDismiss = { stoppedHintDismissed = true }
                )
            }
            if (showFridaHint && !fridaHintDismissed && fridaStatus != FridaInstaller.FridaStatus.INJECTED) {
                HintBanner(
                    text = "Модель, Android ID, IMEI появятся, когда цель их запросит. + Frida: Zygisk, один раз перезагрузка",
                    action = "Frida",
                    onAction = { viewModel.injectFridaAttach() },
                    onDismiss = { fridaHintDismissed = true }
                )
            }
            val digestEmpty = askedSections.all { it.items.isEmpty() }
            if (eventCount == 0) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    EmptyMonitorHint()
                }
            } else if (events.isEmpty() && (listMode != ListMode.DIGEST || digestEmpty)) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(if (pinnedOnly) "Нет закреплённых" else "Нет совпадений", color = TextMuted, fontSize = 13.sp)
                }
            } else if (listMode == ListMode.DIGEST) {
                if (digestEmpty) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text("Нет классифицированных запросов — откройте «Лента»", color = TextMuted, fontSize = 13.sp)
                    }
                } else {
                    LazyColumn(state = listState) {
                        askedSections.forEach { section ->
                            stickyHeader(key = "d-${section.group?.name ?: "none"}") {
                                ClassSectionHeader(section.group, section.items.size)
                            }
                            items(section.items, key = { "ask-${it.id}" }) { item ->
                                DigestRow(item) { viewModel.selectAsked(item) }
                                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                            }
                        }
                    }
                }
            } else if (listMode == ListMode.BY_CLASS) {
                val sections = groupDisplayEvents(events)
                LazyColumn(state = listState) {
                    sections.forEach { section ->
                        stickyHeader(key = "c-${section.group?.name ?: "none"}") {
                            ClassSectionHeader(section.group, section.items.size)
                        }
                        items(section.items, key = { it.event.id }) { item ->
                            EventRow(
                                item = item,
                                onClick = { viewModel.selectEvent(item.event) },
                                onLongClick = { contextEvent = item }
                            )
                            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                        }
                    }
                }
            } else {
                LazyColumn(state = listState) {
                    items(events, key = { it.event.id }) { item ->
                        EventRow(
                            item = item,
                            onClick = { viewModel.selectEvent(item.event) },
                            onLongClick = { contextEvent = item }
                        )
                        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                    }
                }
            }
        }
    }

    if (showStats) {
        ModalBottomSheet(
            onDismissRequest = { viewModel.toggleStats() },
            sheetState = statsSheetState,
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            StatsSheet(sessionStats)
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
                canPrev = selectedIndex > 0,
                canNext = selectedIndex >= 0 && selectedIndex < events.lastIndex,
                pinned = pinKey(selectedEvent!!) in pinnedKeys,
                onPrev = { viewModel.selectAdjacent(-1) },
                onNext = { viewModel.selectAdjacent(1) },
                onProbe = { viewModel.probeEvent(selectedEvent!!) },
                onPin = { viewModel.togglePin(selectedEvent!!) }
            )
        }
    }

    contextEvent?.let { item ->
        AlertDialog(
            onDismissRequest = { contextEvent = null },
            title = { Text(item.event.action, maxLines = 2, fontSize = 16.sp) },
            text = {
                Column {
                    TextButton(onClick = {
                        clipboard.setText(AnnotatedString(eventAsText(item.event)))
                        contextEvent = null
                    }) { Text("Копировать") }
                    TextButton(onClick = {
                        viewModel.togglePin(item.event)
                        contextEvent = null
                    }) { Text(if (item.pinned) "Открепить" else "Закрепить") }
                    TextButton(onClick = {
                        viewModel.filterByAction(item.event.action)
                        contextEvent = null
                    }) { Text("Только это действие") }
                    TextButton(onClick = {
                        onShareText(eventAsText(item.event))
                        contextEvent = null
                    }) { Text("Поделиться") }
                }
            },
            confirmButton = {
                TextButton(onClick = { contextEvent = null }) { Text("Закрыть") }
            }
        )
    }
}
