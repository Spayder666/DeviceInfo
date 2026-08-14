package com.deviceinfo.trafficmonitor

import android.content.Intent
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Launch
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deviceinfo.trafficmonitor.export.ExportHelper
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.probe.ProbeResult
import com.deviceinfo.trafficmonitor.identifiers.IdentifierCatalog
import com.deviceinfo.trafficmonitor.identifiers.IdentifierGroup
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.monitor.AccessMonitorService
import com.deviceinfo.trafficmonitor.ui.categoryColor
import com.deviceinfo.trafficmonitor.ui.categoryLabel
import com.deviceinfo.trafficmonitor.ui.sourceLabel
import com.deviceinfo.trafficmonitor.ui.theme.TrafficMonitorTheme
import com.deviceinfo.trafficmonitor.viewmodel.MonitorViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
                    packageName = packageName,
                    viewModel = viewModel,
                    onBack = { finish() },
                    onStop = {
                        AccessMonitorService.stop(this)
                        finish()
                    },
                    onLaunchApp = { viewModel.launchTargetApp() },
                    onClear = { viewModel.clearEvents() },
                    onShareExport = { file ->
                        val intent = ExportHelper.createShareIntent(this, file, "application/json")
                        startActivity(Intent.createChooser(intent, "Поделиться отчётом"))
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
    packageName: String,
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
    val probeResult by viewModel.probeResult.collectAsState()
    val isProbing by viewModel.isProbing.collectAsState()
    val exportResult by viewModel.exportResult.collectAsState()
    val isExporting by viewModel.isExporting.collectAsState()
    val fridaStatus by viewModel.fridaStatus.collectAsState()
    val isFridaInjecting by viewModel.isFridaInjecting.collectAsState()
    val fridaMessage by viewModel.fridaMessage.collectAsState()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.refreshFridaStatus()
    }

    LaunchedEffect(fridaMessage) {
        fridaMessage?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            viewModel.clearFridaMessage()
        }
    }

    LaunchedEffect(exportResult) {
        exportResult?.let { result ->
            snackbarHostState.showSnackbar(
                message = "Сохранено ${result.eventCount} событий (JSON + CSV)",
                actionLabel = "Открыть"
            ).let { action ->
                if (action == SnackbarResult.ActionPerformed) {
                    onShareExport(result.jsonFile)
                }
            }
            viewModel.clearExportResult()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(appName, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        Text(
                            "Зафиксировано: $eventCount · ${fridaStatusLabel(fridaStatus)}",
                            fontSize = 11.sp,
                            color = Color.White.copy(alpha = 0.8f)
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад", tint = Color.White)
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.exportAll(appName) },
                        enabled = !isExporting && eventCount > 0
                    ) {
                        if (isExporting) {
                            CircularProgressIndicator(
                                modifier = Modifier.height(20.dp).width(20.dp),
                                strokeWidth = 2.dp,
                                color = Color.White
                            )
                        } else {
                            Icon(Icons.Default.Save, contentDescription = "Сохранить", tint = Color.White)
                        }
                    }
                    IconButton(onClick = onLaunchApp) {
                        Icon(Icons.Default.Launch, contentDescription = "Запустить", tint = Color.White)
                    }
                    IconButton(onClick = onClear) {
                        Icon(Icons.Default.Clear, contentDescription = "Очистить", tint = Color.White)
                    }
                    IconButton(onClick = onStop) {
                        Icon(Icons.Default.Stop, contentDescription = "Стоп", tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = Color.White
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            CategoryFilterRow(
                selected = selectedCategory,
                onSelect = viewModel::setCategoryFilter
            )

            if (selectedCategory == AccessCategory.IDENTIFIER || selectedIdentifierGroup != null) {
                IdentifierGroupFilterRow(
                    selected = selectedIdentifierGroup,
                    onSelect = viewModel::setIdentifierGroupFilter
                )
            }

            FridaControlRow(
                status = fridaStatus,
                isInjecting = isFridaInjecting,
                onAttach = { viewModel.injectFridaAttach() },
                onWrap = { viewModel.injectFridaWrap() }
            )

            if (events.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("Запросы пока не зафиксированы", style = MaterialTheme.typography.bodyLarge)
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Запустите приложение и выполните действия",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Для точных ответов API нажмите «Запустить + Frida»",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(events, key = { it.id }) { event ->
                        EventCard(event = event, onClick = { viewModel.selectEvent(event) })
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
            sheetState = sheetState
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

@Composable
fun CategoryFilterRow(selected: AccessCategory?, onSelect: (AccessCategory?) -> Unit) {
    val categories = listOf(
        null to "Все",
        AccessCategory.LOCATION to "GPS",
        AccessCategory.CAMERA to "Камера",
        AccessCategory.TELEPHONY to "SIM",
        AccessCategory.IDENTIFIER to "ID",
        AccessCategory.NETWORK to "API",
        AccessCategory.PERMISSION to "Права",
        AccessCategory.MICROPHONE to "Мик",
        AccessCategory.STORAGE to "Файлы",
        AccessCategory.SENSOR to "Датчики"
    )

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        categories.forEach { (cat, label) ->
            FilterChip(
                selected = selected == cat,
                onClick = { onSelect(cat) },
                label = { Text(label, fontSize = 12.sp) }
            )
        }
    }
}

@Composable
fun IdentifierGroupFilterRow(selected: String?, onSelect: (String?) -> Unit) {
    val groups = listOf(null to "Все ID") + IdentifierGroup.entries.map { it.name to it.label }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        groups.forEach { (name, label) ->
            FilterChip(
                selected = selected == name,
                onClick = { onSelect(name) },
                label = { Text(label, fontSize = 11.sp) }
            )
        }
    }
}

@Composable
fun EventCard(event: CaptureEvent, onClick: () -> Unit) {
    val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
    val color = categoryColor(event.category)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        elevation = CardDefaults.cardElevation(2.dp)
    ) {
        Row(modifier = Modifier.padding(12.dp)) {
            Box(
                modifier = Modifier
                    .width(4.dp)
                    .height(56.dp)
                    .background(color, RoundedCornerShape(2.dp))
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    AssistChip(
                        onClick = {},
                        label = { Text(categoryLabel(event.category), fontSize = 10.sp) },
                        modifier = Modifier.height(24.dp)
                    )
                    Text(
                        text = timeFormat.format(Date(event.timestamp)),
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(
                    text = event.action,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                    modifier = Modifier.padding(top = 4.dp)
                )
                event.identifierName?.let { id ->
                    Text(
                        text = id,
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.primary,
                        fontFamily = FontFamily.Monospace
                    )
                }
                event.requestDetails?.let {
                    Text(
                        text = it,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2
                    )
                }
                event.responseDetails?.let {
                    Text(
                        text = "→ $it",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 2,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
                Text(
                    text = sourceLabel(event.source),
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.outline,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }
    }
}

@Composable
fun EventDetailSheet(
    event: CaptureEvent,
    probeResult: ProbeResult?,
    isProbing: Boolean,
    onProbe: () -> Unit
) {
    val timeFormat = SimpleDateFormat("dd.MM.yyyy HH:mm:ss.SSS", Locale.getDefault())

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 8.dp)
    ) {
        Text("Детали запроса", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(16.dp))

        DetailRow("Категория", categoryLabel(event.category))
        DetailRow("Действие", event.action)
        event.identifierName?.let { id ->
            DetailRow("ID тип", id)
            IdentifierCatalog.findById(id)?.let { def ->
                def.api?.let { DetailRow("API", it) }
                def.systemProperty?.let { DetailRow("Property", it) }
                def.filePath?.let { DetailRow("File", it) }
                def.group.let { DetailRow("Группа", it.label) }
            }
        }
        DetailRow("Источник", sourceLabel(event.source))
        DetailRow("Время", timeFormat.format(Date(event.timestamp)))
        event.permission?.let { DetailRow("Разрешение", it) }
        event.processId?.let { DetailRow("PID", it.toString()) }

        HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))

        event.requestDetails?.let {
            Text("Запрос", fontWeight = FontWeight.Bold)
            Text(it, modifier = Modifier.padding(vertical = 4.dp))
        }

        event.responseDetails?.let {
            Spacer(Modifier.height(8.dp))
            Text("Ответ / результат (перехваченный)", fontWeight = FontWeight.Bold)
            Text(it, modifier = Modifier.padding(vertical = 4.dp))
        }

        Spacer(Modifier.height(12.dp))
        Button(
            onClick = onProbe,
            enabled = !isProbing,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isProbing) {
                CircularProgressIndicator(modifier = Modifier.height(18.dp).width(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text("Проверить ответ сейчас")
        }

        probeResult?.let { probe ->
            Spacer(Modifier.height(12.dp))
            Text("Ответ (значения устройства)", fontWeight = FontWeight.Bold)
            Text(
                text = probe.requestLabel,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFFE8F5E9))
            ) {
                Text(
                    text = probe.valueAsRoot,
                    modifier = Modifier.padding(12.dp),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp
                )
            }
            probe.valueInTargetContext?.let {
                Text("Перехвачено в приложении", fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                Text(it, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.padding(vertical = 4.dp))
            }
            Text(
                text = probe.note,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        Text(
            text = "Значения выше прочитаны от root. Frida (источник Frida) фиксирует точный ответ внутри приложения в момент вызова.",
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.outline,
            modifier = Modifier.padding(top = 8.dp)
        )

        event.rawData?.let {
            Spacer(Modifier.height(12.dp))
            Text("Полные данные", fontWeight = FontWeight.Bold)
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F5F5))
            ) {
                Text(
                    text = it,
                    modifier = Modifier.padding(12.dp),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp
                )
            }
        }

        Spacer(Modifier.height(32.dp))
    }
}

@Composable
fun FridaControlRow(
    status: FridaInstaller.FridaStatus,
    isInjecting: Boolean,
    onAttach: () -> Unit,
    onWrap: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Default.Science, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        Button(
            onClick = onAttach,
            enabled = !isInjecting && status != FridaInstaller.FridaStatus.INJECTED,
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
        ) {
            if (isInjecting) {
                CircularProgressIndicator(modifier = Modifier.height(14.dp).width(14.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(6.dp))
            }
            Text("Frida к запущенному", fontSize = 12.sp)
        }
        Button(
            onClick = onWrap,
            enabled = !isInjecting,
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
        ) {
            Text("Запустить + Frida", fontSize = 12.sp)
        }
        Text(
            text = fridaStatusLabel(status),
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

private fun fridaStatusLabel(status: FridaInstaller.FridaStatus): String = when (status) {
    FridaInstaller.FridaStatus.NOT_INSTALLED -> "Frida: не установлен"
    FridaInstaller.FridaStatus.EXTRACTING -> "Frida: установка из APK…"
    FridaInstaller.FridaStatus.DOWNLOADING -> "Frida: загрузка…"
    FridaInstaller.FridaStatus.READY -> "Frida: готов (ручное подключение)"
    FridaInstaller.FridaStatus.INJECTED -> "Frida: хуки активны"
    FridaInstaller.FridaStatus.ERROR -> "Frida: ошибка"
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
    ) {
        Text(
            text = "$label:",
            fontWeight = FontWeight.Medium,
            modifier = Modifier.width(120.dp),
            fontSize = 13.sp
        )
        Text(text = value, fontSize = 13.sp)
    }
}
