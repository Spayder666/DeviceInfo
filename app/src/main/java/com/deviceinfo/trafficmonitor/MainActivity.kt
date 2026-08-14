package com.deviceinfo.trafficmonitor

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.deviceinfo.trafficmonitor.model.InstalledApp
import com.deviceinfo.trafficmonitor.monitor.AccessMonitorService
import com.deviceinfo.trafficmonitor.ui.theme.Accent
import com.deviceinfo.trafficmonitor.ui.theme.Danger
import com.deviceinfo.trafficmonitor.ui.theme.SurfaceDeep
import com.deviceinfo.trafficmonitor.ui.theme.SurfaceLift
import com.deviceinfo.trafficmonitor.ui.theme.TextMuted
import com.deviceinfo.trafficmonitor.ui.theme.TrafficMonitorTheme
import com.deviceinfo.trafficmonitor.util.AppListLoader
import com.deviceinfo.trafficmonitor.util.RecentApp
import com.deviceinfo.trafficmonitor.viewmodel.MainViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            TrafficMonitorTheme {
                MainScreen(
                    viewModel = viewModel,
                    onAppSelected = { packageName, appName ->
                        AccessMonitorService.start(this, packageName, appName)
                        startActivity(MonitorActivity.createIntent(this, packageName, appName))
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.checkRoot()
        viewModel.refreshRecents()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: MainViewModel, onAppSelected: (String, String) -> Unit) {
    val apps by viewModel.filteredApps.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    val isRootAvailable by viewModel.isRootAvailable.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val showSystem by viewModel.showSystem.collectAsState()
    val recents by viewModel.recents.collectAsState()
    val activePackage by viewModel.activePackage.collectAsState()
    val context = LocalContext.current
    val versionName = remember {
        runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }
            .getOrNull()
            .orEmpty()
    }

    Scaffold(
        containerColor = SurfaceDeep,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(CircleShape)
                                .background(Accent.copy(alpha = 0.16f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Outlined.Radar, null, tint = Accent, modifier = Modifier.size(16.dp))
                        }
                        Spacer(Modifier.width(8.dp))
                        Column {
                            Text("Access Monitor", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                            Text("${apps.size} приложений", fontSize = 11.sp, color = TextMuted)
                        }
                    }
                },
                actions = {
                    if (versionName.isNotBlank()) {
                        Text(
                            text = "v$versionName",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            color = TextMuted,
                            modifier = Modifier.padding(end = 12.dp)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceDeep)
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            RootChip(isRootAvailable)
            OutlinedTextField(
                value = searchQuery,
                onValueChange = viewModel::setSearchQuery,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 6.dp)
                    .height(48.dp),
                placeholder = { Text("Поиск приложения", fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Outlined.Search, null, modifier = Modifier.size(18.dp), tint = TextMuted) },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { viewModel.setSearchQuery("") }, modifier = Modifier.size(28.dp)) {
                            Icon(Icons.Outlined.Close, "Очистить", modifier = Modifier.size(16.dp), tint = TextMuted)
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Accent,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline,
                    focusedContainerColor = SurfaceLift,
                    unfocusedContainerColor = SurfaceLift
                )
            )
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                ScopeChip("Пользовательские", !showSystem) { if (showSystem) viewModel.toggleSystemApps() }
                ScopeChip("Системные", showSystem) { if (!showSystem) viewModel.toggleSystemApps() }
            }
            if (isLoading) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Accent, strokeWidth = 2.dp)
                }
            } else if (apps.isEmpty() && recents.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Ничего не найдено", color = TextMuted, fontSize = 13.sp)
                }
            } else {
                LazyColumn(contentPadding = PaddingValues(bottom = 16.dp)) {
                    if (recents.isNotEmpty() && searchQuery.isBlank()) {
                        item {
                            Row(
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Outlined.History, null, tint = TextMuted, modifier = Modifier.size(14.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Недавние", fontSize = 11.sp, color = TextMuted, fontWeight = FontWeight.Medium)
                            }
                        }
                        item {
                            Row(
                                modifier = Modifier
                                    .horizontalScroll(rememberScrollState())
                                    .padding(horizontal = 12.dp, vertical = 2.dp),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                recents.forEach { recent ->
                                    RecentCard(recent, activePackage == recent.packageName) {
                                        onAppSelected(recent.packageName, recent.appName)
                                    }
                                }
                            }
                        }
                        item { Spacer(Modifier.height(6.dp)) }
                    }
                    items(apps, key = { it.packageName }) { app ->
                        AppRow(app, isRootAvailable, activePackage == app.packageName) {
                            onAppSelected(app.packageName, app.appName)
                        }
                        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.28f))
                    }
                }
            }
        }
    }
}

@Composable
private fun ScopeChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        label,
        fontSize = 11.sp,
        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
        color = if (selected) Accent else TextMuted,
        modifier = Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(if (selected) Accent.copy(alpha = 0.14f) else SurfaceLift)
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 5.dp)
    )
}

@Composable
private fun RecentCard(recent: RecentApp, live: Boolean, onClick: () -> Unit) {
    val context = LocalContext.current
    val icon = AppListLoader.getAppIcon(context, recent.packageName)
    Column(
        modifier = Modifier
            .width(88.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(SurfaceLift)
            .clickable(onClick = onClick)
            .padding(8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        icon?.let {
            Image(
                bitmap = it.toBitmap(36, 36).asImageBitmap(),
                contentDescription = null,
                modifier = Modifier.size(36.dp).clip(RoundedCornerShape(8.dp))
            )
        } ?: Box(Modifier.size(36.dp).clip(RoundedCornerShape(8.dp)).background(SurfaceDeep))
        Spacer(Modifier.height(6.dp))
        Text(recent.appName, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(
            if (live) "идёт" else "${recent.eventCount} соб.",
            fontSize = 9.sp,
            color = if (live) Accent else TextMuted
        )
    }
}

@Composable
private fun RootChip(ok: Boolean) {
    val color = if (ok) Accent else Danger
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            if (ok) Icons.Outlined.Security else Icons.Outlined.WarningAmber,
            null,
            tint = color,
            modifier = Modifier.size(15.dp)
        )
        Spacer(Modifier.width(8.dp))
        Text(
            if (ok) "Root · GPS, камера, SIM, HTTPS" else "Нужен root (su)",
            fontSize = 12.sp,
            color = color,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun AppRow(app: InstalledApp, enabled: Boolean, live: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        app.icon?.let { drawable ->
            Image(
                bitmap = drawable.toBitmap(36, 36).asImageBitmap(),
                contentDescription = null,
                modifier = Modifier.size(36.dp).clip(RoundedCornerShape(8.dp))
            )
        } ?: Box(Modifier.size(36.dp).clip(RoundedCornerShape(8.dp)).background(SurfaceLift))
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(app.appName, fontWeight = FontWeight.Medium, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (live) {
                    Spacer(Modifier.width(6.dp))
                    Text("идёт", fontSize = 10.sp, color = Accent, fontWeight = FontWeight.SemiBold)
                }
            }
            Text(app.packageName, fontSize = 11.sp, color = TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Icon(Icons.Outlined.ChevronRight, null, tint = TextMuted, modifier = Modifier.size(18.dp))
    }
}
