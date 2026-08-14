package com.deviceinfo.trafficmonitor.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.deviceinfo.trafficmonitor.TrafficMonitorApp
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.model.InstalledApp
import com.deviceinfo.trafficmonitor.probe.IdentifierProbe
import com.deviceinfo.trafficmonitor.root.RootShell
import com.deviceinfo.trafficmonitor.util.AppListLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val _apps = MutableStateFlow<List<InstalledApp>>(emptyList())
    val apps: StateFlow<List<InstalledApp>> = _apps.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _isRootAvailable = MutableStateFlow(false)
    val isRootAvailable: StateFlow<Boolean> = _isRootAvailable.asStateFlow()

    private val _isLoading = MutableStateFlow(true)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    val filteredApps: StateFlow<List<InstalledApp>> = combine(_apps, _searchQuery) { apps, query ->
        if (query.isBlank()) apps
        else apps.filter {
            it.appName.contains(query, ignoreCase = true) ||
                it.packageName.contains(query, ignoreCase = true)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        checkRoot()
        loadApps()
    }

    fun checkRoot() {
        viewModelScope.launch(Dispatchers.IO) {
            _isRootAvailable.value = RootShell.isRootAvailable()
        }
    }

    fun loadApps() {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            _apps.value = AppListLoader.loadInstalledApps(getApplication())
            _isLoading.value = false
        }
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }
}

class MonitorViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = (application as TrafficMonitorApp).repository

    private val _packageName = MutableStateFlow("")
    private val _selectedCategory = MutableStateFlow<AccessCategory?>(null)
    private val _selectedIdentifierGroup = MutableStateFlow<String?>(null)
    private val _selectedEvent = MutableStateFlow<CaptureEvent?>(null)
    private val _allEvents = MutableStateFlow<List<CaptureEvent>>(emptyList())

    val packageName: StateFlow<String> = _packageName.asStateFlow()
    val selectedCategory: StateFlow<AccessCategory?> = _selectedCategory.asStateFlow()
    val selectedIdentifierGroup: StateFlow<String?> = _selectedIdentifierGroup.asStateFlow()
    val selectedEvent: StateFlow<CaptureEvent?> = _selectedEvent.asStateFlow()

    val events: StateFlow<List<CaptureEvent>> = combine(
        _allEvents,
        _selectedCategory,
        _selectedIdentifierGroup
    ) { all, cat, idGroup ->
        var filtered = all
        if (cat != null) filtered = filtered.filter { it.category == cat }
        if (idGroup != null) filtered = filtered.filter { it.identifierGroup == idGroup }
        filtered
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val eventCount: StateFlow<Int> = _allEvents
        .map { it.size }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    private var observeJob: Job? = null

    fun init(packageName: String) {
        if (_packageName.value == packageName) return
        _packageName.value = packageName
        observeJob?.cancel()
        observeJob = viewModelScope.launch {
            repository.observeEvents(packageName).collect { list ->
                _allEvents.value = list
            }
        }
    }

    fun setCategoryFilter(category: AccessCategory?) {
        _selectedCategory.value = category
        if (category != AccessCategory.IDENTIFIER) {
            _selectedIdentifierGroup.value = null
        }
    }

    fun setIdentifierGroupFilter(group: String?) {
        _selectedIdentifierGroup.value = group
        if (group != null) {
            _selectedCategory.value = AccessCategory.IDENTIFIER
        }
    }

    fun selectEvent(event: CaptureEvent?) {
        _selectedEvent.value = event
    }

    fun clearEvents() {
        viewModelScope.launch {
            repository.clear(_packageName.value)
        }
    }

    fun launchTargetApp() {
        viewModelScope.launch(Dispatchers.IO) {
            RootShell.launchApp(_packageName.value)
        }
    }

    private val _probeResult = MutableStateFlow<com.deviceinfo.trafficmonitor.probe.ProbeResult?>(null)
    val probeResult = _probeResult.asStateFlow()

    private val _isProbing = MutableStateFlow(false)
    val isProbing = _isProbing.asStateFlow()

    fun probeEvent(event: CaptureEvent) {
        viewModelScope.launch(Dispatchers.IO) {
            _isProbing.value = true
            _probeResult.value = IdentifierProbe.probe(event)
            _isProbing.value = false
        }
    }

    fun clearProbeResult() {
        _probeResult.value = null
    }

    private val _exportResult = MutableStateFlow<com.deviceinfo.trafficmonitor.export.ExportHelper.ExportResult?>(null)
    val exportResult = _exportResult.asStateFlow()

    private val _isExporting = MutableStateFlow(false)
    val isExporting = _isExporting.asStateFlow()

    fun exportAll(appName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isExporting.value = true
            val events = repository.getAllEvents(_packageName.value)
            _exportResult.value = com.deviceinfo.trafficmonitor.export.ExportHelper.exportEvents(
                context = getApplication(),
                packageName = _packageName.value,
                appName = appName,
                events = events
            )
            _isExporting.value = false
        }
    }

    fun clearExportResult() {
        _exportResult.value = null
    }

    private val _fridaStatus = MutableStateFlow(FridaInstaller.status)
    val fridaStatus = _fridaStatus.asStateFlow()

    private val _isFridaInjecting = MutableStateFlow(false)
    val isFridaInjecting = _isFridaInjecting.asStateFlow()

    private val _fridaMessage = MutableStateFlow<String?>(null)
    val fridaMessage = _fridaMessage.asStateFlow()

    fun refreshFridaStatus() {
        _fridaStatus.value = FridaInstaller.status
    }

    fun injectFridaAttach() {
        viewModelScope.launch(Dispatchers.IO) {
            _isFridaInjecting.value = true
            FridaInstaller.ensureReady(getApplication())
            FridaInstaller.prepareHooksForPackage(_packageName.value, getApplication())
            val ok = FridaInstaller.injectManual(getApplication(), _packageName.value, restartApp = false)
            _fridaStatus.value = FridaInstaller.status
            _fridaMessage.value = if (ok) {
                "Frida подключена (без перезапуска)"
            } else {
                FridaInstaller.lastError ?: "Attach не удался"
            }
            _isFridaInjecting.value = false
        }
    }

    fun injectFridaWrap() {
        viewModelScope.launch(Dispatchers.IO) {
            _isFridaInjecting.value = true
            FridaInstaller.ensureReady(getApplication())
            FridaInstaller.prepareHooksForPackage(_packageName.value, getApplication())
            val ok = FridaInstaller.injectManual(getApplication(), _packageName.value, restartApp = true)
            _fridaStatus.value = FridaInstaller.status
            _fridaMessage.value = if (ok) {
                "Приложение запущено, Frida подключена"
            } else {
                FridaInstaller.lastError ?: "Инъекция не удалась"
            }
            _isFridaInjecting.value = false
        }
    }

    fun clearFridaMessage() {
        _fridaMessage.value = null
    }
}
