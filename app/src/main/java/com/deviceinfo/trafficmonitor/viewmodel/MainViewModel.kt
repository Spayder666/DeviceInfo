package com.deviceinfo.trafficmonitor.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.deviceinfo.trafficmonitor.TrafficMonitorApp
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.mitm.HttpsMitmController
import com.deviceinfo.trafficmonitor.model.InstalledApp
import com.deviceinfo.trafficmonitor.monitor.AccessMonitorService
import com.deviceinfo.trafficmonitor.probe.IdentifierProbe
import com.deviceinfo.trafficmonitor.root.RootShell
import com.deviceinfo.trafficmonitor.ui.DisplayEvent
import com.deviceinfo.trafficmonitor.ui.SessionStats
import com.deviceinfo.trafficmonitor.ui.buildSessionStats
import com.deviceinfo.trafficmonitor.ui.collapseRepeats
import com.deviceinfo.trafficmonitor.ui.eventMatchesQuery
import com.deviceinfo.trafficmonitor.util.AppListLoader
import com.deviceinfo.trafficmonitor.util.RecentApp
import com.deviceinfo.trafficmonitor.util.SessionPrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
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

    private val _showSystem = MutableStateFlow(false)
    val showSystem: StateFlow<Boolean> = _showSystem.asStateFlow()

    private val _recents = MutableStateFlow<List<RecentApp>>(emptyList())
    val recents: StateFlow<List<RecentApp>> = _recents.asStateFlow()

    private val _activePackage = MutableStateFlow<String?>(null)
    val activePackage: StateFlow<String?> = _activePackage.asStateFlow()

    val filteredApps: StateFlow<List<InstalledApp>> = combine(_apps, _searchQuery, _showSystem) { apps, query, system ->
        apps.filter { app ->
            (system || !app.isSystem) &&
                (query.isBlank() ||
                    app.appName.contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true))
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        checkRoot()
        loadApps()
        refreshRecents()
    }

    fun toggleSystemApps() {
        _showSystem.value = !_showSystem.value
    }

    fun refreshRecents() {
        _recents.value = SessionPrefs.recents(getApplication())
        _activePackage.value = AccessMonitorService.currentPackage
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
    private val _selectedSource = MutableStateFlow<EventSource?>(null)
    private val _searchQuery = MutableStateFlow("")
    private val _dedupEnabled = MutableStateFlow(true)
    private val _paused = MutableStateFlow(false)
    private val _frozenEvents = MutableStateFlow<List<DisplayEvent>>(emptyList())
    private val _frozenRawCount = MutableStateFlow(0)
    private val _selectedEvent = MutableStateFlow<CaptureEvent?>(null)
    private val _allEvents = MutableStateFlow<List<CaptureEvent>>(emptyList())
    private val _targetRunning = MutableStateFlow(false)
    private val _showStats = MutableStateFlow(false)
    private val _showSearch = MutableStateFlow(false)

    val packageName: StateFlow<String> = _packageName.asStateFlow()
    val selectedCategory: StateFlow<AccessCategory?> = _selectedCategory.asStateFlow()
    val selectedIdentifierGroup: StateFlow<String?> = _selectedIdentifierGroup.asStateFlow()
    val selectedSource: StateFlow<EventSource?> = _selectedSource.asStateFlow()
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()
    val dedupEnabled: StateFlow<Boolean> = _dedupEnabled.asStateFlow()
    val paused: StateFlow<Boolean> = _paused.asStateFlow()
    val selectedEvent: StateFlow<CaptureEvent?> = _selectedEvent.asStateFlow()
    val targetRunning: StateFlow<Boolean> = _targetRunning.asStateFlow()
    val showStats: StateFlow<Boolean> = _showStats.asStateFlow()
    val showSearch: StateFlow<Boolean> = _showSearch.asStateFlow()

    private val filteredRaw: StateFlow<List<CaptureEvent>> = combine(
        _allEvents,
        _selectedCategory,
        _selectedIdentifierGroup,
        _selectedSource,
        _searchQuery
    ) { all, cat, idGroup, source, query ->
        all.filter { event ->
            (cat == null || event.category == cat) &&
                (idGroup == null || event.identifierGroup == idGroup) &&
                (source == null || event.source == source) &&
                eventMatchesQuery(event, query)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val liveDisplay: StateFlow<List<DisplayEvent>> = combine(filteredRaw, _dedupEnabled) { list, dedup ->
        if (dedup) collapseRepeats(list) else list.map { DisplayEvent(it) }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val events: StateFlow<List<DisplayEvent>> = combine(liveDisplay, _paused, _frozenEvents) { live, paused, frozen ->
        if (paused) frozen else live
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val missedWhilePaused: StateFlow<Int> = combine(_allEvents, _paused, _frozenRawCount) { all, paused, frozen ->
        if (paused) (all.size - frozen).coerceAtLeast(0) else 0
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    val sessionStats: StateFlow<SessionStats> = _allEvents
        .map { buildSessionStats(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), SessionStats())

    val sourceCounts: StateFlow<Map<EventSource, Int>> = _allEvents
        .map { list -> list.groupingBy { it.source }.eachCount() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyMap())

    val eventCount: StateFlow<Int> = _allEvents
        .map { it.size }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    val categoryCounts: StateFlow<Map<AccessCategory, Int>> = _allEvents
        .map { list -> list.groupingBy { it.category }.eachCount() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyMap())

    val identifierGroupCounts: StateFlow<Map<String, Int>> = _allEvents
        .map { list -> list.mapNotNull { it.identifierGroup }.groupingBy { it }.eachCount() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyMap())

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
        viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                _targetRunning.value = RootShell.isAppRunning(_packageName.value)
                delay(3000)
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

    fun setSourceFilter(source: EventSource?) {
        _selectedSource.value = if (_selectedSource.value == source) null else source
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun toggleSearch() {
        _showSearch.value = !_showSearch.value
        if (!_showSearch.value) _searchQuery.value = ""
    }

    fun toggleDedup() {
        _dedupEnabled.value = !_dedupEnabled.value
    }

    fun togglePause() {
        if (!_paused.value) {
            _frozenEvents.value = liveDisplay.value
            _frozenRawCount.value = _allEvents.value.size
            _paused.value = true
        } else {
            _paused.value = false
        }
    }

    fun toggleStats() {
        _showStats.value = !_showStats.value
    }

    fun selectEvent(event: CaptureEvent?) {
        _selectedEvent.value = event
        _probeResult.value = null
        if (event != null) {
            probeEvent(event)
        }
    }

    fun selectAdjacent(delta: Int) {
        val list = events.value
        val currentId = _selectedEvent.value?.id ?: return
        val index = list.indexOfFirst { it.event.id == currentId }
        val next = list.getOrNull(index + delta) ?: return
        selectEvent(next.event)
    }

    fun clearEvents() {
        viewModelScope.launch {
            repository.clear(_packageName.value)
        }
    }

    fun launchTargetApp() {
        viewModelScope.launch(Dispatchers.IO) {
            RootShell.launchApp(_packageName.value)
            _targetRunning.value = true
        }
    }

    fun forceStopTarget() {
        viewModelScope.launch(Dispatchers.IO) {
            RootShell.forceStop(_packageName.value)
            _targetRunning.value = false
            _fridaMessage.value = "Приложение остановлено"
        }
    }

    fun rememberSession(appName: String) {
        SessionPrefs.remember(getApplication(), _packageName.value, appName, _allEvents.value.size)
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
            doExport(appName, repository.getAllEvents(_packageName.value))
        }
    }

    fun exportVisible(appName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            doExport(appName, filteredRaw.value)
        }
    }

    private fun doExport(appName: String, events: List<CaptureEvent>) {
        _isExporting.value = true
        _exportResult.value = com.deviceinfo.trafficmonitor.export.ExportHelper.exportEvents(
            context = getApplication(),
            packageName = _packageName.value,
            appName = appName,
            events = events
        )
        _isExporting.value = false
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

    private val _mitmActive = MutableStateFlow(HttpsMitmController.active)
    val mitmActive = _mitmActive.asStateFlow()

    private val _isMitmStarting = MutableStateFlow(false)
    val isMitmStarting = _isMitmStarting.asStateFlow()

    fun startMitm() {
        viewModelScope.launch(Dispatchers.IO) {
            _isMitmStarting.value = true
            try {
                val uid = RootShell.getUid(_packageName.value) ?: -1
                val ok = HttpsMitmController.start(
                    getApplication(),
                    _packageName.value,
                    uid,
                    repository
                )
                _mitmActive.value = HttpsMitmController.active
                _fridaStatus.value = FridaInstaller.status
                _fridaMessage.value = if (ok) {
                    "MITM HTTPS: plaintext + CA. При pinning смотрите события Frida."
                } else {
                    HttpsMitmController.lastError ?: "MITM не запустился"
                }
            } catch (t: Throwable) {
                _fridaMessage.value = "MITM: ${t.javaClass.simpleName}: ${t.message}"
            } finally {
                _isMitmStarting.value = false
            }
        }
    }

    fun stopMitm() {
        viewModelScope.launch(Dispatchers.IO) {
            HttpsMitmController.stop()
            _mitmActive.value = false
            _fridaMessage.value = "MITM HTTPS выключен"
        }
    }
}
