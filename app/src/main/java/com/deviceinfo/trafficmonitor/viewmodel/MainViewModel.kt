package com.deviceinfo.trafficmonitor.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.deviceinfo.trafficmonitor.TrafficMonitorApp
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.frida.FridaEventPoller
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.mitm.HttpsMitmController
import com.deviceinfo.trafficmonitor.model.InstalledApp
import com.deviceinfo.trafficmonitor.monitor.AccessMonitorService
import com.deviceinfo.trafficmonitor.probe.IdentifierProbe
import com.deviceinfo.trafficmonitor.root.RootShell
import com.deviceinfo.trafficmonitor.mitm.MitmCaManager
import com.deviceinfo.trafficmonitor.ui.AskedItem
import com.deviceinfo.trafficmonitor.ui.DigestSection
import com.deviceinfo.trafficmonitor.ui.DisplayEvent
import com.deviceinfo.trafficmonitor.ui.ListMode
import com.deviceinfo.trafficmonitor.ui.SessionStats
import com.deviceinfo.trafficmonitor.ui.buildAskedDigest
import com.deviceinfo.trafficmonitor.ui.buildAskedSections
import com.deviceinfo.trafficmonitor.ui.buildSessionStats
import com.deviceinfo.trafficmonitor.ui.collapseRepeats
import com.deviceinfo.trafficmonitor.ui.eventMatchesCategory
import com.deviceinfo.trafficmonitor.ui.eventMatchesQuery
import com.deviceinfo.trafficmonitor.ui.isIdentifierEvent
import com.deviceinfo.trafficmonitor.ui.pinKey
import com.deviceinfo.trafficmonitor.ui.resolveEventGroup
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

    private val _showSystem = MutableStateFlow(SessionPrefs.showSystem(application))
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
        SessionPrefs.setShowSystem(getApplication(), _showSystem.value)
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
    private val _listMode = MutableStateFlow(ListMode.DIGEST)
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
    private val _pinnedKeys = MutableStateFlow<Set<String>>(emptySet())
    private val _pinnedOnly = MutableStateFlow(false)
    private val _sessionStartedAt = MutableStateFlow(System.currentTimeMillis())
    private val _targetDied = MutableStateFlow(false)

    val packageName: StateFlow<String> = _packageName.asStateFlow()
    val selectedCategory: StateFlow<AccessCategory?> = _selectedCategory.asStateFlow()
    val selectedIdentifierGroup: StateFlow<String?> = _selectedIdentifierGroup.asStateFlow()
    val listMode: StateFlow<ListMode> = _listMode.asStateFlow()
    val selectedSource: StateFlow<EventSource?> = _selectedSource.asStateFlow()
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()
    val dedupEnabled: StateFlow<Boolean> = _dedupEnabled.asStateFlow()
    val paused: StateFlow<Boolean> = _paused.asStateFlow()
    val selectedEvent: StateFlow<CaptureEvent?> = _selectedEvent.asStateFlow()
    val targetRunning: StateFlow<Boolean> = _targetRunning.asStateFlow()
    val showStats: StateFlow<Boolean> = _showStats.asStateFlow()
    val showSearch: StateFlow<Boolean> = _showSearch.asStateFlow()
    val pinnedKeys: StateFlow<Set<String>> = _pinnedKeys.asStateFlow()
    val pinnedOnly: StateFlow<Boolean> = _pinnedOnly.asStateFlow()
    val sessionStartedAt: StateFlow<Long> = _sessionStartedAt.asStateFlow()
    val targetDied: StateFlow<Boolean> = _targetDied.asStateFlow()

    private val filteredRaw: StateFlow<List<CaptureEvent>> = combine(
        _allEvents,
        _selectedCategory,
        _selectedIdentifierGroup,
        _selectedSource,
        _searchQuery
    ) { all, cat, idGroup, source, query ->
        all.filter { event ->
            eventMatchesCategory(event, cat) &&
                (idGroup == null || resolveEventGroup(event)?.name == idGroup) &&
                (source == null || event.source == source) &&
                eventMatchesQuery(event, query)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val pinnedFiltered: StateFlow<List<CaptureEvent>> =
        combine(filteredRaw, _pinnedOnly, _pinnedKeys) { list, only, pins ->
            if (!only) list else list.filter { pinKey(it) in pins }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val liveDisplay: StateFlow<List<DisplayEvent>> =
        combine(pinnedFiltered, _dedupEnabled, _pinnedKeys) { list, dedup, pins ->
            val display = if (dedup) collapseRepeats(list) else list.map { DisplayEvent(it) }
            display.map { it.copy(pinned = pinKey(it.event) in pins) }
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

    val askedDigest: StateFlow<List<AskedItem>> = pinnedFiltered
        .map { buildAskedDigest(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val askedSections: StateFlow<List<DigestSection>> = pinnedFiltered
        .map { buildAskedSections(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val sourceCounts: StateFlow<Map<EventSource, Int>> = _allEvents
        .map { list -> list.groupingBy { it.source }.eachCount() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyMap())

    val eventCount: StateFlow<Int> = _allEvents
        .map { it.size }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    val categoryCounts: StateFlow<Map<AccessCategory, Int>> = _allEvents
        .map { list ->
            val counts = list.groupingBy { it.category }.eachCount().toMutableMap()
            counts[AccessCategory.IDENTIFIER] = list.count(::isIdentifierEvent)
            counts
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyMap())

    val identifierGroupCounts: StateFlow<Map<String, Int>> = _allEvents
        .map { list ->
            list.mapNotNull { resolveEventGroup(it)?.name }
                .groupingBy { it }
                .eachCount()
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyMap())

    private var observeJob: Job? = null
    private var runningWatchJob: Job? = null
    @Volatile
    private var ignoreDeathUntilMs = 0L

    fun init(packageName: String) {
        if (_packageName.value == packageName) return
        _packageName.value = packageName
        val app = getApplication<Application>()
        _pinnedKeys.value = SessionPrefs.pins(app)
        _dedupEnabled.value = SessionPrefs.dedup(app)
        _selectedCategory.value = null
        _selectedSource.value = null
        _selectedIdentifierGroup.value = null
        _listMode.value = runCatching { ListMode.valueOf(SessionPrefs.listMode(app)) }
            .getOrDefault(ListMode.DIGEST)
        _sessionStartedAt.value = System.currentTimeMillis()
        _targetDied.value = false
        _targetRunning.value = false
        observeJob?.cancel()
        observeJob = viewModelScope.launch {
            repository.observeEvents(packageName).collect { list ->
                _allEvents.value = list
            }
        }
        runningWatchJob?.cancel()
        runningWatchJob = viewModelScope.launch(Dispatchers.IO) {
            var seenRunning = false
            var downStreak = 0
            while (isActive) {
                val running = RootShell.isAppRunning(_packageName.value)
                if (running) {
                    seenRunning = true
                    downStreak = 0
                    _targetRunning.value = true
                } else {
                    downStreak++
                    if (downStreak >= 2) {
                        val ignoreDeath = System.currentTimeMillis() < ignoreDeathUntilMs
                        if (seenRunning && _targetRunning.value && !_targetDied.value && !ignoreDeath) {
                            _targetDied.value = true
                        }
                        _targetRunning.value = false
                        seenRunning = false
                    }
                }
                delay(3000)
            }
        }
    }

    private fun suppressDeathBanner(ms: Long = 15_000L) {
        ignoreDeathUntilMs = System.currentTimeMillis() + ms
        _targetDied.value = false
    }

    fun consumeTargetDied() {
        _targetDied.value = false
    }

    fun setCategoryFilter(category: AccessCategory?) {
        _selectedCategory.value = category
        if (category != AccessCategory.IDENTIFIER) {
            _selectedIdentifierGroup.value = null
        }
        persistFilters()
    }

    fun setIdentifierGroupFilter(group: String?) {
        _selectedIdentifierGroup.value = if (_selectedIdentifierGroup.value == group) null else group
        persistFilters()
    }

    fun setListMode(mode: ListMode) {
        _listMode.value = mode
        SessionPrefs.setListMode(getApplication(), mode.name)
    }

    fun setSourceFilter(source: EventSource?) {
        _selectedSource.value = if (_selectedSource.value == source) null else source
        persistFilters()
    }

    fun filterByAction(action: String) {
        _showSearch.value = true
        _searchQuery.value = action
    }

    fun filterByIdentifier(id: String) {
        _showSearch.value = true
        _searchQuery.value = id
        persistFilters()
    }

    fun selectAsked(item: AskedItem) {
        val match = _allEvents.value.lastOrNull { event ->
            event.id == item.eventId ||
                event.identifierName == item.id ||
                event.action == item.title
        }
        if (match != null) {
            _selectedEvent.value = match
        } else {
            filterByIdentifier(item.title)
        }
    }

    private fun persistFilters() {
        SessionPrefs.saveFilters(
            getApplication(),
            _selectedCategory.value?.name,
            _selectedSource.value?.name,
            _selectedIdentifierGroup.value
        )
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
        SessionPrefs.setDedup(getApplication(), _dedupEnabled.value)
    }

    fun togglePinnedOnly() {
        _pinnedOnly.value = !_pinnedOnly.value
    }

    fun togglePin(event: CaptureEvent) {
        val key = pinKey(event)
        val nowPinned = SessionPrefs.togglePin(getApplication(), key)
        _pinnedKeys.value = SessionPrefs.pins(getApplication())
        _fridaMessage.value = if (nowPinned) "Закреплено" else "Откреплено"
    }

    fun isPinned(event: CaptureEvent): Boolean = pinKey(event) in _pinnedKeys.value

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
        suppressDeathBanner()
        viewModelScope.launch(Dispatchers.IO) {
            RootShell.launchApp(_packageName.value)
            _targetRunning.value = RootShell.isAppRunning(_packageName.value)
        }
    }

    fun forceStopTarget() {
        suppressDeathBanner()
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
            doExport(appName, pinnedFiltered.value)
        }
    }

    fun exportHar(appName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isExporting.value = true
            val mitm = _allEvents.value.filter { it.source == EventSource.MITM }
            val source = mitm.ifEmpty { pinnedFiltered.value.ifEmpty { _allEvents.value } }
            _exportResult.value = com.deviceinfo.trafficmonitor.export.ExportHelper.exportHar(
                context = getApplication(),
                packageName = _packageName.value,
                appName = appName,
                events = source
            )
            _isExporting.value = false
        }
    }

    fun copyMitmCa() {
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<Application>()
            if (MitmCaManager.caCert == null) {
                MitmCaManager.ensureCa(app)
            }
            val pem = MitmCaManager.caPem()
            if (pem == null) {
                _fridaMessage.value = "CA ещё нет — включите MITM"
                return@launch
            }
            val cm = app.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            cm.setPrimaryClip(android.content.ClipData.newPlainText("AccessMonitor CA", pem))
            val subject = MitmCaManager.caSubject().orEmpty()
            _fridaMessage.value = "CA скопирован" + if (subject.isNotBlank()) " · $subject" else ""
        }
    }

    fun shareMitmCa(): java.io.File? {
        val app = getApplication<Application>()
        if (MitmCaManager.caCert == null) {
            MitmCaManager.ensureCa(app)
        }
        return MitmCaManager.exportCaFile(app)
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
            if (ok) FridaEventPoller.active?.pullLogcatDump()
            _fridaStatus.value = FridaInstaller.status
            _fridaMessage.value = if (ok) {
                "Скрипт загружен. В фильтре должен появиться источник Frida"
            } else {
                FridaInstaller.lastError ?: "Zygisk не подключил хуки"
            }
            _isFridaInjecting.value = false
        }
    }

    fun injectFridaWrap() {
        viewModelScope.launch(Dispatchers.IO) {
            _isFridaInjecting.value = true
            suppressDeathBanner(20_000L)
            FridaInstaller.ensureReady(getApplication())
            FridaInstaller.prepareHooksForPackage(_packageName.value, getApplication())
            val ok = FridaInstaller.injectManual(getApplication(), _packageName.value, restartApp = true)
            if (ok) FridaEventPoller.active?.pullLogcatDump()
            _fridaStatus.value = FridaInstaller.status
            _fridaMessage.value = if (ok) {
                "Скрипт загружен. В фильтре должен появиться источник Frida"
            } else {
                FridaInstaller.lastError ?: "Zygisk не подключил хуки"
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
            suppressDeathBanner(20_000L)
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
