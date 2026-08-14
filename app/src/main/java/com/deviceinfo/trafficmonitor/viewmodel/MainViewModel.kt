package com.deviceinfo.trafficmonitor.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.deviceinfo.trafficmonitor.TrafficMonitorApp
import com.deviceinfo.trafficmonitor.data.AccessCategory
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.model.InstalledApp
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
}
