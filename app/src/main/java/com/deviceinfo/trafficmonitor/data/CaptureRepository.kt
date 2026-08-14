package com.deviceinfo.trafficmonitor.data

import kotlinx.coroutines.flow.Flow

class CaptureRepository(private val dao: CaptureEventDao) {

    fun observeEvents(packageName: String): Flow<List<CaptureEvent>> =
        dao.observeByPackage(packageName)

    fun observeCount(packageName: String): Flow<Int> =
        dao.observeCount(packageName)

    suspend fun insert(event: CaptureEvent): Long = dao.insert(event)

    suspend fun getById(id: Long): CaptureEvent? = dao.getById(id)

    suspend fun getAllEvents(packageName: String): List<CaptureEvent> =
        dao.getAllForPackage(packageName)

    suspend fun clear(packageName: String) = dao.clearForPackage(packageName)

    suspend fun isDuplicate(pkg: String, action: String, raw: String?, sinceMs: Long = 2000): Boolean =
        dao.existsRecent(pkg, action, raw, System.currentTimeMillis() - sinceMs)
}
