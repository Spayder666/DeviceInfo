package com.deviceinfo.trafficmonitor.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface CaptureEventDao {
    @Insert
    suspend fun insert(event: CaptureEvent): Long

    @Query("SELECT * FROM capture_events WHERE targetPackage = :packageName ORDER BY timestamp DESC LIMIT 5000")
    fun observeByPackage(packageName: String): Flow<List<CaptureEvent>>

    @Query("SELECT * FROM capture_events WHERE targetPackage = :packageName AND category = :category ORDER BY timestamp DESC LIMIT 5000")
    fun observeByCategory(packageName: String, category: AccessCategory): Flow<List<CaptureEvent>>

    @Query("SELECT * FROM capture_events WHERE id = :id")
    suspend fun getById(id: Long): CaptureEvent?

    @Query("DELETE FROM capture_events WHERE targetPackage = :packageName")
    suspend fun clearForPackage(packageName: String)

    @Query("SELECT COUNT(*) FROM capture_events WHERE targetPackage = :packageName")
    fun observeCount(packageName: String): Flow<Int>

    @Query("SELECT EXISTS(SELECT 1 FROM capture_events WHERE targetPackage = :pkg AND action = :action AND rawData = :raw AND timestamp > :since)")
    suspend fun existsRecent(pkg: String, action: String, raw: String?, since: Long): Boolean
}
