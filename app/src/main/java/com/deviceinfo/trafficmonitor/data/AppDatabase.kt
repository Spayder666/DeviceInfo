package com.deviceinfo.trafficmonitor.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

class EnumConverters {
    @TypeConverter
    fun fromCategory(value: AccessCategory): String = value.name

    @TypeConverter
    fun toCategory(value: String): AccessCategory =
        runCatching { AccessCategory.valueOf(value) }.getOrDefault(AccessCategory.OTHER)

    @TypeConverter
    fun fromSource(value: EventSource): String = value.name

    @TypeConverter
    fun toSource(value: String): EventSource = EventSource.valueOf(value)
}

@Database(entities = [CaptureEvent::class], version = 3, exportSchema = false)
@TypeConverters(EnumConverters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun captureEventDao(): CaptureEventDao

    companion object {
        @Volatile
        private var instance: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "access_monitor.db"
                ).fallbackToDestructiveMigration()
                .build().also { instance = it }
            }
        }
    }
}
