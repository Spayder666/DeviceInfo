package com.deviceinfo.trafficmonitor.export

import android.content.Context
import android.content.Intent
import android.os.Environment
import androidx.core.content.FileProvider
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ExportHelper {

    data class ExportResult(
        val jsonFile: File,
        val csvFile: File,
        val eventCount: Int
    )

    fun exportEvents(
        context: Context,
        packageName: String,
        appName: String,
        events: List<CaptureEvent>
    ): ExportResult {
        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val safeName = appName.replace(Regex("[^a-zA-Z0-9._-]"), "_").take(40)
        val baseName = "AccessMonitor_${safeName}_${timestamp}"

        val exportDir = File(
            context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS),
            "exports"
        ).apply { mkdirs() }

        val jsonFile = File(exportDir, "$baseName.json")
        val csvFile = File(exportDir, "$baseName.csv")

        jsonFile.writeText(toJson(packageName, appName, events))
        csvFile.writeText(toCsv(events))

        return ExportResult(jsonFile, csvFile, events.size)
    }

    fun createShareIntent(context: Context, file: File, mimeType: String): Intent {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        return Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    private fun toJson(packageName: String, appName: String, events: List<CaptureEvent>): String {
        val root = JSONObject()
        root.put("exportedAt", System.currentTimeMillis())
        root.put("targetPackage", packageName)
        root.put("targetAppName", appName)
        root.put("eventCount", events.size)

        val arr = JSONArray()
        for (e in events) {
            arr.put(
                JSONObject().apply {
                    put("id", e.id)
                    put("timestamp", e.timestamp)
                    put("category", e.category.name)
                    put("source", e.source.name)
                    put("action", e.action)
                    put("permission", e.permission)
                    put("requestDetails", e.requestDetails)
                    put("responseDetails", e.responseDetails)
                    put("rawData", e.rawData)
                    put("processId", e.processId)
                    put("identifierName", e.identifierName)
                    put("identifierGroup", e.identifierGroup)
                }
            )
        }
        root.put("events", arr)
        return root.toString(2)
    }

    private fun toCsv(events: List<CaptureEvent>): String {
        val header = listOf(
            "id", "timestamp", "category", "source", "action", "permission",
            "requestDetails", "responseDetails", "identifierName", "identifierGroup",
            "processId", "rawData"
        ).joinToString(",")
        val rows = events.map { e ->
            listOf(
                e.id, e.timestamp, e.category.name, e.source.name, e.action,
                e.permission, e.requestDetails, e.responseDetails,
                e.identifierName, e.identifierGroup, e.processId, e.rawData
            ).joinToString(",") { escapeCsv(it?.toString()) }
        }
        return (listOf(header) + rows).joinToString("\n")
    }

    private fun escapeCsv(value: String?): String {
        if (value == null) return ""
        val v = value.replace("\"", "\"\"")
        return if (v.contains(',') || v.contains('\n') || v.contains('"')) "\"$v\"" else v
    }
}
