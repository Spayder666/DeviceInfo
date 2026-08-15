package com.deviceinfo.trafficmonitor.export

import android.content.Context
import android.content.Intent
import android.os.Environment
import androidx.core.content.FileProvider
import com.deviceinfo.trafficmonitor.data.CaptureEvent
import com.deviceinfo.trafficmonitor.data.EventSource
import com.deviceinfo.trafficmonitor.ui.buildAskedDigest
import com.deviceinfo.trafficmonitor.ui.describeAskedGot
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object ExportHelper {

    data class ExportResult(
        val jsonFile: File,
        val csvFile: File? = null,
        val eventCount: Int,
        val label: String = "JSON+CSV",
        val mime: String = "application/json"
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

        return ExportResult(jsonFile, csvFile, events.size, "JSON+CSV")
    }

    fun exportHar(
        context: Context,
        packageName: String,
        appName: String,
        events: List<CaptureEvent>
    ): ExportResult {
        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val safeName = appName.replace(Regex("[^a-zA-Z0-9._-]"), "_").take(40)
        val exportDir = File(
            context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS),
            "exports"
        ).apply { mkdirs() }
        val harFile = File(exportDir, "AccessMonitor_${safeName}_${timestamp}.har")
        val mitm = events.filter { it.source == EventSource.MITM }
        harFile.writeText(toHar(packageName, appName, mitm.ifEmpty { events }))
        return ExportResult(
            jsonFile = harFile,
            eventCount = mitm.ifEmpty { events }.size,
            label = "HAR",
            mime = "application/json"
        )
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

        val digest = JSONArray()
        for (item in buildAskedDigest(events)) {
            digest.put(
                JSONObject()
                    .put("asked", item.title)
                    .put("got", item.value)
                    .put("api", item.api)
                    .put("count", item.count)
            )
        }
        root.put("askedGot", digest)

        val arr = JSONArray()
        for (e in events) {
            val io = describeAskedGot(e)
            arr.put(
                JSONObject().apply {
                    put("id", e.id)
                    put("timestamp", e.timestamp)
                    put("category", e.category.name)
                    put("source", e.source.name)
                    put("action", e.action)
                    put("asked", io.asked)
                    put("got", io.got)
                    put("api", io.api)
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
            "id", "timestamp", "category", "source", "action", "asked", "got", "api", "permission",
            "requestDetails", "responseDetails", "identifierName", "identifierGroup",
            "processId", "rawData"
        ).joinToString(",")
        val rows = events.map { e ->
            val io = describeAskedGot(e)
            listOf(
                e.id, e.timestamp, e.category.name, e.source.name, e.action,
                io.asked, io.got, io.api,
                e.permission, e.requestDetails, e.responseDetails,
                e.identifierName, e.identifierGroup, e.processId, e.rawData
            ).joinToString(",") { escapeCsv(it?.toString()) }
        }
        return (listOf(header) + rows).joinToString("\n")
    }

    private fun toHar(packageName: String, appName: String, events: List<CaptureEvent>): String {
        val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val entries = JSONArray()
        val sorted = events.sortedBy { it.timestamp }
        val used = BooleanArray(sorted.size)
        for (i in sorted.indices) {
            if (used[i]) continue
            val event = sorted[i]
            val host = event.requestDetails?.trim().orEmpty().ifBlank { "unknown" }
            val raw = event.rawData.orEmpty()
            val isRequest = event.action.contains("request", ignoreCase = true) ||
                raw.startsWith("GET ") || raw.startsWith("POST ") ||
                raw.startsWith("PUT ") || raw.startsWith("HEAD ") ||
                raw.startsWith("DELETE ") || raw.startsWith("PATCH ")
            var pair: CaptureEvent? = null
            if (isRequest) {
                for (j in i + 1 until sorted.size) {
                    if (used[j]) continue
                    val other = sorted[j]
                    if (other.requestDetails == event.requestDetails &&
                        other.action.contains("response", ignoreCase = true) &&
                        other.timestamp - event.timestamp < 8_000
                    ) {
                        pair = other
                        used[j] = true
                        break
                    }
                }
            }
            used[i] = true
            val requestText = if (isRequest) raw else pair?.rawData.orEmpty()
            val responseText = if (isRequest) pair?.rawData.orEmpty() else raw
            val firstReq = requestText.lineSequence().firstOrNull { it.isNotBlank() }.orEmpty()
            val firstResp = responseText.lineSequence().firstOrNull { it.isNotBlank() }.orEmpty()
            val method = firstReq.split(' ').firstOrNull()?.takeIf { it.length in 2..10 } ?: "GET"
            val path = firstReq.split(' ').getOrNull(1) ?: "/"
            val url = if (path.startsWith("http")) path else "https://$host$path"
            val status = Regex("""HTTP/\S+\s+(\d{3})""").find(firstResp)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            val statusText = firstResp.split(' ').drop(2).joinToString(" ").ifBlank { if (status == 0) "" else "OK" }
            entries.put(
                JSONObject().apply {
                    put("startedDateTime", iso.format(Date(event.timestamp)))
                    put("time", ((pair?.timestamp ?: event.timestamp) - event.timestamp).coerceAtLeast(0))
                    put(
                        "request",
                        JSONObject()
                            .put("method", method)
                            .put("url", url)
                            .put("httpVersion", "HTTP/1.1")
                            .put("headers", JSONArray())
                            .put("queryString", JSONArray())
                            .put("cookies", JSONArray())
                            .put("headersSize", -1)
                            .put("bodySize", requestText.length)
                    )
                    put(
                        "response",
                        JSONObject()
                            .put("status", status)
                            .put("statusText", statusText)
                            .put("httpVersion", "HTTP/1.1")
                            .put("headers", JSONArray())
                            .put("cookies", JSONArray())
                            .put(
                                "content",
                                JSONObject()
                                    .put("size", responseText.length)
                                    .put("mimeType", "text/plain")
                                    .put("text", responseText.take(8_000))
                            )
                            .put("redirectURL", "")
                            .put("headersSize", -1)
                            .put("bodySize", responseText.length)
                    )
                    put("cache", JSONObject())
                    put("timings", JSONObject().put("send", 0).put("wait", 0).put("receive", 0))
                    put("serverIPAddress", host)
                    put("comment", event.action)
                }
            )
        }
        return JSONObject()
            .put(
                "log",
                JSONObject()
                    .put("version", "1.2")
                    .put("creator", JSONObject().put("name", "Access Monitor").put("version", "1.0.43"))
                    .put("comment", "$appName ($packageName)")
                    .put("entries", entries)
            )
            .toString(2)
    }

    private fun escapeCsv(value: String?): String {
        if (value == null) return ""
        val v = value.replace("\"", "\"\"")
        return if (v.contains(',') || v.contains('\n') || v.contains('"')) "\"$v\"" else v
    }
}
