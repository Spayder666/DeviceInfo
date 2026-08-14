package com.deviceinfo.trafficmonitor.analysis

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Достаёт :method/:path/:status из HTTP/2, если заголовки не только Huffman. */
object Http2Frames {
    private val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()

    fun summarize(data: ByteArray): String? {
        if (data.size < 9) return null
        val isPreface = data.size >= preface.size && data.copyOf(preface.size).contentEquals(preface)
        if (!isPreface && data[3] !in 0..9) return null
        val out = ArrayList<String>(6)
        if (isPreface) out.add("HTTP/2 preface")
        var i = if (isPreface) preface.size else 0
        var frames = 0
        while (i + 9 <= data.size && frames < 12) {
            val len = ((data[i].toInt() and 0xff) shl 16) or
                ((data[i + 1].toInt() and 0xff) shl 8) or
                (data[i + 2].toInt() and 0xff)
            val type = data[i + 3].toInt() and 0xff
            val stream = ByteBuffer.wrap(data, i + 5, 4).order(ByteOrder.BIG_ENDIAN).int and 0x7fffffff
            i += 9
            if (len < 0 || i + len > data.size) break
            val payload = data.copyOfRange(i, i + len)
            i += len
            frames++
            when (type) {
                1 -> {
                    val headers = extractLiterals(payload)
                    out.add("HEADERS #$stream ${headers.ifBlank { "len=$len" }}")
                }
                0 -> {
                    val printable = payload.toString(Charsets.UTF_8)
                        .filter { it == '\n' || it == '\r' || it.code in 32..126 }
                    if (printable.length >= 8) out.add("DATA #$stream ${printable.take(90)}")
                    else out.add("DATA #$stream $len")
                }
                4 -> out.add("SETTINGS")
                8 -> out.add("WINDOW_UPDATE")
                else -> out.add("frame$type #$stream")
            }
        }
        return if (out.isEmpty()) null else out.joinToString(" · ").take(400)
    }

    private fun extractLiterals(payload: ByteArray): String {
        val text = payload.toString(Charsets.ISO_8859_1)
        val keys = listOf(":method", ":path", ":authority", ":status", ":scheme", "content-type", "host")
        return keys.mapNotNull { key ->
            val idx = text.indexOf(key, ignoreCase = true)
            if (idx < 0) return@mapNotNull null
            val after = text.substring(idx + key.length).take(80)
            val value = after.dropWhile { it.code < 33 }.takeWhile { it.code in 33..126 }
            if (value.isBlank()) null else "$key=$value"
        }.joinToString(" ")
    }
}
