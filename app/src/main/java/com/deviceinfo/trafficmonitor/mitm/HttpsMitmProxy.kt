package com.deviceinfo.trafficmonitor.mitm

import com.deviceinfo.trafficmonitor.analysis.Http2Frames
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class HttpsMitmProxy(
    private val onPlaintext: (host: String, direction: String, text: String) -> Unit
) {
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null
    private var pool = Executors.newCachedThreadPool()

    fun start(port: Int = MitmCaManager.PORT) {
        if (!running.compareAndSet(false, true)) return
        if (pool.isShutdown) pool = Executors.newCachedThreadPool()
        server = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress("0.0.0.0", port))
        }
        pool.execute {
            while (running.get()) {
                try {
                    val client = server?.accept() ?: break
                    pool.execute { handle(client) }
                } catch (_: Exception) {
                    if (!running.get()) break
                }
            }
        }
    }

    fun stop() {
        running.set(false)
        try { server?.close() } catch (_: Exception) {}
        server = null
        pool.shutdownNow()
    }

    private fun handle(client: Socket) {
        try {
            client.soTimeout = 20_000
            val first = readTlsOrHttp(client.getInputStream()) ?: return
            if (first.isTls) {
                val host = first.sni ?: return
                mitmTls(client, first.bytes, host)
            } else {
                relayHttp(client, first.bytes)
            }
        } catch (_: Exception) {
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun mitmTls(client: Socket, leftover: ByteArray, host: String) {
        val creds = MitmCaManager.contextForHost(host)
        val engine = creds.sslContext.createSSLEngine(host, 443)
        engine.useClientMode = false
        engine.needClientAuth = false
        applyAlpn(engine, arrayOf("h2", "http/1.1"))
        handshakeWithLeftover(engine, client, leftover)

        val negotiated = negotiatedProtocol(engine)
        val upstream = SSLSocketFactory.getDefault().createSocket(host, 443) as SSLSocket
        upstream.soTimeout = 20_000
        applyAlpn(upstream, arrayOf(negotiated))
        upstream.startHandshake()

        val fromClient = Thread {
            pumpEngineToPeer(engine, client, upstream.getOutputStream(), host, "request")
        }
        val fromServer = Thread {
            pumpPeerToEngine(engine, client, upstream.getInputStream(), host, "response")
        }
        fromClient.start()
        fromServer.start()
        fromClient.join(60_000)
        fromServer.join(60_000)
        try { upstream.close() } catch (_: Exception) {}
    }

    private fun handshakeWithLeftover(engine: SSLEngine, client: Socket, leftover: ByteArray) {
        engine.beginHandshake()
        var pending = leftover
        val out = client.getOutputStream()
        val input = client.getInputStream()
        var guard = 0
        while (guard++ < 32) {
            val status = engine.handshakeStatus
            if (status == SSLEngineResult.HandshakeStatus.FINISHED ||
                status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
            ) return
            when (status) {
                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    if (pending.isEmpty()) pending = readAvailable(input, 16_384)
                    if (pending.isEmpty()) return
                    val src = ByteBuffer.wrap(pending)
                    val dst = ByteBuffer.allocate(maxOf(engine.session.applicationBufferSize, 16_384))
                    val res = engine.unwrap(src, dst)
                    pending = ByteArray(src.remaining()).also { src.get(it) }
                    if (res.status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        pending += readAvailable(input, 16_384)
                    }
                    runTasks(engine)
                }
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    val dst = ByteBuffer.allocate(maxOf(engine.session.packetBufferSize, 16_384))
                    engine.wrap(ByteBuffer.allocate(0), dst)
                    dst.flip()
                    if (dst.hasRemaining()) {
                        val bytes = ByteArray(dst.remaining())
                        dst.get(bytes)
                        out.write(bytes)
                        out.flush()
                    }
                    runTasks(engine)
                }
                SSLEngineResult.HandshakeStatus.NEED_TASK -> runTasks(engine)
                else -> return
            }
        }
    }

    private fun pumpEngineToPeer(
        engine: SSLEngine,
        client: Socket,
        peerOut: OutputStream,
        host: String,
        direction: String
    ) {
        val input = client.getInputStream()
        val app = ByteBuffer.allocate(32_768)
        while (true) {
            val packet = readAvailable(input, 16_384)
            if (packet.isEmpty()) break
            val src = ByteBuffer.wrap(packet)
            app.clear()
            val res = engine.unwrap(src, app)
            if (res.bytesProduced() > 0) {
                app.flip()
                val plain = ByteArray(app.remaining())
                app.get(plain)
                peerOut.write(plain)
                peerOut.flush()
                emit(host, direction, plain)
            }
            if (res.status == SSLEngineResult.Status.CLOSED) break
        }
    }

    private fun pumpPeerToEngine(
        engine: SSLEngine,
        client: Socket,
        peerIn: InputStream,
        host: String,
        direction: String
    ) {
        val out = client.getOutputStream()
        val buf = ByteArray(16_384)
        val packet = ByteBuffer.allocate(32_768)
        while (true) {
            val n = peerIn.read(buf)
            if (n <= 0) break
            emit(host, direction, buf.copyOf(n))
            val src = ByteBuffer.wrap(buf, 0, n)
            packet.clear()
            engine.wrap(src, packet)
            packet.flip()
            if (packet.hasRemaining()) {
                val wired = ByteArray(packet.remaining())
                packet.get(wired)
                out.write(wired)
                out.flush()
            }
        }
    }

    private fun relayHttp(client: Socket, leftover: ByteArray) {
        val text = leftover.toString(Charset.forName("ISO-8859-1"))
        val host = Regex("(?im)^Host:\\s*([^\\s:]+)").find(text)?.groupValues?.get(1) ?: return
        val port = Regex("(?im)^Host:\\s*[^\\s:]+:(\\d+)").find(text)?.groupValues?.get(1)?.toIntOrNull() ?: 80
        emit(host, "request", leftover)
        val up = Socket(host, port)
        up.getOutputStream().write(leftover)
        up.getOutputStream().flush()
        val t1 = Thread { copy(client.getInputStream(), up.getOutputStream(), host, "request") }
        val t2 = Thread { copy(up.getInputStream(), client.getOutputStream(), host, "response") }
        t1.start()
        t2.start()
        t1.join(30_000)
        t2.join(30_000)
        try { up.close() } catch (_: Exception) {}
    }

    private fun copy(from: InputStream, to: OutputStream, host: String, direction: String) {
        val buf = ByteArray(8192)
        while (true) {
            val n = try { from.read(buf) } catch (_: Exception) { -1 }
            if (n <= 0) break
            to.write(buf, 0, n)
            to.flush()
            emit(host, direction, buf.copyOf(n))
        }
    }

    private fun emit(host: String, direction: String, data: ByteArray) {
        val text = decodePlain(data)
        if (text.isBlank()) return
        onPlaintext(host, direction, text.take(1800))
    }

    private fun decodePlain(data: ByteArray): String {
        val h2 = Http2Frames.summarize(data)
        if (h2 != null) return "HTTP/2 $h2"
        val s = data.toString(Charsets.UTF_8)
        if (s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("PUT ") ||
            s.startsWith("HTTP/") || s.startsWith("{") || s.startsWith("[") ||
            s.contains("content-type", ignoreCase = true)
        ) return s
        val printable = s.filter { it == '\n' || it == '\r' || it == '\t' || it.code in 32..126 }
        return if (printable.length >= 8) printable else ""
    }

    private fun applyAlpn(engine: SSLEngine, protocols: Array<String>) {
        try {
            val params = engine.sslParameters
            params.applicationProtocols = protocols
            engine.sslParameters = params
            engine.setHandshakeApplicationProtocolSelector { _, offered ->
                when {
                    offered.contains("h2") && protocols.contains("h2") -> "h2"
                    offered.contains("http/1.1") -> "http/1.1"
                    else -> offered.firstOrNull()
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun applyAlpn(socket: SSLSocket, protocols: Array<String>) {
        try {
            val params = socket.sslParameters
            params.applicationProtocols = protocols
            socket.sslParameters = params
        } catch (_: Exception) {
        }
    }

    private fun negotiatedProtocol(engine: SSLEngine): String {
        return try {
            engine.applicationProtocol?.takeIf { it.isNotBlank() }
        } catch (_: Exception) {
            null
        } ?: "http/1.1"
    }

    private fun runTasks(engine: SSLEngine) {
        while (true) {
            val t = engine.delegatedTask ?: break
            t.run()
        }
    }

    private fun readAvailable(input: InputStream, max: Int): ByteArray {
        val buf = ByteArray(max)
        val n = input.read(buf)
        return if (n <= 0) ByteArray(0) else buf.copyOf(n)
    }

    private data class Head(val bytes: ByteArray, val isTls: Boolean, val sni: String?)

    private fun readTlsOrHttp(input: InputStream): Head? {
        val first = ByteArray(5)
        if (!readFully(input, first, 5)) return null
        if (first[0] == 0x16.toByte()) {
            val len = ((first[3].toInt() and 0xff) shl 8) or (first[4].toInt() and 0xff)
            val rest = ByteArray(len)
            if (!readFully(input, rest, len)) return null
            val all = first + rest
            return Head(all, true, parseSni(all))
        }
        val more = ByteArrayOutputStream()
        more.write(first)
        val tmp = ByteArray(4096)
        val n = try { input.read(tmp) } catch (_: Exception) { -1 }
        if (n > 0) more.write(tmp, 0, n)
        return Head(more.toByteArray(), false, null)
    }

    private fun readFully(input: InputStream, buf: ByteArray, len: Int): Boolean {
        var off = 0
        while (off < len) {
            val n = input.read(buf, off, len - off)
            if (n <= 0) return false
            off += n
        }
        return true
    }

    private fun parseSni(record: ByteArray): String? {
        return try {
            var i = 5
            if (record.size < 43) return null
            i += 4
            i += 32
            val sessionLen = record[i].toInt() and 0xff
            i += 1 + sessionLen
            val cipherLen = ((record[i].toInt() and 0xff) shl 8) or (record[i + 1].toInt() and 0xff)
            i += 2 + cipherLen
            val compLen = record[i].toInt() and 0xff
            i += 1 + compLen
            if (i + 2 > record.size) return null
            val extLen = ((record[i].toInt() and 0xff) shl 8) or (record[i + 1].toInt() and 0xff)
            i += 2
            val extEnd = i + extLen
            while (i + 4 <= extEnd && i + 4 <= record.size) {
                val type = ((record[i].toInt() and 0xff) shl 8) or (record[i + 1].toInt() and 0xff)
                val len = ((record[i + 2].toInt() and 0xff) shl 8) or (record[i + 3].toInt() and 0xff)
                i += 4
                if (type == 0 && i + 5 <= record.size) {
                    var j = i + 2
                    val nameType = record[j].toInt() and 0xff
                    val nameLen = ((record[j + 1].toInt() and 0xff) shl 8) or (record[j + 2].toInt() and 0xff)
                    j += 3
                    if (nameType == 0 && j + nameLen <= record.size) {
                        return String(record, j, nameLen, Charsets.US_ASCII)
                    }
                }
                i += len
            }
            null
        } catch (_: Exception) {
            null
        }
    }
}
