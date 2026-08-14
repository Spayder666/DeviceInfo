package com.deviceinfo.trafficmonitor.mitm

import android.content.Context
import android.util.Log
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.root.RootShell
import java.io.File
import java.net.Socket
import java.security.KeyPair
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager

object MitmCaManager {
    const val PORT = 18888
    private const val TAG = "MitmCa"
    private const val CERT_NAME = "mitm-ca.pem"
    private const val KEY_NAME = "mitm-ca-key.pem"

    data class HostCreds(
        val certificate: X509Certificate,
        val keyPair: KeyPair,
        val sslContext: SSLContext
    )

    @Volatile
    var caCert: X509Certificate? = null
        private set
    @Volatile
    var lastError: String? = null
        private set
    private var caKey: PrivateKey? = null
    private val hostCache = ConcurrentHashMap<String, HostCreds>()
    private val errors = mutableListOf<String>()

    fun ensureCa(context: Context): Boolean {
        lastError = null
        errors.clear()
        val certFile = File(context.filesDir, CERT_NAME)
        val keyFile = File(context.filesDir, KEY_NAME)
        File(context.filesDir, "am_mitm.p12").delete()

        val ok = tryLoad(certFile, keyFile) ||
            tryCopyAssets(context, certFile, keyFile) ||
            tryMint(certFile, keyFile) ||
            tryOpenSsl(certFile, keyFile)

        if (!ok || caCert == null || caKey == null) {
            lastError = errors.lastOrNull() ?: "все способы выпуска CA провалились"
            Log.e(TAG, "ensureCa failed: $lastError")
            return false
        }
        runCatching { exportPem(context) }
        return true
    }

    fun contextForHost(host: String): HostCreds {
        hostCache[host]?.let { return it }
        val creds = issueHost(host)
        hostCache[host] = creds
        return creds
    }

    fun installAsSystemCa(): Boolean {
        val cert = caCert ?: return false
        val hash = opensslSubjectHashOld(cert)
        val pem = X509Mint.certToPem(cert)
        val tmp = "${FridaInstaller.BASE_DIR}/$hash.0"
        RootShell.execAndRead("mkdir -p ${FridaInstaller.BASE_DIR}")
        RootShell.execAndRead("printf %s ${RootShell.shellQuote(pem)} > $tmp && chmod 644 $tmp")
        RootShell.execAndRead("mkdir -p /data/misc/user/0/cacerts-added && cp $tmp /data/misc/user/0/cacerts-added/$hash.0 && chmod 644 /data/misc/user/0/cacerts-added/$hash.0")
        RootShell.execAndRead(
            "if [ -d /system/etc/security/cacerts ]; then " +
                "mount -o rw,remount /system 2>/dev/null; " +
                "cp $tmp /system/etc/security/cacerts/$hash.0 2>/dev/null; fi"
        )
        RootShell.execAndRead(
            "if [ -d /apex/com.android.conscrypt/cacerts ]; then " +
                "mkdir -p ${FridaInstaller.BASE_DIR}/cacerts && " +
                "cp -f /apex/com.android.conscrypt/cacerts/* ${FridaInstaller.BASE_DIR}/cacerts/ 2>/dev/null; " +
                "cp $tmp ${FridaInstaller.BASE_DIR}/cacerts/$hash.0 && " +
                "mount --bind ${FridaInstaller.BASE_DIR}/cacerts /apex/com.android.conscrypt/cacerts; fi"
        )
        return true
    }

    fun uninstallBind() {
        RootShell.execAndRead("umount /apex/com.android.conscrypt/cacerts 2>/dev/null")
    }

    private fun tryLoad(certFile: File, keyFile: File): Boolean {
        if (!certFile.exists() || !keyFile.exists()) return false
        return try {
            apply(X509Mint.parseCertificate(certFile.readBytes()), X509Mint.parsePrivateKey(keyFile.readText()))
            true
        } catch (t: Throwable) {
            remember("load PEM", t)
            certFile.delete()
            keyFile.delete()
            false
        }
    }

    private fun tryCopyAssets(context: Context, certFile: File, keyFile: File): Boolean {
        return try {
            val certPem = context.assets.open("mitm/ca.pem").bufferedReader().readText()
            val keyPem = context.assets.open("mitm/ca-key.pem").bufferedReader().readText()
            val cert = X509Mint.parseCertificate(certPem.toByteArray())
            val key = X509Mint.parsePrivateKey(keyPem)
            persist(certFile, keyFile, cert, key)
            apply(cert, key)
            true
        } catch (t: Throwable) {
            remember("assets CA", t)
            false
        }
    }

    private fun tryMint(certFile: File, keyFile: File): Boolean {
        return try {
            val pair = X509Mint.rsaKeyPair()
            val cert = X509Mint.selfSignedCa(pair)
            persist(certFile, keyFile, cert, pair.private)
            apply(cert, pair.private)
            true
        } catch (t: Throwable) {
            remember("X509Mint", t)
            false
        }
    }

    private fun tryOpenSsl(certFile: File, keyFile: File): Boolean {
        val openssl = RootShell.resolveBinary("openssl") ?: run {
            remember("openssl", IllegalStateException("openssl не найден"))
            return false
        }
        return try {
            val dir = certFile.parentFile?.absolutePath ?: return false
            val keyPkcs8 = "$dir/mitm-ca-key.pem"
            val certPem = "$dir/mitm-ca.pem"
            val keyTmp = "$dir/mitm-ca-rsa.pem"
            RootShell.execAndRead(
                "$openssl genrsa -out $keyTmp 2048 && " +
                    "$openssl pkcs8 -topk8 -nocrypt -in $keyTmp -out $keyPkcs8 && " +
                    "$openssl req -new -x509 -key $keyPkcs8 -out $certPem -days 3650 -sha256 " +
                    "-subj /CN=AccessMonitor\\ MITM\\ CA",
                timeoutSec = 20
            )
            val cert = X509Mint.parseCertificate(File(certPem).readBytes())
            val key = X509Mint.parsePrivateKey(File(keyPkcs8).readText())
            apply(cert, key)
            true
        } catch (t: Throwable) {
            remember("openssl", t)
            false
        }
    }

    private fun issueHost(host: String): HostCreds {
        val ca = caCert ?: error("CA missing")
        val key = caKey ?: error("CA key missing")
        val pair = X509Mint.rsaKeyPair()
        val cert = try {
            X509Mint.issueHost(ca, key, pair, host)
        } catch (t: Throwable) {
            Log.e(TAG, "host cert mint failed for $host", t)
            throw t
        }
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(arrayOf(LeafKeyManager(cert, ca, pair.private)), null, null)
        return HostCreds(cert, pair, ctx)
    }

    private fun persist(certFile: File, keyFile: File, cert: X509Certificate, key: PrivateKey) {
        runCatching {
            certFile.writeText(X509Mint.certToPem(cert))
            keyFile.writeText(X509Mint.keyToPem(key))
        }
    }

    private fun apply(cert: X509Certificate, key: PrivateKey) {
        caCert = cert
        caKey = key
        hostCache.clear()
    }

    private fun exportPem(context: Context) {
        val cert = caCert ?: return
        val pem = X509Mint.certToPem(cert)
        File(context.filesDir, CERT_NAME).writeText(pem)
        RootShell.execAndRead("mkdir -p ${FridaInstaller.BASE_DIR}")
        RootShell.execAndRead(
            "printf %s ${RootShell.shellQuote(pem)} > ${FridaInstaller.BASE_DIR}/mitm-ca.pem && chmod 644 ${FridaInstaller.BASE_DIR}/mitm-ca.pem"
        )
    }

    private fun opensslSubjectHashOld(cert: X509Certificate): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(cert.subjectX500Principal.encoded)
        val hash = (digest[0].toInt() and 0xff) or
            ((digest[1].toInt() and 0xff) shl 8) or
            ((digest[2].toInt() and 0xff) shl 16) or
            ((digest[3].toInt() and 0xff) shl 24)
        return String.format("%08x", hash)
    }

    private fun remember(step: String, t: Throwable) {
        val msg = "$step: ${t.javaClass.simpleName}: ${t.message ?: "unknown"}"
        errors += msg
        Log.e(TAG, msg, t)
    }

    private class LeafKeyManager(
        private val leaf: X509Certificate,
        private val ca: X509Certificate,
        private val key: PrivateKey
    ) : X509ExtendedKeyManager() {
        override fun getClientAliases(keyType: String?, issuers: Array<Principal>?) = null
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<Principal>?, socket: Socket?) = null
        override fun getServerAliases(keyType: String?, issuers: Array<Principal>?) = arrayOf("leaf")
        override fun chooseServerAlias(keyType: String?, issuers: Array<Principal>?, socket: Socket?) = "leaf"
        override fun chooseEngineServerAlias(keyType: String?, issuers: Array<Principal>?, engine: SSLEngine?) = "leaf"
        override fun getCertificateChain(alias: String?) = arrayOf(leaf, ca)
        override fun getPrivateKey(alias: String?) = key
    }
}
