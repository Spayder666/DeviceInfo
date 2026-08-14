package com.deviceinfo.trafficmonitor.mitm

import android.content.Context
import android.util.Log
import com.deviceinfo.trafficmonitor.frida.FridaInstaller
import com.deviceinfo.trafficmonitor.root.RootShell
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

object MitmCaManager {
    const val PORT = 18888
    private const val TAG = "MitmCa"
    private const val KS_NAME = "am_mitm.p12"
    private const val KS_PASS = "accessmonitor"

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

    fun ensureCa(context: Context): Boolean {
        lastError = null
        val ksFile = File(context.filesDir, KS_NAME)
        return try {
            if (ksFile.exists()) {
                try {
                    load(ksFile)
                } catch (loadError: Exception) {
                    Log.w(TAG, "keystore load failed, regenerating", loadError)
                    ksFile.delete()
                    generateCa()
                    save(ksFile)
                }
            } else {
                generateCa()
                save(ksFile)
            }
            if (caCert == null || caKey == null) {
                lastError = "CA пустой после генерации"
                return false
            }
            runCatching { exportPem(context) }
            true
        } catch (e: Exception) {
            lastError = e.toUserMessage()
            Log.e(TAG, "ensureCa failed", e)
            false
        }
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
        val pem = toPem(cert)
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

    private fun generateCa() {
        val pair = rsaKeyPair()
        val now = System.currentTimeMillis()
        val name = X500Name("CN=AccessMonitor MITM CA")
        val builder = JcaX509v3CertificateBuilder(
            name,
            BigInteger(64, java.security.SecureRandom()),
            Date(now - 86_400_000L),
            Date(now + 3650L * 86_400_000L),
            name,
            pair.public
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        val holder = builder.build(contentSigner(pair.private))
        caCert = holder.toX509()
        caKey = pair.private
    }

    private fun issueHost(host: String): HostCreds {
        val ca = caCert ?: error("CA missing")
        val key = caKey ?: error("CA key missing")
        val pair = rsaKeyPair()
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(ca.subjectX500Principal.name),
            BigInteger(64, java.security.SecureRandom()),
            Date(now - 86_400_000L),
            Date(now + 825L * 86_400_000L),
            X500Name("CN=$host"),
            pair.public
        )
        builder.addExtension(Extension.basicConstraints, false, BasicConstraints(false))
        builder.addExtension(
            Extension.subjectAlternativeName,
            false,
            GeneralNames(GeneralName(GeneralName.dNSName, host))
        )
        val cert = builder.build(contentSigner(key)).toX509()
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("leaf", pair.private, KS_PASS.toCharArray(), arrayOf(cert, ca))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, KS_PASS.toCharArray())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        return HostCreds(cert, pair, ctx)
    }

    private fun rsaKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    /** Android already ships a stub JCE provider named BC — never pin BouncyCastle as "BC". */
    private fun contentSigner(key: PrivateKey) =
        JcaContentSignerBuilder("SHA256withRSA").build(key)

    private fun X509CertificateHolder.toX509(): X509Certificate {
        return try {
            JcaX509CertificateConverter().getCertificate(this)
        } catch (_: Exception) {
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
        }
    }

    private fun load(file: File) {
        val ks = KeyStore.getInstance("PKCS12")
        file.inputStream().use { ks.load(it, KS_PASS.toCharArray()) }
        caKey = ks.getKey("ca", KS_PASS.toCharArray()) as? PrivateKey
            ?: error("CA key missing in keystore")
        caCert = ks.getCertificate("ca") as? X509Certificate
            ?: error("CA cert missing in keystore")
    }

    private fun save(file: File) {
        val key = caKey ?: return
        val cert = caCert ?: return
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("ca", key, KS_PASS.toCharArray(), arrayOf(cert))
        file.outputStream().use { ks.store(it, KS_PASS.toCharArray()) }
    }

    private fun exportPem(context: Context) {
        val cert = caCert ?: return
        val pem = toPem(cert)
        File(context.filesDir, "mitm-ca.pem").writeText(pem)
        RootShell.execAndRead("mkdir -p ${FridaInstaller.BASE_DIR}")
        RootShell.execAndRead(
            "printf %s ${RootShell.shellQuote(pem)} > ${FridaInstaller.BASE_DIR}/mitm-ca.pem && chmod 644 ${FridaInstaller.BASE_DIR}/mitm-ca.pem"
        )
    }

    private fun toPem(cert: X509Certificate): String {
        val b64 = android.util.Base64.encodeToString(cert.encoded, android.util.Base64.DEFAULT)
        return "-----BEGIN CERTIFICATE-----\n$b64-----END CERTIFICATE-----\n"
    }

    /** OpenSSL subject_hash_old (first 4 bytes of MD5(subject DER), little-endian). */
    private fun opensslSubjectHashOld(cert: X509Certificate): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(cert.subjectX500Principal.encoded)
        val hash = (digest[0].toInt() and 0xff) or
            ((digest[1].toInt() and 0xff) shl 8) or
            ((digest[2].toInt() and 0xff) shl 16) or
            ((digest[3].toInt() and 0xff) shl 24)
        return String.format("%08x", hash)
    }

    private fun Exception.toUserMessage(): String {
        val cause = cause?.let { " (${it.javaClass.simpleName}: ${it.message})" } ?: ""
        return "${javaClass.simpleName}: ${message ?: "unknown"}$cause"
    }
}
