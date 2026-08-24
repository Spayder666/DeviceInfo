package com.deviceinfo.trafficmonitor.mitm

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** X.509 CA/leaf без BouncyCastle и без PKCS12 — только Android Signature + DER. */
object X509Mint {
    private val OID_RSA = intArrayOf(1, 2, 840, 113549, 1, 1, 1)
    private val OID_SHA256_RSA = intArrayOf(1, 2, 840, 113549, 1, 1, 11)
    private val OID_CN = intArrayOf(2, 5, 4, 3)
    private val OID_BASIC = intArrayOf(2, 5, 29, 19)
    private val OID_KEY_USAGE = intArrayOf(2, 5, 29, 15)
    private val OID_SAN = intArrayOf(2, 5, 29, 17)

    fun rsaKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    fun selfSignedCa(pair: KeyPair, cn: String = "AccessMonitor MITM CA", days: Long = 3650): X509Certificate {
        val now = System.currentTimeMillis()
        return signCert(
            issuerCn = cn,
            subjectCn = cn,
            subjectPublic = pair.public.encoded,
            signer = pair.private,
            serial = BigInteger(64, java.security.SecureRandom()),
            notBefore = now - 86_400_000L,
            notAfter = now + days * 86_400_000L,
            ca = true,
            sanHost = null
        )
    }

    fun issueHost(
        caCert: X509Certificate,
        caKey: PrivateKey,
        hostPair: KeyPair,
        host: String,
        days: Long = 825
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val issuerCn = cnFrom(caCert.subjectX500Principal.name) ?: "AccessMonitor MITM CA"
        return signCert(
            issuerCn = issuerCn,
            subjectCn = host,
            subjectPublic = hostPair.public.encoded,
            signer = caKey,
            serial = BigInteger(64, java.security.SecureRandom()),
            notBefore = now - 86_400_000L,
            notAfter = now + days * 86_400_000L,
            ca = false,
            sanHost = host
        )
    }

    fun parseCertificate(pemOrDer: ByteArray): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        val der = if (pemOrDer.isPem()) decodePem(String(pemOrDer, Charsets.US_ASCII)) else pemOrDer
        return cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    fun parsePrivateKey(pem: String): PrivateKey {
        val der = decodePem(pem)
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der))
    }

    fun certToPem(cert: X509Certificate): String = toPem("CERTIFICATE", cert.encoded)

    fun keyToPem(key: PrivateKey): String = toPem("PRIVATE KEY", key.encoded)

    private fun signCert(
        issuerCn: String,
        subjectCn: String,
        subjectPublic: ByteArray,
        signer: PrivateKey,
        serial: BigInteger,
        notBefore: Long,
        notAfter: Long,
        ca: Boolean,
        sanHost: String?
    ): X509Certificate {
        val tbs = derSequence(
            derContext(0, derInteger(BigInteger.TWO)),
            derInteger(serial),
            algorithmId(OID_SHA256_RSA),
            name(issuerCn),
            derSequence(utcTime(notBefore), utcTime(notAfter)),
            name(subjectCn),
            subjectPublic,
            derContext(3, derSequence(*extensions(ca, sanHost)))
        )
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(signer)
        sig.update(tbs)
        val signed = derSequence(tbs, algorithmId(OID_SHA256_RSA), derBitString(sig.sign()))
        return parseCertificate(signed)
    }

    private fun extensions(ca: Boolean, sanHost: String?): Array<ByteArray> {
        val basic = if (ca) byteArrayOf(0x30, 0x03, 0x01, 0x01, 0xFF.toByte()) else byteArrayOf(0x30, 0x00)
        val usage = if (ca) {
            derBitString(byteArrayOf(0x06), unused = 1)
        } else {
            derBitString(byteArrayOf(0xA0.toByte()), unused = 5)
        }
        val list = mutableListOf(
            extension(OID_BASIC, critical = true, value = basic),
            extension(OID_KEY_USAGE, critical = true, value = usage)
        )
        if (!sanHost.isNullOrBlank()) {
            val dns = derContext(2, sanHost.toByteArray(Charsets.US_ASCII), implicit = true)
            list += extension(OID_SAN, critical = false, value = derSequence(dns))
        }
        return list.toTypedArray()
    }

    private fun extension(oid: IntArray, critical: Boolean, value: ByteArray): ByteArray {
        val parts = mutableListOf(derOid(oid))
        if (critical) parts += derBoolean(true)
        parts += derOctet(value)
        return derSequence(*parts.toTypedArray())
    }

    private fun name(cn: String): ByteArray {
        val attr = derSequence(derOid(OID_CN), derUtf8(cn))
        val rdn = derSet(attr)
        return derSequence(rdn)
    }

    private fun algorithmId(oid: IntArray): ByteArray =
        derSequence(derOid(oid), byteArrayOf(0x05, 0x00))

    private fun utcTime(ms: Long): ByteArray {
        val fmt = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val s = fmt.format(Date(ms)).toByteArray(Charsets.US_ASCII)
        return der(0x17, s)
    }

    private fun cnFrom(dn: String): String? =
        Regex("CN=([^,]+)").find(dn)?.groupValues?.get(1)?.trim()

    private fun derBoolean(value: Boolean) = byteArrayOf(0x01, 0x01, if (value) 0xFF.toByte() else 0x00)
    private fun derInteger(n: BigInteger) = der(0x02, n.toByteArray())
    private fun derUtf8(s: String) = der(0x0C, s.toByteArray(Charsets.UTF_8))
    private fun derOctet(data: ByteArray) = der(0x04, data)
    private fun derBitString(data: ByteArray, unused: Int = 0) = der(0x03, byteArrayOf(unused.toByte()) + data)
    private fun derOid(parts: IntArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(parts[0] * 40 + parts[1])
        for (i in 2 until parts.size) writeBase128(out, parts[i])
        return der(0x06, out.toByteArray())
    }

    private fun derSequence(vararg items: ByteArray) = der(0x30, items.fold(ByteArray(0)) { a, b -> a + b })
    private fun derSet(vararg items: ByteArray) = der(0x31, items.fold(ByteArray(0)) { a, b -> a + b })

    private fun derContext(tag: Int, data: ByteArray, implicit: Boolean = false): ByteArray {
        val t = (if (implicit) 0x80 else 0xA0) or (tag and 0x1F)
        return der(t, data)
    }

    private fun der(tag: Int, body: ByteArray): ByteArray {
        val len = derLength(body.size)
        return byteArrayOf(tag.toByte()) + len + body
    }

    private fun derLength(size: Int): ByteArray = when {
        size < 0x80 -> byteArrayOf(size.toByte())
        size <= 0xFF -> byteArrayOf(0x81.toByte(), size.toByte())
        else -> byteArrayOf(0x82.toByte(), (size shr 8).toByte(), size.toByte())
    }

    private fun writeBase128(out: ByteArrayOutputStream, value: Int) {
        val stack = ArrayDeque<Int>()
        var v = value
        stack.addFirst(v and 0x7F)
        v = v ushr 7
        while (v > 0) {
            stack.addFirst((v and 0x7F) or 0x80)
            v = v ushr 7
        }
        stack.forEach { out.write(it) }
    }

    private fun ByteArray.isPem(): Boolean =
        String(this, Charsets.US_ASCII).contains("BEGIN ")

    private fun decodePem(pem: String): ByteArray {
        val b64 = pem.lineSequence()
            .filter { !it.startsWith("-----") && it.isNotBlank() }
            .joinToString("")
        return java.util.Base64.getMimeDecoder().decode(b64)
    }

    private fun toPem(type: String, der: ByteArray): String {
        val b64 = java.util.Base64.getMimeEncoder(64, byteArrayOf('\n'.code.toByte())).encodeToString(der).trim()
        return "-----BEGIN $type-----\n$b64\n-----END $type-----\n"
    }
}
