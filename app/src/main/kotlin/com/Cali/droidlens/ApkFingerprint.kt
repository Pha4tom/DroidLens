package com.Cali.droidlens

import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.jar.JarFile

object ApkFingerprint {

    data class SignerInfo(
        val subject: String,
        val issuer: String,
        val serial: String,
        val validFrom: String,
        val validTo: String,
        val signatureAlgorithm: String
    )

    data class Fingerprint(
        val fileName: String,
        val sizeBytes: Long,
        val sha256: String,
        val md5: String,
        val signers: List<SignerInfo>,
        val signingNote: String?
    )

    fun compute(apk: File): Fingerprint {
        val bytes = apk.readBytes()
        val sha256 = hash(bytes, "SHA-256")
        val md5 = hash(bytes, "MD5")
        val (signers, note) = readSigners(apk)
        return Fingerprint(
            fileName = apk.name,
            sizeBytes = apk.length(),
            sha256 = sha256,
            md5 = md5,
            signers = signers,
            signingNote = note
        )
    }

    private fun hash(bytes: ByteArray, algo: String): String {
        val digest = MessageDigest.getInstance(algo).digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun readSigners(apk: File): Pair<List<SignerInfo>, String?> {
        return try {
            JarFile(apk, true).use { jar ->
                val signers = mutableListOf<SignerInfo>()
                val seen = mutableSetOf<String>()
                var found = false

                val entries = jar.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (!entry.name.startsWith("META-INF/")) continue
                    val n = entry.name
                    if (!(n.endsWith(".SF") || n.endsWith(".MF") || n.endsWith(".RSA")
                                || n.endsWith(".DSA") || n.endsWith(".EC"))) continue

                    jar.getInputStream(entry).use { input ->
                        val buf = ByteArray(8192)
                        while (input.read(buf) != -1) { /* drain */ }
                    }

                    val certs = entry.certificates ?: continue
                    for (cert in certs) {
                        if (cert is X509Certificate) {
                            val subject = cert.subjectDN.name
                            if (seen.add(subject)) {
                                signers.add(
                                    SignerInfo(
                                        subject = subject,
                                        issuer = cert.issuerDN.name,
                                        serial = cert.serialNumber.toString(16),
                                        validFrom = cert.notBefore.toString(),
                                        validTo = cert.notAfter.toString(),
                                        signatureAlgorithm = cert.sigAlgName
                                    )
                                )
                            }
                        }
                    }
                    found = true
                }

                when {
                    !found -> signers to "No JAR signature block found. APK may use v2/v3 signing only (not decoded)."
                    signers.isEmpty() -> signers to "Signature block present, but no X509 certs extracted."
                    else -> signers to null
                }
            }
        } catch (e: Throwable) {
            emptyList<SignerInfo>() to "Signature read failed: ${e.message}"
        }
    }

    fun format(fp: Fingerprint): String = buildString {
        append("FILE\n")
        append("  ${fp.fileName}\n")
        append("  ${formatSize(fp.sizeBytes)}\n\n")

        append("HASHES\n")
        append("  SHA-256: ${fp.sha256}\n")
        append("  MD5:     ${fp.md5}\n\n")

        append("SIGNING\n")
        if (fp.signers.isEmpty()) {
            append("  ${fp.signingNote ?: "No signers found."}\n")
        } else {
            for ((i, s) in fp.signers.withIndex()) {
                append("  [Signer ${i + 1}]\n")
                append("  Subject: ${s.subject}\n")
                append("  Issuer:  ${s.issuer}\n")
                append("  Serial:  ${s.serial}\n")
                append("  Valid:   ${s.validFrom} → ${s.validTo}\n")
                append("  Algo:    ${s.signatureAlgorithm}\n")
            }
        }
    }.trimEnd()

    private fun formatSize(bytes: Long): String {
        val kb = bytes / 1024.0
        val mb = kb / 1024.0
        return when {
            mb >= 1 -> "%.2f MB (%d bytes)".format(mb, bytes)
            kb >= 1 -> "%.1f KB (%d bytes)".format(kb, bytes)
            else -> "$bytes bytes"
        }
    }
}