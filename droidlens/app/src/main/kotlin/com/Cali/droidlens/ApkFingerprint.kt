package com.Cali.droidlens

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object ApkFingerprint {

    data class SignerInfo(
        val subject: String,
        val issuer: String,
        val serial: String,
        val validFrom: String,
        val validTo: String,
        val signatureAlgorithm: String,
        val source: String
    )

    data class Fingerprint(
        val fileName: String,
        val sizeBytes: Long,
        val sha256: String,
        val md5: String,
        val signers: List<SignerInfo>,
        val signingNote: String?,
        val error: String? = null
    )

    fun compute(context: Context, apk: File): Fingerprint {
        // Stream hashes — no readBytes(), no OOM on big APKs
        val hashes: Pair<String, String>? = try {
            hashFile(apk)
        } catch (e: Throwable) {
            null
        }

        if (hashes == null) {
            return Fingerprint(
                fileName = apk.name,
                sizeBytes = apk.length(),
                sha256 = "—",
                md5 = "—",
                signers = emptyList(),
                signingNote = null,
                error = "Failed to hash APK (file may be too large or unreadable)"
            )
        }

        val (signers, note, signError) = try {
            readSigners(context, apk)
        } catch (e: Throwable) {
            Triple(
                emptyList<SignerInfo>(),
                null as String?,
                "Signing read failed: ${e::class.java.simpleName}: ${e.message}"
            )
        }

        return Fingerprint(
            fileName = apk.name,
            sizeBytes = apk.length(),
            sha256 = hashes.first,
            md5 = hashes.second,
            signers = signers,
            signingNote = note,
            error = signError
        )
    }

    /** Streams the file through both digests in one pass. */
    private fun hashFile(apk: File): Pair<String, String> {
        val sha = MessageDigest.getInstance("SHA-256")
        val md5 = MessageDigest.getInstance("MD5")
        val buf = ByteArray(8192)
        apk.inputStream().use { input ->
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                sha.update(buf, 0, n)
                md5.update(buf, 0, n)
            }
        }
        return hex(sha.digest()) to hex(md5.digest())
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun readSigners(
        context: Context,
        apk: File
    ): Triple<List<SignerInfo>, String?, String?> {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }

        val info: PackageInfo = pm.getPackageArchiveInfo(apk.absolutePath, flags)
            ?: return Triple(
                emptyList(),
                null,
                "PackageManager could not parse this APK (maybe a split APK or corrupted)"
            )

        val signers = mutableListOf<SignerInfo>()
        val seen = mutableSetOf<String>()

        // v2/v3 signing info (API 28+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val si: SigningInfo? = info.signingInfo
            if (si != null) {
                val source = if (si.hasMultipleSigners()) "v2/v3 multi-signer" else "v2/v3"
                val certs: Array<Signature> =
                    if (si.hasMultipleSigners()) si.apkContentsSigners ?: emptyArray()
                    else si.signingCertificateHistory ?: emptyArray()

                for (sig in certs) {
                    val x = toX509(sig) ?: continue
                    val subject = x.subjectDN.name
                    if (seen.add(subject)) {
                        signers.add(
                            SignerInfo(
                                subject = subject,
                                issuer = x.issuerDN.name,
                                serial = x.serialNumber.toString(16),
                                validFrom = x.notBefore.toString(),
                                validTo = x.notAfter.toString(),
                                signatureAlgorithm = x.sigAlgName,
                                source = source
                            )
                        )
                    }
                }
            }
        }

        // v1 fallback (also covers API 26–27 where signingInfo is unavailable)
        if (signers.isEmpty()) {
            @Suppress("DEPRECATION")
            val v1certs: Array<Signature>? = info.signatures
            if (v1certs != null) {
                for (sig in v1certs) {
                    val x = toX509(sig) ?: continue
                    val subject = x.subjectDN.name
                    if (seen.add(subject)) {
                        signers.add(
                            SignerInfo(
                                subject = subject,
                                issuer = x.issuerDN.name,
                                serial = x.serialNumber.toString(16),
                                validFrom = x.notBefore.toString(),
                                validTo = x.notAfter.toString(),
                                signatureAlgorithm = x.sigAlgName,
                                source = "v1"
                            )
                        )
                    }
                }
            }
        }

        val note = if (signers.isEmpty())
            "No signing certificates could be extracted."
        else null

        return Triple(signers, note, null)
    }

    private fun toX509(sig: Signature): X509Certificate? = try {
        val factory = CertificateFactory.getInstance("X.509")
        factory.generateCertificate(sig.toByteArray().inputStream()) as X509Certificate
    } catch (_: Throwable) { null }

    fun format(fp: Fingerprint): String = buildString {
        append("FILE\n")
        append("  ${fp.fileName}\n")
        append("  ${formatSize(fp.sizeBytes)}\n\n")

        append("HASHES\n")
        append("  SHA-256: ${fp.sha256}\n")
        append("  MD5:     ${fp.md5}\n\n")

        append("SIGNING\n")
        when {
            fp.error != null -> append("  ⚠ ${fp.error}\n")
            fp.signers.isEmpty() -> append("  ${fp.signingNote ?: "No signers found."}\n")
            else -> {
                for ((i, s) in fp.signers.withIndex()) {
                    append("  [Signer ${i + 1}]  (${s.source})\n")
                    append("  Subject: ${s.subject}\n")
                    append("  Issuer:  ${s.issuer}\n")
                    append("  Serial:  ${s.serial}\n")
                    append("  Valid:   ${s.validFrom} → ${s.validTo}\n")
                    append("  Algo:    ${s.signatureAlgorithm}\n")
                }
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