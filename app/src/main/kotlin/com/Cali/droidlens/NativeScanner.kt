package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Extracts printable strings from every native library (.so) inside an APK.
 * Same technique as the classic `strings` command — walk the binary and pull
 * sequences of printable ASCII bytes.
 */
object NativeScanner {

    private const val MIN_STRING_LEN = 6
    private const val MAX_STRING_LEN = 500

    data class NativeLib(
        val name: String,
        val arch: String,
        val sizeBytes: Long,
        val strings: List<String>
    )

    data class Summary(
        val libs: List<NativeLib>,
        val totalLibs: Int,
        val totalStrings: Int,
        val error: String? = null
    )

    fun analyze(apk: File): Summary {
        val libs = mutableListOf<NativeLib>()

        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().asSequence()
                    .filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
                    .sortedBy { it.name }
                    .toList()

                for (entry in entries) {
                    try {
                        val bytes = zip.getInputStream(entry).readBytes()
                        val strings = extractStrings(bytes)

                        val parts = entry.name.split('/')
                        val arch = if (parts.size >= 3) parts[1] else "unknown"
                        val libName = parts.lastOrNull() ?: entry.name

                        libs.add(
                            NativeLib(
                                name = libName,
                                arch = arch,
                                sizeBytes = entry.size.coerceAtLeast(0L),
                                strings = strings
                            )
                        )
                    } catch (_: Throwable) { }
                }
            }
        } catch (e: Throwable) {
            return Summary(emptyList(), 0, 0, "Native scan failed: ${e.message}")
        }

        val total = libs.sumOf { it.strings.size }
        return Summary(libs, libs.size, total)
    }

    private fun extractStrings(data: ByteArray): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        for (b in data) {
            val i = b.toInt() and 0xFF
            if (i in 0x20..0x7E) {
                sb.append(i.toChar())
                if (sb.length > MAX_STRING_LEN) {
                    sb.setLength(0)
                }
            } else {
                if (sb.length >= MIN_STRING_LEN) {
                    out.add(sb.toString())
                }
                sb.setLength(0)
            }
        }
        if (sb.length >= MIN_STRING_LEN) {
            out.add(sb.toString())
        }
        return out
    }

    fun format(s: Summary): String {
        if (s.error != null) return "Native scan failed: ${s.error}"
        if (s.libs.isEmpty()) return "No native libraries (.so) in this APK."

        return buildString {
            append("${s.libs.size} native lib${if (s.libs.size == 1) "" else "s"}")
            append(" · ${s.totalStrings} strings total\n\n")

            for (lib in s.libs) {
                val sizeText = if (lib.sizeBytes >= 1024 * 1024) {
                    "%.2f MB".format(lib.sizeBytes / 1024.0 / 1024.0)
                } else {
                    "%.1f KB".format(lib.sizeBytes / 1024.0)
                }
                append("  ${padRight(lib.name, 34)} ${padRight(lib.arch, 12)} ${padLeft(sizeText, 10)}  ${lib.strings.size} strings\n")
            }
        }.trimEnd()
    }

    /** Compact preview — first N libs only. */
    fun formatPreview(s: Summary, limit: Int = 6): String {
        if (s.error != null) return "Native scan failed: ${s.error}"
        if (s.libs.isEmpty()) return "No native libraries (.so) in this APK."

        return buildString {
            append("${s.libs.size} native lib${if (s.libs.size == 1) "" else "s"}")
            append(" · ${s.totalStrings} strings total\n\n")

            val shown = s.libs.take(limit)
            for (lib in shown) {
                val sizeText = if (lib.sizeBytes >= 1024 * 1024) {
                    "%.2f MB".format(lib.sizeBytes / 1024.0 / 1024.0)
                } else {
                    "%.1f KB".format(lib.sizeBytes / 1024.0)
                }
                append("  ${padRight(lib.name, 34)} ${padRight(lib.arch, 12)} ${padLeft(sizeText, 10)}  ${lib.strings.size} strings\n")
            }
            if (s.libs.size > limit) {
                append("  … and ${s.libs.size - limit} more libs\n")
            }
        }.trimEnd()
    }

    private fun padRight(s: String, n: Int): String =
        if (s.length >= n) s else s + " ".repeat(n - s.length)

    private fun padLeft(s: String, n: Int): String =
        if (s.length >= n) s else " ".repeat(n - s.length) + s
}