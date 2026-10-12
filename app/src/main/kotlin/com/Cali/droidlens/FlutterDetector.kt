package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Detects Flutter apps and extracts strings from the Dart AOT snapshot.
 * A Flutter APK has both libflutter.so and libapp.so in lib/.
 * libapp.so contains the compiled Dart code as a serialized snapshot.
 */
object FlutterDetector {

    data class FlutterInfo(
        val detected: Boolean,
        val libFlutterPresent: Boolean,
        val libAppPresent: Boolean,
        val libAppSize: Long,
        val libAppStrings: List<String>,
        val nativeArch: String?
    )

    fun analyze(apk: File): FlutterInfo {
        var libFlutterPresent = false
        var libAppPresent = false
        var libAppSize = 0L
        var nativeArch: String? = null
        val libAppStrings = mutableListOf<String>()

        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().asSequence()
                    .filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
                    .toList()

                for (entry in entries) {
                    val name = entry.name.substringAfterLast('/')
                    val arch = entry.name.split('/').getOrNull(1)

                    if (name == "libflutter.so") {
                        libFlutterPresent = true
                        if (nativeArch == null) nativeArch = arch
                    }
                    if (name == "libapp.so") {
                        libAppPresent = true
                        libAppSize = entry.size.coerceAtLeast(0L)
                        if (nativeArch == null) nativeArch = arch
                    }
                }

                // Extract strings from the first libapp.so found
                val libAppEntry = entries.firstOrNull { it.name.endsWith("/libapp.so") }
                if (libAppEntry != null) {
                    try {
                        val bytes = zip.getInputStream(libAppEntry).readBytes()
                        libAppStrings.addAll(extractStrings(bytes))
                    } catch (_: Throwable) { }
                }
            }
        } catch (_: Throwable) { }

        return FlutterInfo(
            detected = libFlutterPresent && libAppPresent,
            libFlutterPresent = libFlutterPresent,
            libAppPresent = libAppPresent,
            libAppSize = libAppSize,
            libAppStrings = libAppStrings,
            nativeArch = nativeArch
        )
    }

    private fun extractStrings(data: ByteArray): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        for (b in data) {
            val i = b.toInt() and 0xFF
            if (i in 0x20..0x7E) {
                sb.append(i.toChar())
                if (sb.length > 500) sb.setLength(0)
            } else {
                if (sb.length >= 6) out.add(sb.toString())
                sb.setLength(0)
            }
        }
        if (sb.length >= 6) out.add(sb.toString())
        return out
    }

    fun format(info: FlutterInfo): String {
        if (!info.detected) return "Not a Flutter app."

        val sizeText = if (info.libAppSize >= 1024 * 1024) {
            "%.2f MB".format(info.libAppSize / 1024.0 / 1024.0)
        } else {
            "%.1f KB".format(info.libAppSize / 1024.0)
        }

        return buildString {
            append("Dart AOT snapshot detected\n\n")
            append("  Architecture:  ${info.nativeArch ?: "unknown"}\n")
            append("  libflutter.so: ${if (info.libFlutterPresent) "present" else "missing"}\n")
            append("  libapp.so:     $sizeText\n")
            append("  Strings:       ${info.libAppStrings.size}\n")
        }.trimEnd()
    }
}