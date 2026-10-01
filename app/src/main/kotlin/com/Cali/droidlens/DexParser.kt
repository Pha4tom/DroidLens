package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Extracts class names directly from DEX files in an APK.
 * No decompilation — just reads the DEX header tables.
 *
 * For multi-dex APKs, processes classes.dex, classes2.dex, etc.
 */
object DexParser {

    data class DexFileInfo(
        val fileName: String,
        val version: String,
        val classCount: Int,
        val classNames: List<String>
    )

    data class Summary(
        val dexFiles: List<DexFileInfo>,
        val totalClasses: Int,
        val topPackages: List<Pair<String, Int>>,
        val appClasses: List<String>
    )

    fun analyze(apk: File): Summary {
        val dexInfos = mutableListOf<DexFileInfo>()

        try {
            ZipFile(apk).use { zip ->
                val dexEntries = zip.entries().asSequence()
                    .filter { it.name.matches(Regex("classes\\d*\\.dex")) }
                    .sortedBy { it.name }
                    .toList()

                for (entry in dexEntries) {
                    try {
                        val bytes = zip.getInputStream(entry).readBytes()
                        val info = parseDex(bytes, entry.name)
                        if (info != null) dexInfos.add(info)
                    } catch (_: Throwable) { }
                }
            }
        } catch (_: Throwable) { }

        val totalClasses = dexInfos.sumOf { it.classCount }

        // Top-level package counts (first 2 segments)
        val pkgCounts = mutableMapOf<String, Int>()
        for (dex in dexInfos) {
            for (cls in dex.classNames) {
                val pkg = topPackage(cls)
                pkgCounts[pkg] = (pkgCounts[pkg] ?: 0) + 1
            }
        }
        val topPackages = pkgCounts.toList().sortedByDescending { it.second }

        // App-specific classes (exclude common library prefixes)
        val libraryPrefixes = listOf(
            "androidx.", "android.", "kotlin.", "kotlinx.", "com.google.",
            "com.android.", "org.jetbrains.", "org.intellij.", "org.chromium.",
            "com.facebook.", "io.reactivex.", "com.squareup.", "okhttp3.",
            "okio.", "retrofit2.", "com.bumptech.glide.", "dagger.",
            "javax.", "java.", "org.apache.", "com.amazon.", "com.unity3d."
        )

        val appClasses = mutableListOf<String>()
        for (dex in dexInfos) {
            for (cls in dex.classNames) {
                if (libraryPrefixes.none { cls.startsWith(it) }) {
                    appClasses.add(cls)
                    if (appClasses.size >= 200) break
                }
            }
            if (appClasses.size >= 200) break
        }

        return Summary(dexInfos, totalClasses, topPackages, appClasses)
    }

    // ---------- DEX parsing ----------

    private fun parseDex(data: ByteArray, fileName: String): DexFileInfo? {
        if (data.size < 112) return null

        val magic = String(data, 0, 8, Charsets.US_ASCII)
        if (!magic.startsWith("dex\n")) return null
        val version = magic.substring(4, 7)

        val stringIdsSize = u32(data, 56)
        val stringIdsOff  = u32(data, 60)
        val typeIdsSize   = u32(data, 64)
        val typeIdsOff    = u32(data, 68)
        val classDefsSize = u32(data, 96)
        val classDefsOff  = u32(data, 100)

        if (stringIdsOff < 0 || stringIdsSize <= 0) return null
        if (stringIdsOff + stringIdsSize * 4 > data.size) return null
        if (typeIdsOff + typeIdsSize * 4 > data.size) return null
        if (classDefsOff + classDefsSize * 32 > data.size) return null

        val stringOffsets = IntArray(stringIdsSize)
        for (i in 0 until stringIdsSize) {
            stringOffsets[i] = u32(data, stringIdsOff + i * 4)
        }

        val typeDescriptorIdx = IntArray(typeIdsSize)
        for (i in 0 until typeIdsSize) {
            typeDescriptorIdx[i] = u32(data, typeIdsOff + i * 4)
        }

        val classNames = ArrayList<String>(classDefsSize)
        for (i in 0 until classDefsSize) {
            val classDefOff = classDefsOff + i * 32
            val classIdx = u32(data, classDefOff)
            if (classIdx < 0 || classIdx >= typeIdsSize) continue
            val descriptorIdx = typeDescriptorIdx[classIdx]
            if (descriptorIdx < 0 || descriptorIdx >= stringIdsSize) continue
            val descriptor = readStringAt(data, stringOffsets[descriptorIdx]) ?: continue
            val cleaned = cleanDescriptor(descriptor)
            if (cleaned.isNotEmpty()) classNames.add(cleaned)
        }

        return DexFileInfo(fileName, version, classNames.size, classNames)
    }

    /** "Lcom/example/MainActivity;" → "com.example.MainActivity" */
    private fun cleanDescriptor(descriptor: String): String {
        var s = descriptor
        if (s.startsWith("L")) s = s.substring(1)
        if (s.endsWith(";")) s = s.substring(0, s.length - 1)
        return s.replace('/', '.')
    }

    /** "com.example.bet.ui.MainActivity" → "com.example" */
    private fun topPackage(className: String): String {
        val parts = className.split('.')
        return when {
            parts.size >= 2 -> "${parts[0]}.${parts[1]}"
            parts.isNotEmpty() -> parts[0]
            else -> "?"
        }
    }

    /** Reads a MUTF-8 / UTF-8 string at the given byte offset in the DEX data. */
    private fun readStringAt(data: ByteArray, offset: Int): String? {
        if (offset < 0 || offset >= data.size) return null
        var pos = offset

        // uleb128 length prefix
        var length = 0
        var shift = 0
        var bytesRead = 0
        while (true) {
            if (pos >= data.size || bytesRead >= 5) return null
            val b = data[pos].toInt() and 0xFF
            pos++
            length = length or ((b and 0x7F) shl shift)
            shift += 7
            bytesRead++
            if ((b and 0x80) == 0) break
        }
        if (pos + length > data.size) return null
        if (length > 4096) return null  // sanity cap

        return String(data, pos, length, Charsets.UTF_8)
    }

    private fun u32(data: ByteArray, off: Int): Int {
        if (off < 0 || off + 4 > data.size) return 0
        return (data[off].toInt() and 0xFF) or
               ((data[off + 1].toInt() and 0xFF) shl 8) or
               ((data[off + 2].toInt() and 0xFF) shl 16) or
               ((data[off + 3].toInt() and 0xFF) shl 24)
    }

    // ---------- Formatting ----------

    fun format(s: Summary): String = buildString {
        if (s.dexFiles.isEmpty()) {
            append("No DEX files found in this APK.")
            return@buildString
        }

        append("${s.dexFiles.size} dex file${if (s.dexFiles.size == 1) "" else "s"}")
        append(" · ")
        append("${s.totalClasses} classes\n\n")

        for (dex in s.dexFiles) {
            append("  ${padRight(dex.fileName, 20)} ${padLeft(dex.classCount.toString(), 6)} classes  ")
            append("(v${dex.version})\n")
        }

        if (s.topPackages.isNotEmpty()) {
            append("\nTop packages:\n")
            for ((pkg, count) in s.topPackages.take(15)) {
                append("  ${padRight(pkg, 35)} ${padLeft(count.toString(), 6)}\n")
            }
        }

        if (s.appClasses.isNotEmpty()) {
            append("\nApp classes (up to 200):\n")
            for (cls in s.appClasses.take(40)) {
                append("  $cls\n")
            }
            if (s.appClasses.size > 40) {
                append("  … and ${s.appClasses.size - 40} more\n")
            }
        }
    }.trimEnd()

    private fun padRight(s: String, n: Int): String =
        if (s.length >= n) s else s + " ".repeat(n - s.length)

    private fun padLeft(s: String, n: Int): String =
        if (s.length >= n) s else " ".repeat(n - s.length) + s
}