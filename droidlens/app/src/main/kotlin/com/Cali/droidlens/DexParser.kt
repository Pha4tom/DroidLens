package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

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

    /** Safety cap — refuse to process dex files larger than this. */
    private const val MAX_DEX_BYTES = 100L * 1024 * 1024  // 100 MB

    fun analyze(apk: File): Summary {
        val dexInfos = mutableListOf<DexFileInfo>()

        try {
            ZipFile(apk).use { zip ->
                val dexEntries = zip.entries().asSequence()
                    .filter { it.name.matches(Regex("""classes\d*\.dex""")) }
                    .sortedBy { it.name }
                    .toList()

                for (entry in dexEntries) {
                    try {
                        if (entry.size > MAX_DEX_BYTES) continue
                        val bytes = zip.getInputStream(entry).readBytes()
                        val info = parseDex(bytes, entry.name)
                        if (info != null) dexInfos.add(info)
                    } catch (_: Throwable) { }
                }
            }
        } catch (_: Throwable) { }

        val totalClasses = dexInfos.sumOf { it.classCount }

        val pkgCounts = mutableMapOf<String, Int>()
        for (dex in dexInfos) {
            for (cls in dex.classNames) {
                val pkg = topPackage(cls)
                pkgCounts[pkg] = (pkgCounts[pkg] ?: 0) + 1
            }
        }
        val topPackages = pkgCounts.toList().sortedByDescending { it.second }

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
        val stringIdsOff = u32(data, 60)
        val typeIdsSize = u32(data, 64)
        val typeIdsOff = u32(data, 68)
        val classDefsSize = u32(data, 96)
        val classDefsOff = u32(data, 100)

        // Use Long math to avoid Int overflow on crafted DEX
        if (stringIdsOff < 0L || stringIdsSize <= 0L) return null
        if (stringIdsOff + stringIdsSize * 4L > data.size) return null
        if (typeIdsOff + typeIdsSize * 4L > data.size) return null
        if (classDefsOff + classDefsSize * 32L > data.size) return null

        // Cap how many entries we'll even attempt (Int cap — safe)
        val stringCount = stringIdsSize.coerceAtMost(500_000)
        val typeCount = typeIdsSize.coerceAtMost(500_000)
        val classDefsCount = classDefsSize.coerceAtMost(500_000)

        val stringOffsets = IntArray(stringCount)
        for (i in 0 until stringCount) {
            stringOffsets[i] = u32(data, (stringIdsOff + i * 4L).toInt())
        }

        val typeDescriptorIdx = IntArray(typeCount)
        for (i in 0 until typeCount) {
            typeDescriptorIdx[i] = u32(data, (typeIdsOff + i * 4L).toInt())
        }

        val classNames = ArrayList<String>(classDefsCount)
        for (i in 0 until classDefsCount) {
            val classDefOff = (classDefsOff + i * 32L).toInt()
            val classIdx = u32(data, classDefOff)
            if (classIdx < 0 || classIdx >= typeCount) continue
            val descriptorIdx = typeDescriptorIdx[classIdx]
            if (descriptorIdx < 0 || descriptorIdx >= stringCount) continue
            val descriptor = readStringAt(data, stringOffsets[descriptorIdx]) ?: continue
            val cleaned = cleanDescriptor(descriptor)
            if (cleaned.isNotEmpty()) classNames.add(cleaned)
        }

        return DexFileInfo(fileName, version, classNames.size, classNames)
    }

    private fun cleanDescriptor(descriptor: String): String {
        var s = descriptor
        if (s.startsWith("L")) s = s.substring(1)
        if (s.endsWith(";")) s = s.substring(0, s.length - 1)
        return s.replace('/', '.')
    }

    private fun topPackage(className: String): String {
        val parts = className.split('.')
        return when {
            parts.size >= 2 -> "${parts[0]}.${parts[1]}"
            parts.isNotEmpty() -> parts[0]
            else -> "?"
        }
    }

    /**
     * Reads a DEX string at the given offset.
     *
     * DEX uses MUTF-8 with a uleb128 length prefix. The length counts UTF-16
     * code units, NOT bytes — so we can't use it as a byte count. Instead we
     * read the uleb128, then read bytes until a null terminator (the actual
     * string terminator in DEX).
     */
    private fun readStringAt(data: ByteArray, offset: Int): String? {
        if (offset < 0 || offset >= data.size) return null
        var pos = offset

        // Read uleb128 length — we use it only as an upper bound
        var length = 0L
        var shift = 0
        var bytesRead = 0
        while (true) {
            if (pos >= data.size || bytesRead >= 5) return null
            val b = data[pos].toInt() and 0xFF
            pos++
            length = length or ((b and 0x7F).toLong() shl shift)
            shift += 7
            bytesRead++
            if ((b and 0x80) == 0) break
        }
        if (length < 0 || length > 1_000_000L) return null

        // Now find the actual byte range: skip the uleb128, read until null
        pos = offset
        var skip = 0
        while (skip < 5 && pos < data.size) {
            val b = data[pos].toInt() and 0xFF
            pos++
            skip++
            if ((b and 0x80) == 0) break
        }
        val byteStart = pos
        var byteEnd = pos
        while (byteEnd < data.size && data[byteEnd].toInt() != 0) {
            byteEnd++
            if (byteEnd - byteStart > 4_000_000) break
        }
        return try {
            String(data, byteStart, byteEnd - byteStart, Charsets.UTF_8)
        } catch (_: Throwable) {
            null
        }
    }

    private fun u32(data: ByteArray, off: Int): Int {
        if (off < 0 || off + 4 > data.size) return 0
        return (data[off].toInt() and 0xFF) or
               ((data[off + 1].toInt() and 0xFF) shl 8) or
               ((data[off + 2].toInt() and 0xFF) shl 16) or
               ((data[off + 3].toInt() and 0xFF) shl 24)
    }

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