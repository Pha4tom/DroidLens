package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Extracts every string from every DEX file in an APK.
 * Uses the same MUTF-8 reader as DexParser but keeps all strings, not just class names.
 */
object StringExtractor {

    private const val MAX_DEX_BYTES = 100L * 1024 * 1024

    data class ExtractedStrings(
        val strings: List<String>,
        val dexFileCount: Int,
        val error: String? = null
    )

    fun extract(apk: File): ExtractedStrings {
        val all = HashSet<String>()
        var dexCount = 0

        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().asSequence()
                    .filter { it.name.matches(Regex("""classes\d*\.dex""")) }
                    .sortedBy { it.name }
                    .toList()

                for (entry in entries) {
                    try {
                        if (entry.size > MAX_DEX_BYTES) continue
                        val bytes = zip.getInputStream(entry).readBytes()
                        val strings = parseStrings(bytes)
                        for (s in strings) all.add(s)
                        dexCount++
                    } catch (_: Throwable) { }
                }
            }
        } catch (e: Throwable) {
            return ExtractedStrings(emptyList(), 0, "Extraction failed: ${e.message}")
        }

        return ExtractedStrings(all.toList(), dexCount)
    }

    private fun parseStrings(data: ByteArray): List<String> {
        if (data.size < 112) return emptyList()
        val magic = String(data, 0, 8, Charsets.US_ASCII)
        if (!magic.startsWith("dex\n")) return emptyList()

        val stringIdsSize = u32(data, 56)
        val stringIdsOff = u32(data, 60)

        if (stringIdsOff < 0L || stringIdsSize <= 0L) return emptyList()
        if (stringIdsOff + stringIdsSize * 4L > data.size) return emptyList()

        val count = stringIdsSize.coerceAtMost(500_000)
        val out = ArrayList<String>(count)

        for (i in 0 until count) {
            val off = u32(data, (stringIdsOff + i * 4L).toInt())
            if (off <= 0 || off >= data.size) continue
            val s = readStringAt(data, off) ?: continue
            if (s.isNotEmpty()) out.add(s)
        }
        return out
    }

    private fun readStringAt(data: ByteArray, offset: Int): String? {
        if (offset < 0 || offset >= data.size) return null
        var pos = offset

        // Skip uleb128 length
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
        } catch (_: Throwable) { null }
    }

    private fun u32(data: ByteArray, off: Int): Int {
        if (off < 0 || off + 4 > data.size) return 0
        return (data[off].toInt() and 0xFF) or
               ((data[off + 1].toInt() and 0xFF) shl 8) or
               ((data[off + 2].toInt() and 0xFF) shl 16) or
               ((data[off + 3].toInt() and 0xFF) shl 24)
    }
}