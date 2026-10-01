package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Parses resources.arsc and builds a map of resource ID → string value.
 * Best-effort: if parsing fails, returns whatever was collected so far.
 */
object ResourcesDecoder {

    private const val RES_STRING_POOL = 0x0001
    private const val RES_TABLE = 0x0002
    private const val RES_TABLE_PACKAGE = 0x0200
    private const val RES_TABLE_TYPE = 0x0201

    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int) = u8(b, i) or (u8(b, i + 1) shl 8)
    private fun u32(b: ByteArray, i: Int) =
        u8(b, i) or (u8(b, i + 1) shl 8) or (u8(b, i + 2) shl 16) or (u8(b, i + 3) shl 24)

    fun buildMap(apk: File): Map<Int, String> {
        val out = HashMap<Int, String>()
        try {
            ZipFile(apk).use { zip ->
                val entry = zip.getEntry("resources.arsc") ?: return out
                val bytes = zip.getInputStream(entry).readBytes()
                parseTable(bytes, out)
            }
        } catch (_: Throwable) { }
        return out
    }

    private fun parseTable(data: ByteArray, out: MutableMap<Int, String>) {
        if (data.size < 12) return
        if (u16(data, 0) != RES_TABLE) return
        var pos = u16(data, 2)
        var globalPool: List<String?> = emptyList()

        while (pos + 8 <= data.size) {
            val ct = u16(data, pos)
            val cs = u32(data, pos + 4)
            if (cs <= 0 || pos + cs > data.size) break
            when (ct) {
                RES_STRING_POOL -> globalPool = parseStringPool(data, pos)
                RES_TABLE_PACKAGE -> parsePackage(data, pos, globalPool, out)
            }
            pos += cs
        }
    }

    private fun parseStringPool(data: ByteArray, base: Int): List<String?> {
        val headerSize = u16(data, base + 2)
        val stringCount = u32(data, base + 8)
        val flags = u32(data, base + 16)
        val stringsStart = u32(data, base + 20)
        val isUtf8 = (flags and 0x100) != 0
        val offsetsBase = base + headerSize
        val dataBase = base + stringsStart

        val list = arrayOfNulls<String>(stringCount)
        for (i in 0 until stringCount) {
            val off = u32(data, offsetsBase + i * 4)
            list[i] = try {
                if (isUtf8) readUtf8(data, dataBase + off)
                else readUtf16(data, dataBase + off)
            } catch (_: Throwable) { null }
        }
        return list.toList()
    }

    private fun readUtf8(b: ByteArray, off: Int): String {
        var pos = off
        var len = u8(b, pos); pos++
        if ((len and 0x80) != 0) { len = ((len and 0x7F) shl 8) or u8(b, pos); pos++ }
        var byteLen = u8(b, pos); pos++
        if ((byteLen and 0x80) != 0) { byteLen = ((byteLen and 0x7F) shl 8) or u8(b, pos); pos++ }
        return String(b, pos, byteLen, Charsets.UTF_8)
    }

    private fun readUtf16(b: ByteArray, off: Int): String {
        var pos = off
        var len = u16(b, pos); pos += 2
        if ((len and 0x8000) != 0) { len = ((len and 0x7FFF) shl 16) or u16(b, pos); pos += 2 }
        return String(b, pos, len * 2, Charsets.UTF_16LE)
    }

    private fun parsePackage(
        data: ByteArray,
        pkgBase: Int,
        globalPool: List<String?>,
        out: MutableMap<Int, String>
    ) {
        val headerSize = u16(data, pkgBase + 2)
        val chunkSize = u32(data, pkgBase + 4)
        val pkgId = u32(data, pkgBase + 8)
        val typeStringsOff = u32(data, pkgBase + 12 + 256)
        val keyStringsOff = u32(data, pkgBase + 12 + 256 + 8)

        // Advance past the two inner string pools
        val typePoolSize = u32(data, pkgBase + typeStringsOff + 4)
        val keyPoolSize = u32(data, pkgBase + keyStringsOff + 4)
        var pos = pkgBase + maxOf(typeStringsOff + typePoolSize, keyStringsOff + keyPoolSize)
        if (pos < pkgBase + headerSize) pos = pkgBase + headerSize

        val pkgEnd = pkgBase + chunkSize

        while (pos + 8 <= pkgEnd && pos + 8 <= data.size) {
            val ct = u16(data, pos)
            val cs = u32(data, pos + 4)
            if (cs <= 0 || pos + cs > data.size) break
            if (ct == RES_TABLE_TYPE) {
                try { parseTypeChunk(data, pos, pkgId, globalPool, out) } catch (_: Throwable) { }
            }
            pos += cs
        }
    }

    private fun parseTypeChunk(
        data: ByteArray,
        base: Int,
        pkgId: Int,
        globalPool: List<String?>,
        out: MutableMap<Int, String>
    ) {
        val headerSize = u16(data, base + 2)
        val typeId = u8(data, base + 8)
        val entryCount = u32(data, base + 12)
        val entriesStart = u32(data, base + 16)

        val offsetsBase = base + headerSize
        val entriesBase = base + entriesStart

        for (i in 0 until entryCount) {
            val entryOff = u32(data, offsetsBase + i * 4)
            if (entryOff == -1) continue  // NO_ENTRY
            val entryPos = entriesBase + entryOff
            if (entryPos + 16 > data.size) continue

            val entryFlags = u16(data, entryPos + 2)
            val isComplex = (entryFlags and 0x0001) != 0
            if (isComplex) continue

            val valuePos = entryPos + 8
            if (valuePos + 8 > data.size) continue

            val valueType = u8(data, valuePos + 3)
            val valueData = u32(data, valuePos + 4)

            val resId = (pkgId shl 24) or (typeId shl 16) or i
            val decoded = when (valueType) {
                TYPE_STRING -> globalPool.getOrNull(valueData)
                TYPE_INT_DEC -> valueData.toString()
                TYPE_INT_HEX -> "0x${Integer.toHexString(valueData)}"
                TYPE_INT_BOOLEAN -> if (valueData != 0) "true" else "false"
                else -> null
            } ?: continue

            if (!out.containsKey(resId)) out[resId] = decoded
        }
    }
}