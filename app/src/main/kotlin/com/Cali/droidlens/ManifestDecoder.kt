package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Minimal AndroidManifest.xml (AXML) decoder for APKs.
 * Reads the whole binary XML into memory, then walks the chunk structure.
 * Zero external dependencies.
 */
object ManifestDecoder {

    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_TYPE = 0x0003
    private const val RES_XML_START_NAMESPACE_TYPE = 0x0100
    private const val RES_XML_END_NAMESPACE_TYPE = 0x0101
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103
    private const val RES_XML_CDATA_TYPE = 0x0104

    private const val UTF8_FLAG = 0x00000100

    fun decode(apkFile: File): String {
        return try {
            ZipFile(apkFile).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml")
                    ?: return "AndroidManifest.xml not found in APK."
                val bytes = zip.getInputStream(entry).readBytes()
                parse(bytes)
            }
        } catch (e: Throwable) {
            "Decode failed: ${e::class.java.simpleName}\n${e.message}\n\n${e.stackTraceToString()}"
        }
    }

    // ---------- Little-endian byte readers ----------

    private fun u16(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

    private fun u32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
        ((b[off + 1].toInt() and 0xFF) shl 8) or
        ((b[off + 2].toInt() and 0xFF) shl 16) or
        ((b[off + 3].toInt() and 0xFF) shl 24)

    // ---------- Main parser ----------

    private fun parse(data: ByteArray): String {
        // XML header: u16 type, u16 headerSize, u32 chunkSize
        var pos = 0
        val fileType = u16(data, pos); pos += 2
        val fileHeaderSize = u16(data, pos); pos += 2
        pos += 4 // chunk size

        if (fileType != RES_XML_TYPE) {
            return "Not an AXML file (type=0x${Integer.toHexString(fileType)})"
        }
        if (fileHeaderSize != 8) {
            pos = fileHeaderSize
        }

        // String pool chunk
        val poolType = u16(data, pos)
        if (poolType != RES_STRING_POOL_TYPE) {
            return "Expected string pool, got 0x${Integer.toHexString(poolType)}"
        }
        val poolHeaderSize = u16(data, pos + 2)
        val poolChunkSize = u32(data, pos + 4)
        val stringCount = u32(data, pos + 8)
        val styleCount = u32(data, pos + 12)
        val flags = u32(data, pos + 16)
        val stringsStart = u32(data, pos + 20)
        // stylesStart at pos+24

        val isUtf8 = (flags and UTF8_FLAG) != 0

        val offsetsBase = pos + poolHeaderSize
        val stringDataBase = pos + stringsStart

        val offsets = IntArray(stringCount)
        for (i in 0 until stringCount) {
            offsets[i] = u32(data, offsetsBase + i * 4)
        }

        val pool = Array(stringCount) { i ->
            val off = stringDataBase + offsets[i]
            if (isUtf8) readUtf8(data, off) else readUtf16(data, off)
        }

        // Advance past the string pool
        pos += poolChunkSize

        // Walk subsequent chunks
        val sb = StringBuilder()
        sb.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")

        val indentStack = ArrayDeque<String>()

        while (pos + 8 <= data.size) {
            val chunkType = u16(data, pos)
            val chunkHeaderSize = u16(data, pos + 2)
            val chunkSize = u32(data, pos + 4)

            if (chunkSize <= 0) break

            when (chunkType) {
                RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE -> {
                    // Skip
                }

                RES_XML_START_ELEMENT_TYPE -> {
                    val nameIdx = u32(data, pos + 20)
                    val name = pool.getOrNull(nameIdx) ?: "?"
                    val attrCount = u16(data, pos + 28)
                    val attrStart = u16(data, pos + 24)
                    val attrBase = pos + chunkHeaderSize + attrStart

                    val indent = "  ".repeat(indentStack.size)
                    sb.append(indent).append("<").append(name)

                    for (i in 0 until attrCount) {
                        val aOff = attrBase + i * 20
                        val aNameIdx = u32(data, aOff + 4)
                        val aRawIdx = u32(data, aOff + 8)
                        val aType = data[aOff + 15].toInt() and 0xFF
                        val aData = u32(data, aOff + 16)

                        val aName = pool.getOrNull(aNameIdx) ?: "?"
                        val aValue = when {
                            aRawIdx >= 0 && aRawIdx < pool.size && pool[aRawIdx] != null ->
                                pool[aRawIdx]!!
                            aType == 0x03 -> pool.getOrNull(aData) ?: "0x${Integer.toHexString(aData)}"
                            aType == 0x12 -> if (aData != 0) "true" else "false"
                            else -> "0x${Integer.toHexString(aData)}"
                        }
                        sb.append(" ").append(aName).append("=\"").append(aValue).append("\"")
                    }
                    sb.append(">\n")
                    indentStack.addLast(name)
                }

                RES_XML_END_ELEMENT_TYPE -> {
                    val nameIdx = u32(data, pos + 20)
                    val name = pool.getOrNull(nameIdx) ?: "?"
                    if (indentStack.isNotEmpty()) indentStack.removeLast()
                    val indent = "  ".repeat(indentStack.size)
                    sb.append(indent).append("</").append(name).append(">\n")
                }

                RES_XML_CDATA_TYPE -> { /* skip */ }

                else -> { /* skip unknown chunks */ }
            }

            pos += chunkSize
        }

        return sb.toString()
    }

    // ---------- String readers ----------

    private fun readUtf8(b: ByteArray, offset: Int): String {
    var pos = offset
    if (pos >= b.size) return ""
    var len = b[pos].toInt() and 0xFF
    pos++
    if ((len and 0x80) != 0) {
        if (pos >= b.size) return ""
        len = ((len and 0x7F) shl 8) or (b[pos].toInt() and 0xFF)
        pos++
    }
    if (pos >= b.size) return ""
    var byteLen = b[pos].toInt() and 0xFF
    pos++
    if ((byteLen and 0x80) != 0) {
        if (pos >= b.size) return ""
        byteLen = ((byteLen and 0x7F) shl 8) or (b[pos].toInt() and 0xFF)
        pos++
    }
    if (pos + byteLen > b.size) return ""
    return String(b, pos, byteLen, Charsets.UTF_8)
}

private fun readUtf16(b: ByteArray, offset: Int): String {
    var pos = offset
    if (pos + 2 > b.size) return ""
    // AXML length prefix is LITTLE-ENDIAN, not big-endian.
    var len = (b[pos].toInt() and 0xFF) or ((b[pos + 1].toInt() and 0xFF) shl 8)
    pos += 2
    if ((len and 0x8000) != 0) {
        if (pos + 2 > b.size) return ""
        len = ((len and 0x7FFF) shl 16) or
                (b[pos].toInt() and 0xFF) or
                ((b[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2
    }
    val byteCount = len * 2
    if (pos + byteCount > b.size) return ""
    return String(b, pos, byteCount, Charsets.UTF_16LE)
}
}