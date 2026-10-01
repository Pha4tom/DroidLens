package com.Cali.droidlens

import java.io.File
import java.util.zip.ZipFile

/**
 * Reads the APK's ZIP directory and produces a summary of what's inside.
 * Groups files by top-level folder (assets/, lib/, res/, etc.) and sorts
 * by total size so the biggest contributors show up first.
 */
object ApkFileList {

    data class FolderInfo(val fileCount: Int, val totalSize: Long)

    data class Summary(
        val totalFiles: Int,
        val totalSize: Long,
        val folders: List<Pair<String, FolderInfo>>,
        val topLevelFiles: List<Pair<String, Long>>
    )

    fun analyze(apk: File): Summary {
        val folders = mutableMapOf<String, FolderInfo>()
        val topLevel = mutableListOf<Pair<String, Long>>()
        var totalFiles = 0
        var totalSize = 0L

        ZipFile(apk).use { zip ->
            for (entry in zip.entries()) {
                if (entry.isDirectory) continue
                val size = entry.size.coerceAtLeast(0L)
                totalFiles++
                totalSize += size

                val slash = entry.name.indexOf('/')
                if (slash < 0) {
                    topLevel.add(entry.name to size)
                } else {
                    val folder = entry.name.substring(0, slash) + "/"
                    val existing = folders[folder] ?: FolderInfo(0, 0L)
                    folders[folder] = FolderInfo(existing.fileCount + 1, existing.totalSize + size)
                }
            }
        }

        return Summary(
            totalFiles = totalFiles,
            totalSize = totalSize,
            folders = folders.toList().sortedByDescending { it.second.totalSize },
            topLevelFiles = topLevel.sortedByDescending { it.second }
        )
    }

    fun format(s: Summary): String = buildString {
        append("${s.totalFiles} files · ${formatSize(s.totalSize)}\n\n")

        for ((name, info) in s.folders.take(20)) {
            val pct = if (s.totalSize > 0) (info.totalSize * 100 / s.totalSize) else 0
            append("  ${padRight(name, 20)} ${padLeft(info.fileCount.toString(), 5)} files  ")
            append("${padLeft(formatSize(info.totalSize), 10)}  ($pct%)\n")
        }

        if (s.topLevelFiles.isNotEmpty()) {
            append("\nRoot files:\n")
            for ((name, size) in s.topLevelFiles.take(15)) {
                append("  ${padRight(name, 30)} ${formatSize(size)}\n")
            }
        }
    }.trimEnd()

    private fun formatSize(bytes: Long): String {
        val kb = bytes / 1024.0
        val mb = kb / 1024.0
        return when {
            mb >= 1 -> "%.2f MB".format(mb)
            kb >= 1 -> "%.1f KB".format(kb)
            else -> "$bytes B"
        }
    }

    private fun padRight(s: String, n: Int): String =
        if (s.length >= n) s else s + " ".repeat(n - s.length)

    private fun padLeft(s: String, n: Int): String =
        if (s.length >= n) s else " ".repeat(n - s.length) + s
}