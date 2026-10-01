package com.Cali.droidlens

import jadx.api.JadxArgs
import jadx.api.JadxDecompiler
import jadx.api.JavaClass
import java.io.File

/**
 * Singleton that holds one jadx decompiler instance for the currently loaded APK.
 * Loading an APK takes 5-30 seconds — we only do it once per APK.
 *
 * Requires jadx-dex-input to be on the classpath, otherwise jadx will only
 * see the R class from resources.arsc and none of the actual DEX classes.
 */
object JadxHolder {

    private var currentApkPath: String? = null
    private var decompiler: JadxDecompiler? = null
    private val lock = Any()

    class LoadResult(
        val decompiler: JadxDecompiler?,
        val error: String?,
        val alreadyLoaded: Boolean
    )

    fun ensureLoaded(apk: File): LoadResult {
        synchronized(lock) {
            val path = apk.absolutePath

            if (decompiler != null && currentApkPath == path) {
                return LoadResult(decompiler, null, true)
            }

            releaseLocked()

            return try {
                val args = JadxArgs().apply {
                    inputFiles.add(apk)
                    isSkipResources = true
                    isSkipSources = false
                    setShowInconsistentCode(false)
                    threadsCount = 2
                }
                val d = JadxDecompiler(args)
                d.load()
                decompiler = d
                currentApkPath = path
                LoadResult(d, null, false)
            } catch (e: OutOfMemoryError) {
                releaseLocked()
                LoadResult(null, "Out of memory while loading DEX. Try a smaller APK.", false)
            } catch (e: Throwable) {
                releaseLocked()
                LoadResult(null, "jadx load failed: ${e::class.java.simpleName}: ${e.message}", false)
            }
        }
    }

    fun release() {
        synchronized(lock) { releaseLocked() }
    }

    private fun releaseLocked() {
        try { decompiler?.close() } catch (_: Throwable) { }
        decompiler = null
        currentApkPath = null
    }

    /** Returns the APK path currently loaded by jadx, or null. */
    fun currentPath(): String? = currentApkPath

    /**
     * Number of classes jadx currently sees. Useful for diagnostics.
     * If this returns 1 and the only class is "...R", the DEX input
     * plugin did not load.
     */
    fun loadedClassCount(): Int {
        synchronized(lock) {
            val d = decompiler ?: return 0
            return try { d.getClasses().size } catch (_: Throwable) { 0 }
        }
    }

    /**
     * Decompiles a single class by full name. Returns Java source or null.
     *
     * Tries multiple lookup strategies because the Android fork of jadx behaves
     * differently from the desktop version.
     */
    fun decompileClass(fullName: String): String? {
        synchronized(lock) {
            val d: JadxDecompiler = decompiler ?: return null

            // 1. Canonical search by original full name
            try {
                val cls: JavaClass? = d.searchJavaClassByOrigFullName(fullName)
                if (cls != null) {
                    return try {
                        cls.code
                    } catch (e: Throwable) {
                        "// Decompilation failed: ${e::class.java.simpleName}: ${e.message}"
                    }
                }
            } catch (_: Throwable) { }

            // 2. Alias search — handles renamed / obfuscated entries
            try {
                val cls: JavaClass? = d.searchJavaClassByAliasFullName(fullName)
                if (cls != null) {
                    return try {
                        cls.code
                    } catch (e: Throwable) {
                        "// Decompilation failed: ${e::class.java.simpleName}: ${e.message}"
                    }
                }
            } catch (_: Throwable) { }

            // 3. Iterate the cache as a last resort
            val primary: List<JavaClass> = try {
                d.getClasses()
            } catch (_: Throwable) {
                emptyList()
            }
            val hit: JavaClass? = primary.firstOrNull { it.fullName == fullName }
            if (hit != null) {
                return try {
                    hit.code
                } catch (e: Throwable) {
                    "// Decompilation failed: ${e::class.java.simpleName}: ${e.message}"
                }
            }

            // 4. Give up — report cache size so we can diagnose
            return "// Class not found in jadx: $fullName\n" +
                    "// jadx loaded ${primary.size} classes total\n" +
                    "// (If this is 1, the DEX input plugin did not load)"
        }
    }
}