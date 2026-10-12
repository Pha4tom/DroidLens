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
 *
 * Note: anonymous inner classes (Outer$1, Outer$2, ...) are inlined by jadx
 * into the enclosing method. Asking for their `code` returns a trivial stub.
 * decompileClass() detects this and falls back to decompiling the outer class.
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
            return try { d.classes.size } catch (_: Throwable) { 0 }
        }
    }

    /**
     * Decompiles a single class by full name. Returns Java source (or a
     * diagnostic comment on failure).
     *
     * If `fullName` refers to an anonymous or nested inner class whose
     * standalone decompilation is trivial, this falls back to decompiling
     * the enclosing outer class and returns that instead, with a header
     * explaining the substitution.
     */
    fun decompileClass(fullName: String): String? {
        synchronized(lock) {
            val d: JadxDecompiler = decompiler ?: return null

            // ── Primary lookup ─────────────────────────────────────────────
            val rawCode = lookupRaw(d, fullName)

            if (rawCode == null) {
                return "// Class not found in jadx: $fullName\n" +
                        "// jadx loaded ${safeClassCount(d)} classes total\n" +
                        "// (If this is 1, the DEX input plugin did not load)"
            }

            // ── Inner-class fallback ───────────────────────────────────────
            // Anonymous classes (Outer$1, Outer$2) are inlined by jadx into
            // the enclosing method. The JavaClass object exists but its
            // `code` is an empty or near-empty stub. Detect that and offer
            // the outer class source instead, since that's where the real
            // body lives.
            if (fullName.contains('$') && isTrivialDecompile(rawCode)) {
                val outerName = fullName.substringBefore('$')
                val outerCode = lookupRaw(d, outerName)

                if (outerCode != null && !isTrivialDecompile(outerCode)) {
                    val shortInner = fullName.substringAfterLast('.')
                    val shortOuter = outerName.substringAfterLast('.')
                    return buildString {
                        append("// ⓘ Inner class: ").append(shortInner).append('\n')
                        append("//\n")
                        append("// Jadx inlines anonymous and certain nested classes into\n")
                        append("// their enclosing class. The body of this class lives inside\n")
                        append("// the decompilation of ").append(shortOuter).append(" below.\n")
                        append("//\n")
                        append("// Look for a `new ").append(shortInner).append("(...)` ")
                        append("or `class ").append(shortInner).append("` block.\n")
                        append("//\n")
                        append("// Enclosing class: ").append(outerName).append('\n')
                        append("// ─────────────────────────────────────────────────────\n\n")
                        append(outerCode)
                    }
                }

                // Outer also failed or is trivial — return what we have.
                return rawCode
            }

            return rawCode
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Attempts to resolve a class by name and return its decompiled source.
     * Returns null if not found. Does NOT do the inner-class fallback —
     * that's handled by decompileClass().
     */
    private fun lookupRaw(d: JadxDecompiler, fullName: String): String? {
        // Try `$` form, `.` form, and (rarely) `/` form.
        val candidates = LinkedHashSet<String>()
        candidates.add(fullName)
        if (fullName.contains('$')) {
            candidates.add(fullName.replace('$', '.'))
            candidates.add(fullName.replace('$', '/').replace('.', '/'))
        }

        for (candidate in candidates) {
            // 1. Canonical search by original full name
            try {
                val cls: JavaClass? = d.searchJavaClassByOrigFullName(candidate)
                if (cls != null) {
                    return safeCode(cls)
                }
            } catch (_: Throwable) { }

            // 2. Alias search — handles renamed / obfuscated entries
            try {
                val cls: JavaClass? = d.searchJavaClassByAliasFullName(candidate)
                if (cls != null) {
                    return safeCode(cls)
                }
            } catch (_: Throwable) { }
        }

        // 3. Manual scan with normalized comparison ($ vs . vs /)
        val primary: List<JavaClass> = try {
            d.classes
        } catch (_: Throwable) {
            emptyList()
        }

        val normalizedInput: String = fullName.replace('/', '.')
        val hit: JavaClass? = primary.firstOrNull { cls: JavaClass ->
            val fn = try { cls.fullName ?: "" } catch (_: Throwable) { "" }
            val rn = try { cls.rawName ?: "" } catch (_: Throwable) { "" }
            fn.replace('/', '.') == normalizedInput ||
                    rn.replace('/', '.') == normalizedInput
        }
        if (hit != null) {
            return safeCode(hit)
        }

        // 4. If it looks like an inner class, walk the outer's innerClasses list.
        val dollarIdx = fullName.indexOf('$')
        if (dollarIdx > 0) {
            val outerName = fullName.substring(0, dollarIdx)
            val innerPath = fullName.substring(dollarIdx + 1) // "a" or "a$b"

            val outer: JavaClass? = try {
                d.searchJavaClassByOrigFullName(outerName)
                    ?: d.searchJavaClassByAliasFullName(outerName)
            } catch (_: Throwable) { null }

            if (outer != null) {
                val direct: JavaClass? = try {
                    outer.innerClasses.firstOrNull { ic ->
                        val icFull = (ic.fullName ?: "").replace('/', '.')
                        icFull == normalizedInput ||
                                ic.name == innerPath ||
                                ic.name == innerPath.substringAfterLast('$')
                    }
                } catch (_: Throwable) { null }

                if (direct != null) {
                    return safeCode(direct)
                }
            }
        }

        return null
    }

    /** Wraps cls.code with a try/catch so one bad class doesn't crash the lookup. */
    private fun safeCode(cls: JavaClass): String {
        return try {
            cls.code ?: ""
        } catch (e: Throwable) {
            "// Decompilation failed: ${e::class.java.simpleName}: ${e.message}"
        }
    }

    /**
     * True if the decompiled output has no real body — empty, very short,
     * or consisting only of comments/blank lines/braces. This is what
     * jadx returns for anonymous inner classes.
     */
    private fun isTrivialDecompile(code: String): Boolean {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) return true
        val lines = trimmed.lines()
        // 3 lines or fewer → almost certainly a stub.
        if (lines.size <= 3) return true
        // Longer, but every line is a comment / blank / brace → also a stub.
        return lines.all { line ->
            val l = line.trim()
            l.isEmpty() ||
                    l.startsWith("//") ||
                    l.startsWith("*") ||
                    l.startsWith("/*") ||
                    l == "{" ||
                    l == "}"
        }
    }

    private fun safeClassCount(d: JadxDecompiler): Int =
        try { d.classes.size } catch (_: Throwable) { 0 }
}