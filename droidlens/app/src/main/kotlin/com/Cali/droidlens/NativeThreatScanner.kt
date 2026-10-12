package com.Cali.droidlens

object NativeThreatScanner {

    data class Finding(
        val category: String,
        val libName: String,
        val match: String,
        val severity: FindingsEngine.Severity,
        val explanation: String
    )

    data class Summary(
        val findings: List<Finding>,
        val libsScanned: Int,
        val stringsScanned: Int
    )

    private data class Pattern(
        val category: String,
        val regex: Regex,
        val severity: FindingsEngine.Severity,
        val explanation: String
    )

    private val patterns = listOf(
        // ===== Instrumentation frameworks =====
        Pattern(
            "Frida",
            Regex("""(?i)frida[-_](agent|gadget|server)"""),
            FindingsEngine.Severity.CRITICAL,
            "Frida instrumentation framework referenced in native code. Used for dynamic hooking."
        ),
        Pattern(
            "Frida",
            Regex("""(?i)gum[-_]js[-_]loop|gadget[-_]load"""),
            FindingsEngine.Severity.CRITICAL,
            "Frida gadget loader strings present."
        ),
        Pattern(
            "Frida",
            Regex("""(?i)re\.frida"""),
            FindingsEngine.Severity.CRITICAL,
            "Frida Java namespace referenced."
        ),

        // ===== Debuggers =====
        Pattern(
            "Debugger",
            Regex("""(?i)gdbserver|lldb[-_]server|ida[-_]pro|radare2"""),
            FindingsEngine.Severity.HIGH,
            "Debugger or reverse-engineering tool strings in native code."
        ),

        // ===== Root / emulation detection =====
        Pattern(
            "Root Check",
            Regex("""(?i)/system/xbin/su|/system/bin/su|/su/bin/su|magisk"""),
            FindingsEngine.Severity.MEDIUM,
            "Root detection paths — app checks for rooted devices."
        ),
        Pattern(
            "Emulator Check",
            Regex("""(?i)goldfish|ranchu|genymotion|nox|bluestacks"""),
            FindingsEngine.Severity.LOW,
            "Emulator detection strings — app may behave differently on real devices."
        ),

        // ===== Anti-tamper =====
        Pattern(
            "Anti-Debug",
            Regex("""(?i)ptrace|isDebuggerConnected|anti[-_]?debug"""),
            FindingsEngine.Severity.MEDIUM,
            "Anti-debugging strings — app resists runtime analysis."
        ),

        // ===== Dynamic code loading =====
        Pattern(
            "Dynamic Loading",
            Regex("""(?i)dlopen|RegisterNatives|JNI_OnLoad"""),
            FindingsEngine.Severity.LOW,
            "Native JNI entry points — informational, common in every app."
        ),

        // ===== Crypto =====
        Pattern(
            "Crypto",
            Regex("""(?i)libssl|libcrypto|openssl"""),
            FindingsEngine.Severity.LOW,
            "Bundled OpenSSL — custom TLS stack."
        ),

        // ===== Shell execution =====
        Pattern(
            "Shell Exec",
            Regex("""(?i)/system/bin/sh|/system/bin/toybox|/system/bin/busybox"""),
            FindingsEngine.Severity.MEDIUM,
            "Shell binary references — app may execute shell commands."
        ),
    )

    fun scan(apk: java.io.File): Summary {
        val nativeSummary = NativeScanner.analyze(apk)
        val findings = mutableListOf<Finding>()
        var stringsScanned = 0

        for (lib in nativeSummary.libs) {
            for (s in lib.strings) {
                stringsScanned++
                if (s.length < 6 || s.length > 500) continue

                for (p in patterns) {
                    val match = p.regex.find(s) ?: continue
                    findings.add(
                        Finding(
                            category = p.category,
                            libName = lib.name,
                            match = match.value,
                            severity = p.severity,
                            explanation = p.explanation
                        )
                    )
                    break  // one pattern per string
                }
            }
        }

        return Summary(findings, nativeSummary.libs.size, stringsScanned)
    }

    fun format(s: Summary): String {
        if (s.findings.isEmpty()) {
            return "No native threats detected across ${s.libsScanned} libs " +
                    "(${s.stringsScanned} strings)."
        }

        val byCategory = s.findings.groupBy { it.category }
        return buildString {
            append("${s.findings.size} native signals across ${s.libsScanned} libs\n\n")
            for ((cat, list) in byCategory) {
                append("[${list.first().severity.label}] $cat\n")
                append("  ${list.first().explanation}\n")
                val uniqueLibs = list.map { it.libName }.distinct()
                for (libName in uniqueLibs.take(5)) {
                    append("  → $libName\n")
                }
                if (uniqueLibs.size > 5) {
                    append("  → and ${uniqueLibs.size - 5} more libs\n")
                }
                append("\n")
            }
        }.trimEnd()
    }

    /** Converts native findings into the main findings list. */
    fun toFindings(s: Summary): List<FindingsEngine.Finding> {
        val out = mutableListOf<FindingsEngine.Finding>()
        val byCategory = s.findings.groupBy { it.category }
        for ((cat, list) in byCategory) {
            out.add(
                FindingsEngine.Finding(
                    severity = list.first().severity,
                    title = "Native: $cat (${list.size} signals)",
                    detail = "${list.first().explanation} " +
                            "Found in ${list.map { it.libName }.distinct().size} lib(s).",
                    category = "Native"
                )
            )
        }
        return out
    }
}