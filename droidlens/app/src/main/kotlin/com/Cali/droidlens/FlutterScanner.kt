package com.Cali.droidlens

object FlutterScanner {

    data class Finding(
        val category: String,
        val match: String,
        val severity: FindingsEngine.Severity,
        val explanation: String
    )

    data class Summary(
        val findings: List<Finding>,
        val totalStrings: Int,
        val detected: Boolean
    )

    private data class Pattern(
        val category: String,
        val regex: Regex,
        val severity: FindingsEngine.Severity,
        val explanation: String
    )

    private val patterns = listOf(
        // ===== Dart packages — tell you what the app is built with =====
        Pattern(
            "Package: crypto",
            Regex("""package:crypto/"""),
            FindingsEngine.Severity.LOW,
            "Flutter crypto package — hashing / HMAC / AES primitives"
        ),
        Pattern(
            "Package: dio",
            Regex("""package:dio/"""),
            FindingsEngine.Severity.LOW,
            "Dio HTTP client — custom network stack"
        ),
        Pattern(
            "Package: http",
            Regex("""package:http/"""),
            FindingsEngine.Severity.LOW,
            "Standard Flutter HTTP client"
        ),
        Pattern(
            "Package: flutter_secure_storage",
            Regex("""package:flutter_secure_storage/"""),
            FindingsEngine.Severity.MEDIUM,
            "Uses secure keychain storage for sensitive data"
        ),
        Pattern(
            "Package: shared_preferences",
            Regex("""package:shared_preferences/"""),
            FindingsEngine.Severity.LOW,
            "Uses plain-text SharedPreferences"
        ),
        Pattern(
            "Package: webview_flutter",
            Regex("""package:webview_flutter/"""),
            FindingsEngine.Severity.MEDIUM,
            "Flutter WebView — can load arbitrary web content"
        ),
        Pattern(
            "Package: firebase",
            Regex("""package:firebase_[a-z_]+/"""),
            FindingsEngine.Severity.LOW,
            "Firebase SDK bundled"
        ),
        Pattern(
            "Package: url_launcher",
            Regex("""package:url_launcher/"""),
            FindingsEngine.Severity.LOW,
            "Can launch external apps and URLs"
        ),
        Pattern(
            "Package: path_provider",
            Regex("""package:path_provider/"""),
            FindingsEngine.Severity.INFO,
            "Filesystem access helper"
        ),

        // ===== Runtime capabilities =====
        Pattern(
            "Native Bridge (dart:ffi)",
            Regex("""dart:ffi"""),
            FindingsEngine.Severity.MEDIUM,
            "Uses Dart FFI to call native code directly — bypasses Dart sandbox"
        ),
        Pattern(
            "Platform Channel",
            Regex("""MethodChannel|EventChannel|BasicMessageChannel"""),
            FindingsEngine.Severity.INFO,
            "Communicates with native Android layer via platform channels"
        ),
        Pattern(
            "Isolate Usage",
            Regex("""dart:isolate"""),
            FindingsEngine.Severity.INFO,
            "Runs background isolates (threads)"
        ),
    )

    fun scan(info: FlutterDetector.FlutterInfo): Summary {
        if (!info.detected) {
            return Summary(emptyList(), 0, false)
        }

        val found = mutableListOf<Finding>()
        val seenCategories = mutableSetOf<String>()

        for (s in info.libAppStrings) {
            for (p in patterns) {
                if (seenCategories.contains(p.category)) continue
                val match = p.regex.find(s) ?: continue
                found.add(
                    Finding(
                        category = p.category,
                        match = match.value,
                        severity = p.severity,
                        explanation = p.explanation
                    )
                )
                seenCategories.add(p.category)
                break
            }
        }

        return Summary(
            findings = found.sortedBy { it.severity.ordinal },
            totalStrings = info.libAppStrings.size,
            detected = true
        )
    }

    fun format(s: Summary): String {
        if (!s.detected) return "Not a Flutter app."
        if (s.findings.isEmpty()) {
            return "No Flutter-specific signals detected across ${s.totalStrings} strings."
        }

        return buildString {
            append("${s.findings.size} Flutter signals from ${s.totalStrings} strings\n\n")
            for (f in s.findings) {
                append("[${f.severity.label}]  ${f.category}\n")
                append("         ${f.explanation}\n\n")
            }
        }.trimEnd()
    }

    fun toFindings(s: Summary): List<FindingsEngine.Finding> {
        return s.findings.map { f ->
            FindingsEngine.Finding(
                severity = f.severity,
                title = "Flutter: ${f.category}",
                detail = f.explanation,
                category = "Flutter"
            )
        }
    }
}