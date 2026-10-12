package com.Cali.droidlens

object FindingsEngine {

    enum class Severity(val label: String, val colorHex: Int) {
        CRITICAL("CRITICAL", 0xFFFF3B30.toInt()),
        HIGH    ("HIGH",     0xFFFF6A00.toInt()),
        MEDIUM  ("MEDIUM",   0xFFFFB74D.toInt()),
        LOW     ("LOW",      0xFF4A90E2.toInt()),
        INFO    ("INFO",     0xFF8A8A8A.toInt()),
    }

    data class Finding(
        val severity: Severity,
        val title: String,
        val detail: String,
        val category: String,
    )

    fun analyze(
        xml: String,
        info: ManifestInfo.Info,
        exported: List<ExportedComponents.Component>,
        fingerprint: ApkFingerprint.Fingerprint,
    ): List<Finding> {
        val findings = mutableListOf<Finding>()

        checkSigning(fingerprint, findings)
        checkManifestFlags(info, findings)
        checkPermissions(info, findings)
        checkAccessibilityServices(xml, findings)   // NEW
        checkExportedComponents(exported, findings)
        checkSdks(xml, findings)
        checkSdkVersions(info, findings)

        return findings.sortedBy { it.severity.ordinal }
    }

    // ---------- Signing ----------
    private fun checkSigning(fp: ApkFingerprint.Fingerprint, out: MutableList<Finding>) {
        if (fp.error != null) return   // can't judge — UI already flags incomplete

        if (fp.signers.isEmpty()) {
            out.add(Finding(
                Severity.MEDIUM,
                "No extractable signing certificate",
                fp.signingNote ?: "APK is not signed or uses an unrecognized scheme.",
                "Signing"
            ))
            return
        }

        for (s in fp.signers) {
            val subject = s.subject

            if (subject.contains("CN=Android Debug", ignoreCase = true) ||
                (subject.contains("O=Android", ignoreCase = true) && subject.contains("C=US", ignoreCase = true))) {
                out.add(Finding(
                    Severity.HIGH,
                    "Signed with Android Debug key",
                    "This APK is signed with the developer's debug certificate. It was not prepared for release.",
                    "Signing"
                ))
            }

            // Cert expiry is not enforced by Android at install — downgrade to INFO
            try {
                val fmt = java.text.SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", java.util.Locale.US)
                val validTo = fmt.parse(s.validTo)
                if (validTo != null && validTo.before(java.util.Date())) {
                    out.add(Finding(
                        Severity.LOW,
                        "Signing certificate expired",
                        "Certificate expired on ${s.validTo}. Android does not enforce cert expiry at install, but this may indicate an abandoned build.",
                        "Signing"
                    ))
                }
            } catch (_: Throwable) { }
        }
    }

    // ---------- Manifest flags ----------
    private fun checkManifestFlags(info: ManifestInfo.Info, out: MutableList<Finding>) {
        if (info.debuggable) {
            out.add(Finding(
                Severity.HIGH,
                "Application is debuggable",
                "android:debuggable=\"true\" allows attaching a debugger and dumping memory at runtime.",
                "Manifest"
            ))
        }

        if (info.allowBackup) {
            out.add(Finding(
                Severity.MEDIUM,
                "Application data can be backed up",
                "android:allowBackup=\"true\" allows extracting app data via ADB (adb backup).",
                "Manifest"
            ))
        }
    }

    // ---------- Permission checks ----------
    private val dangerousPermissions = mapOf(
        "android.permission.SYSTEM_ALERT_WINDOW" to
                Finding(Severity.HIGH, "Can draw over other apps",
                    "Overlay permission. Common in tapjacking and fake-login attacks.", "Permission"),

        "android.permission.REQUEST_INSTALL_PACKAGES" to
                Finding(Severity.HIGH, "Can install other APKs",
                    "Dropper pattern. App can silently prompt install of arbitrary packages.", "Permission"),

        "android.permission.SEND_SMS" to
                Finding(Severity.HIGH, "Can send SMS",
                    "Premium-rate SMS fraud is one of the oldest Android scams.", "Permission"),

        "android.permission.READ_SMS" to
                Finding(Severity.HIGH, "Can read SMS",
                    "Often used to intercept OTP codes.", "Permission"),

        "android.permission.RECEIVE_SMS" to
                Finding(Severity.MEDIUM, "Can receive SMS",
                    "Often used to intercept OTP codes.", "Permission"),

        "android.permission.RECORD_AUDIO" to
                Finding(Severity.MEDIUM, "Can record audio",
                    "Microphone access.", "Permission"),

        "android.permission.READ_PHONE_STATE" to
                Finding(Severity.LOW, "Can read phone state",
                    "Access to device identifiers and phone state.", "Permission"),

        "android.permission.WRITE_EXTERNAL_STORAGE" to
                Finding(Severity.LOW, "Writes to external storage",
                    "Access to files outside the app sandbox.", "Permission"),

        "android.permission.RECEIVE_BOOT_COMPLETED" to
                Finding(Severity.LOW, "Starts on boot",
                    "Runs at system startup. Combined with overlays, often part of persistence.", "Permission"),
    )

    private fun checkPermissions(info: ManifestInfo.Info, out: MutableList<Finding>) {
        val set = info.permissions.map { it.trim() }.toSet()

        for ((perm, finding) in dangerousPermissions) {
            if (set.contains(perm)) out.add(finding)
        }

        if (set.contains("android.permission.SYSTEM_ALERT_WINDOW") &&
            set.contains("android.permission.RECEIVE_BOOT_COMPLETED")) {
            out.add(Finding(
                Severity.CRITICAL,
                "Overlay + boot persistence",
                "SYSTEM_ALERT_WINDOW + RECEIVE_BOOT_COMPLETED is the classic overlay-persistence combo used by banking trojans.",
                "Combo"
            ))
        }

        if (set.contains("android.permission.SEND_SMS") &&
            set.contains("android.permission.READ_SMS")) {
            out.add(Finding(
                Severity.CRITICAL,
                "SMS read + send combo",
                "Full SMS control. Common in subscription-fraud malware.",
                "Combo"
            ))
        }
    }

    // ---------- Accessibility services (NEW) ----------
    /**
     * Accessibility services are declared as <service android:permission=
     * "android.permission.BIND_ACCESSIBILITY_SERVICE"> — NOT as a <uses-permission>.
     * So we scan the decoded XML for <service> blocks with that attribute.
     */
    private fun checkAccessibilityServices(xml: String, out: MutableList<Finding>) {
        val serviceBlocks = Regex("""<service\b[^>]*>""", RegexOption.DOT_MATCHES_ALL)
            .findAll(xml)
            .map { it.value }
            .toList()

        var found = false
        for (block in serviceBlocks) {
            if (block.contains("BIND_ACCESSIBILITY_SERVICE", ignoreCase = true)) {
                found = true
                break
            }
        }

        // Also catch the intent action, which is the runtime declaration
        if (!found && xml.contains("android.accessibilityservice.AccessibilityService", ignoreCase = true)) {
            found = true
        }

        if (found) {
            out.add(Finding(
                Severity.CRITICAL,
                "Declares an Accessibility Service",
                "Accessibility services can read screen content, capture keystrokes, and inject input on behalf of the user. " +
                        "This is the single most abused capability in Android malware.",
                "Capability"
            ))
        }
    }

    // ---------- Exported components ----------
    private fun checkExportedComponents(
        exported: List<ExportedComponents.Component>,
        out: MutableList<Finding>
    ) {
        var realThirdPartyCount = 0

        for (c in exported) {
            val pkg = c.name.lowercase()

            // Skip framework-provided components
            if (isFramework(pkg)) continue

            // Skip launcher activities — exporting them is mandatory
            val isLauncherActivity = c.kind == "activity" &&
                    (c.actions.any { it.contains("MAIN") } ||
                     c.categories.any { it.contains("LAUNCHER") })
            if (isLauncherActivity) continue

            // Skip providers protected by any permission (readPermission/writePermission/permission)
            if (c.kind == "provider" && c.permission != null) continue

            realThirdPartyCount++

            if (c.permission == null) {
                val sev = when (c.kind) {
                    "service", "provider" -> Severity.HIGH
                    "activity", "receiver" -> Severity.MEDIUM
                    else -> Severity.LOW
                }
                out.add(Finding(
                    sev,
                    "Exported ${c.kind} without permission",
                    "${c.name} is reachable from any other app on the device with no permission gate.",
                    "Attack Surface"
                ))
            }
        }

        if (realThirdPartyCount == 0) {
            out.add(Finding(
                Severity.INFO,
                "No third-party exported components",
                "All exported components are framework libraries or launcher entries. Attack surface is minimal.",
                "Attack Surface"
            ))
        }
    }

    /** Same check used in the loop above — keep the two in sync. */
    private fun isFramework(lowercasedClassName: String): Boolean =
        lowercasedClassName.startsWith("androidx.") ||
        lowercasedClassName.startsWith("com.google.") ||
        lowercasedClassName.startsWith("com.android.") ||
        lowercasedClassName.startsWith("org.chromium.") ||
        lowercasedClassName.startsWith("android.support.")

    // ---------- SDK detection ----------
    private val knownSdks = listOf(
        Triple("com.google.firebase", "Firebase", Severity.LOW),
        Triple("com.google.android.gms", "Google Play Services", Severity.INFO),
        Triple("io.appmetrica", "AppMetrica Analytics", Severity.LOW),
        Triple("com.facebook", "Facebook SDK", Severity.LOW),
        Triple("com.adjust.sdk", "Adjust Attribution", Severity.MEDIUM),
        Triple("com.appsflyer", "AppsFlyer Attribution", Severity.MEDIUM),
        Triple("com.amplitude", "Amplitude Analytics", Severity.LOW),
        Triple("com.mixpanel", "Mixpanel Analytics", Severity.LOW),
        Triple("com.amz.appsuite", "Amazon AppSuite", Severity.MEDIUM),
        Triple("com.unity3d", "Unity Engine", Severity.INFO),
        Triple("io.branch", "Branch Attribution", Severity.MEDIUM),
        Triple("app_bandwidth_monetizer", "Bandwidth Monetizer SDK", Severity.HIGH),
        Triple("com.mon.app_bandwidth", "Bandwidth Monetizer SDK", Severity.HIGH),
    )

    private fun checkSdks(xml: String, out: MutableList<Finding>) {
        val found = mutableSetOf<String>()
        for ((prefix, label, sev) in knownSdks) {
            if (xml.contains(prefix, ignoreCase = true) && found.add(label)) {
                val detail = when (label) {
                    "Bandwidth Monetizer SDK" ->
                        "Uses the device's bandwidth as part of a paid proxy network. Common in modded apps."
                    "Adjust Attribution", "AppsFlyer Attribution", "Branch Attribution" ->
                        "Attribution SDKs collect device identifiers and install events."
                    "AppMetrica Analytics", "Amplitude Analytics", "Mixpanel Analytics" ->
                        "Analytics SDKs collect usage data."
                    "Amazon AppSuite" -> "Bundled Amazon store SDK."
                    else -> "$label is bundled in this APK."
                }
                out.add(Finding(sev, "$label detected", detail, "SDK"))
            }
        }
    }

    // ---------- SDK versions ----------
    private fun checkSdkVersions(info: ManifestInfo.Info, out: MutableList<Finding>) {
        val target = info.targetSdk.toIntOrNull()
        val min = info.minSdk.toIntOrNull()

        if (target != null && target < 30) {
            out.add(Finding(
                Severity.MEDIUM,
                "Target SDK below 30",
                "Target SDK is API $target. Apps below 30 can use deprecated APIs and are more likely to be non-compliant with modern privacy rules.",
                "Compatibility"
            ))
        }

        if (min != null && min < 21) {
            out.add(Finding(
                Severity.LOW,
                "Minimum SDK below 21",
                "Min SDK is API $min. Very old baseline; the app may not be actively maintained.",
                "Compatibility"
            ))
        }
    }

    // ---------- Formatting ----------
    fun format(findings: List<Finding>): String {
        if (findings.isEmpty()) return "No findings."

        return buildString {
            val groups = findings.groupBy { it.severity }
            for ((sev, list) in groups.toSortedMap(compareBy { it.ordinal })) {
                for (f in list) {
                    append("[${sev.label}]  ${f.title}\n")
                    append("         ${f.detail}\n\n")
                }
            }
        }.trimEnd()
    }

    fun highestSeverity(findings: List<Finding>): Severity? =
        findings.minByOrNull { it.severity.ordinal }?.severity
}