package com.Cali.droidlens

/**
 * Extracts a structured summary from the decoded AndroidManifest.xml string.
 * Works against the XML our ManifestDecoder produces (attributes as name="value").
 *
 * Optionally takes a resource ID → string map (from ResourcesDecoder) to resolve
 * values like label="0x7f0f001c" into readable text.
 */
object ManifestInfo {

    data class Info(
        val packageName: String = "—",
        val versionName: String = "—",
        val versionCode: String = "—",
        val minSdk: String = "—",
        val targetSdk: String = "—",
        val debuggable: Boolean = false,
        val allowBackup: Boolean = false,
        val launcherActivity: String? = null,
        val appLabel: String? = null,
        val activityCount: Int = 0,
        val serviceCount: Int = 0,
        val receiverCount: Int = 0,
        val providerCount: Int = 0,
        val permissions: List<String> = emptyList(),
        val features: List<String> = emptyList(),
    )

    fun parse(xml: String, resources: Map<Int, String> = emptyMap()): Info {
        // ---- Manifest tag ----
        val manifestTag = Regex("""<manifest\b[^>]*>""").find(xml)?.value ?: ""
        val packageName = attr(manifestTag, "package") ?: "—"
        val versionCode = decodeMaybeHex(attr(manifestTag, "versionCode"))
        val versionName = attr(manifestTag, "versionName") ?: "—"

        // ---- Application tag ----
        val appTag = Regex("""<application\b[^>]*>""").find(xml)?.value ?: ""
        val debuggable = decodeBool(attr(appTag, "debuggable"))
        val allowBackup = decodeBool(attr(appTag, "allowBackup"))
        val labelRaw = attr(appTag, "label")
        val appLabel = resolveResource(labelRaw, resources)

        // ---- Uses-SDK ----
        val sdkTag = Regex("""<uses-sdk\b[^>]*>""").find(xml)?.value ?: ""
        val minSdk = decodeMaybeHex(attr(sdkTag, "minSdkVersion"))
        val targetSdk = decodeMaybeHex(attr(sdkTag, "targetSdkVersion"))

        // ---- Launcher activity ----
        val launcherActivity = findLauncherActivity(xml)

        // ---- Component counts ----
        val activityCount = Regex("""<activity\b""").findAll(xml).count()
        val serviceCount = Regex("""<service\b""").findAll(xml).count()
        val receiverCount = Regex("""<receiver\b""").findAll(xml).count()
        val providerCount = Regex("""<provider\b""").findAll(xml).count()

        // ---- Permissions ----
        val permissions = Regex("""<uses-permission[^>]*\sname="([^"]*)"""")
            .findAll(xml)
            .map { it.groupValues[1] }
            .distinct()
            .toList()

        // ---- Features ----
        val features = Regex("""<uses-feature[^>]*\sname="([^"]*)"""")
            .findAll(xml)
            .map { it.groupValues[1] }
            .distinct()
            .toList()

        return Info(
            packageName = packageName,
            versionName = versionName,
            versionCode = versionCode,
            minSdk = minSdk,
            targetSdk = targetSdk,
            debuggable = debuggable,
            allowBackup = allowBackup,
            launcherActivity = launcherActivity,
            appLabel = appLabel,
            activityCount = activityCount,
            serviceCount = serviceCount,
            receiverCount = receiverCount,
            providerCount = providerCount,
            permissions = permissions,
            features = features,
        )
    }

    // ---------- Helpers ----------

    private fun attr(tag: String, name: String): String? {
        val m = Regex("""\s$name="([^"]*)"""").find(tag)
        return m?.groupValues?.get(1)
    }

    private fun decodeBool(v: String?): Boolean {
        if (v == null) return false
        if (v == "true") return true
        if (v == "false") return false
        if (v.startsWith("0x")) {
            val n = v.substring(2).toLongOrNull(16) ?: return false
            return n != 0L
        }
        return false
    }

    private fun decodeMaybeHex(v: String?): String {
        if (v == null) return "—"
        if (!v.startsWith("0x")) return v
        val n = v.substring(2).toLongOrNull(16) ?: return v
        return n.toString()
    }

    /**
     * If the value looks like a resource ID (e.g. "0x7f0f001c"),
     * try to resolve it through the resources map.
     * Returns the original value if resolution fails.
     */
    private fun resolveResource(v: String?, resources: Map<Int, String>): String? {
        if (v == null) return null
        if (!v.startsWith("0x")) return v
        val id = v.substring(2).toLongOrNull(16)?.toInt() ?: return v
        return resources[id] ?: v
    }

    /**
     * Line-based state machine: finds the activity whose intent-filter
     * declares both MAIN and LAUNCHER. Returns null if none found.
     */
    private fun findLauncherActivity(xml: String): String? {
        val lines = xml.lines()
        var currentActivity: String? = null
        var hasMain = false
        var hasLauncher = false

        for (line in lines) {
            val trimmed = line.trim()

            if (trimmed.startsWith("<activity")) {
                currentActivity = attr(trimmed, "name")
                hasMain = false
                hasLauncher = false
            } else if (trimmed.startsWith("</activity")) {
                if (currentActivity != null && hasMain && hasLauncher) {
                    return currentActivity
                }
                currentActivity = null
            } else if (trimmed.contains("android.intent.action.MAIN")) {
                hasMain = true
            } else if (trimmed.contains("android.intent.category.LAUNCHER")) {
                hasLauncher = true
            }
        }
        return null
    }

    /** Pretty-prints the summary for display in the UI. */
    fun format(info: Info): String {
        val sb = StringBuilder()

        sb.append("PACKAGE\n")
        sb.append("  ${info.packageName}\n\n")

        if (info.appLabel != null) {
            sb.append("APP LABEL\n")
            sb.append("  ${info.appLabel}\n\n")
        }

        sb.append("VERSION\n")
        sb.append("  ${info.versionName}")
        if (info.versionCode != "—") sb.append("  (code ${info.versionCode})")
        sb.append("\n\n")

        sb.append("SDK\n")
        sb.append("  min: ${info.minSdk}    target: ${info.targetSdk}\n\n")

        sb.append("FLAGS\n")
        sb.append("  debuggable: ${info.debuggable}")
        if (info.debuggable) sb.append("  [SUSPICIOUS]")
        sb.append("\n")
        sb.append("  allowBackup: ${info.allowBackup}\n\n")

        if (info.launcherActivity != null) {
            sb.append("LAUNCHER\n")
            sb.append("  ${info.launcherActivity}\n\n")
        }

        sb.append("COMPONENTS\n")
        sb.append("  Activities: ${info.activityCount}    ")
        sb.append("Services: ${info.serviceCount}\n")
        sb.append("  Receivers:  ${info.receiverCount}    ")
        sb.append("Providers: ${info.providerCount}\n\n")

        if (info.permissions.isNotEmpty()) {
            sb.append("PERMISSIONS (${info.permissions.size})\n")
            info.permissions.take(8).forEach { sb.append("  • $it\n") }
            if (info.permissions.size > 8) {
                sb.append("  … and ${info.permissions.size - 8} more\n")
            }
            sb.append("\n")
        }

        if (info.features.isNotEmpty()) {
            sb.append("FEATURES (${info.features.size})\n")
            info.features.take(4).forEach { sb.append("  • $it\n") }
            if (info.features.size > 4) {
                sb.append("  … and ${info.features.size - 4} more\n")
            }
        }

        return sb.toString().trimEnd()
    }
}