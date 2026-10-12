package com.Cali.droidlens

object SecretsScanner {

    data class Secret(
        val type: String,
        val value: String,
        val severity: FindingsEngine.Severity
    )

    data class Summary(
        val secrets: List<Secret>,
        val totalStrings: Int,
        val dexFileCount: Int,
        val error: String? = null
    )

    /**
     * Patterns are ordered. First match wins.
     * URL categorization patterns MUST come before the generic URL pattern.
     */
    private val patterns: List<Triple<String, Regex, FindingsEngine.Severity>> = listOf(
        // ===== Highest severity: credentials =====
        Triple(
            "Private Key",
            Regex("""-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""),
            FindingsEngine.Severity.CRITICAL
        ),

        // ===== Cloud / API keys =====
        Triple(
            "Google API Key",
            Regex("""AIza[0-9A-Za-z\-_]{35}"""),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "AWS Access Key",
            Regex("""AKIA[0-9A-Z]{16}"""),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "Stripe Live Key",
            Regex("""sk_live_[0-9a-zA-Z]{24,}"""),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "Stripe Test Key",
            Regex("""sk_test_[0-9a-zA-Z]{24,}"""),
            FindingsEngine.Severity.MEDIUM
        ),
        Triple(
            "Slack Token",
            Regex("""xox[abposr]-[0-9A-Za-z-]{10,}"""),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "GitHub Token",
            Regex("""gh[pousr]_[A-Za-z0-9]{36,}"""),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "Firebase URL",
            Regex("""https?://[a-zA-Z0-9._-]+\.firebaseio\.com"""),
            FindingsEngine.Severity.MEDIUM
        ),
        Triple(
            "JWT Token",
            Regex("""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"""),
            FindingsEngine.Severity.MEDIUM
        ),

        // ===== Region-specific phone numbers =====
        Triple(
            "Egyptian Phone",
            Regex("""(?<!\d)(?:\+20|0020|0)1[0125]\d{8}(?!\d)"""),
            FindingsEngine.Severity.HIGH
        ),

        // ===== Crypto wallets =====
        Triple(
            "Bitcoin Address",
            Regex("""\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"""),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "Ethereum Address",
            Regex("""\b0x[a-fA-F0-9]{40}\b"""),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "TRON Address",
            Regex("""\bT[a-zA-HJ-NP-Z1-9]{33}\b"""),
            FindingsEngine.Severity.MEDIUM
        ),

        // ===== URL categorization — MUST come before generic URL =====
        Triple(
            "Torrent Tracker",
            Regex(
                """https?://(?:[a-z0-9.-]*\.)?(?:thepiratebay|torrentz\d*|rlsbb|solidtorrents|1337x|yts|rarbg|limetorrents|zooqle|torrentgalaxy)\.[a-z]{2,}""",
                RegexOption.IGNORE_CASE
            ),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "Piracy Front",
            Regex(
                """https?://(?:www\.)?(?:123movies|hindilinks4u|hindimoviestv|solarMovieHD|gowatchseries|watchmoviez|movies123|moplix|123chill|123moviesgoto|allmovieland|dood|upmovies|emovies)\.[a-z]{2,}""",
                RegexOption.IGNORE_CASE
            ),
            FindingsEngine.Severity.HIGH
        ),
        Triple(
            "Debrid Service",
            Regex(
                """https?://(?:api\.)?(?:real-debrid|alldebrid|premiumize|linksnappy|zevera|offcloud)\.[a-z]{2,}""",
                RegexOption.IGNORE_CASE
            ),
            FindingsEngine.Severity.MEDIUM
        ),
        Triple(
            "Streaming Embed",
            Regex(
                """https?://(?:vidsrc|vidcloud|streamcool|multiembed|autoembed|smashystream|embedsito|embed\.[a-z0-9.-]+)\.[a-z]{2,}""",
                RegexOption.IGNORE_CASE
            ),
            FindingsEngine.Severity.MEDIUM
        ),
        Triple(
            "OAuth Endpoint",
            Regex(
                """https?://[a-z0-9.-]+/[a-z0-9./_-]*oauth/(authorize|token|device)""",
                RegexOption.IGNORE_CASE
            ),
            FindingsEngine.Severity.LOW
        ),

        // ===== Generic contact info =====
        Triple(
            "Email",
            Regex("""[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"""),
            FindingsEngine.Severity.LOW
        ),

        // ===== Generic URL — LAST because it will match almost anything =====
        Triple(
            "URL",
            Regex("""https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}"""),
            FindingsEngine.Severity.LOW
        ),
    )

    /**
     * Substrings that mark a match as infrastructure noise.
     * If a string contains any of these, it's skipped entirely.
     */
    private val noiseSnippets = listOf(
        // Android framework
        "schemas.android.com",
        "w3.org",
        "apache.org/licenses",
        "creativecommons.org",
        "json-schema.org",
        "unicode.org",
        "ietf.org",
        "iana.org",
        "javax.xml",
        "%s/%s/%s",

        // Dev documentation
        "developer.android.com",
        "developer.mozilla.org",
        "stackoverflow.com",
        "kotlinlang.org",
        "materialdesignicons.com",
        "youtrack.jetbrains.com",
        "dartbug.com",
        "flutter.dev",

        // Common infra
        "example.com",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "10.0.2.2",
        "github.com/",
        "githubusercontent.com/",
        "goo.gl/",
        "support.koom.qq.com",
        "oauth.net",
        "play.google.com/store",
        "youtube.com/watch",
        "youtube.com/embed",
        "suggestqueries.google.com",
        "google.com/search",
        "google.com/docs",
        "google.com/support",
        "image.tmdb.org",

        // Google infrastructure (Firebase, Analytics, Crashlytics)
        "googleapis.com/",
        "app-measurement.com",
        "firebase-settings.crashlytics.com",
        "firebase.google.com/",

        // Adblock Plus list distribution (framework, not a threat)
        "easyList-downloads.adblockplus.org",
        "easylist-downloads.adblockplus.org",
        "ajax.gogocdn.net",
    )

    fun scan(apk: java.io.File): Summary {
        val extracted = StringExtractor.extract(apk)
        if (extracted.error != null) {
            return Summary(emptyList(), 0, 0, extracted.error)
        }

        val found = mutableListOf<Secret>()
        val dedup = HashSet<String>()

        for (raw in extracted.strings) {
            if (raw.length < 6) continue
            if (raw.length > 500) continue

            // Skip obvious infrastructure noise
            var skip = false
            for (n in noiseSnippets) {
                if (raw.contains(n, ignoreCase = true)) { skip = true; break }
            }
            if (skip) continue

            for ((type, regex, severity) in patterns) {
                val match = regex.find(raw) ?: continue
                val value = match.value

                if (type == "URL" && value.length > 150) continue

                val key = "$type|$value"
                if (!dedup.add(key)) continue

                found.add(Secret(type, value, severity))
                break  // one pattern per string
            }
        }

        val sorted = found.sortedWith(
            compareBy({ it.severity.ordinal }, { it.type }, { it.value })
        )

        return Summary(
            secrets = sorted,
            totalStrings = extracted.strings.size,
            dexFileCount = extracted.dexFileCount
        )
    }

    fun format(s: Summary): String {
        if (s.error != null) return "Scan failed: ${s.error}"
        if (s.secrets.isEmpty()) {
            return "No secrets found across ${s.totalStrings} unique strings " +
                    "in ${s.dexFileCount} dex file${if (s.dexFileCount == 1) "" else "s"}."
        }

        val byType = s.secrets.groupBy { it.type }
        return buildString {
            append("${s.secrets.size} secrets across ${s.totalStrings} unique strings\n\n")
            for ((type, list) in byType) {
                append("[${list.first().severity.label}] $type (${list.size})\n")
                val unique = list.map { it.value }.distinct()
                for (v in unique) {
                    val shown = if (v.length > 100) v.take(97) + "…" else v
                    append("  $shown\n")
                }
                append("\n")
            }
        }.trimEnd()
    }

    /** Compact preview — first N values per type. */
    fun formatPreview(s: Summary, perTypeLimit: Int = 3): String {
        if (s.error != null) return "Scan failed: ${s.error}"
        if (s.secrets.isEmpty()) {
            return "No secrets found across ${s.totalStrings} unique strings " +
                    "in ${s.dexFileCount} dex file${if (s.dexFileCount == 1) "" else "s"}."
        }

        val byType = s.secrets.groupBy { it.type }
        return buildString {
            append("${s.secrets.size} secrets across ${s.totalStrings} unique strings\n\n")
            for ((type, list) in byType) {
                append("[${list.first().severity.label}] $type (${list.size})\n")
                val unique = list.map { it.value }.distinct()
                for (v in unique.take(perTypeLimit)) {
                    val shown = if (v.length > 100) v.take(97) + "…" else v
                    append("  $shown\n")
                }
                if (unique.size > perTypeLimit) {
                    append("  … and ${unique.size - perTypeLimit} more\n")
                }
                append("\n")
            }
        }.trimEnd()
    }

    /** True if the full listing would be longer than the preview. */
    fun hasMoreThanPreview(s: Summary, perTypeLimit: Int = 3): Boolean {
        if (s.secrets.isEmpty()) return false
        val byType = s.secrets.groupBy { it.type }
        return byType.values.any { list ->
            list.map { it.value }.distinct().size > perTypeLimit
        }
    }

    fun toFindings(s: Summary): List<FindingsEngine.Finding> {
        val out = mutableListOf<FindingsEngine.Finding>()
        val byType = s.secrets.groupBy { it.type }
        for ((type, list) in byType) {
            val sev = list.first().severity
            val detail = when (type) {
                "Torrent Tracker" ->
                    "App references torrent trackers. Strong indicator of piracy content delivery."
                "Piracy Front" ->
                    "App references known piracy streaming sites."
                "Debrid Service" ->
                    "App uses a premium link generator service. Common in piracy workflows."
                "Streaming Embed" ->
                    "App embeds third-party streaming players. Often proxy for unlicensed content."
                "Private Key" ->
                    "Hardcoded private key material is present in DEX strings. This is a serious leak."
                "Google API Key", "AWS Access Key", "Stripe Live Key", "Slack Token", "GitHub Token" ->
                    "Hardcoded API credentials. May allow unauthorized access or billable abuse."
                "Egyptian Phone" ->
                    "Hardcoded payment or support phone number."
                "Bitcoin Address", "Ethereum Address", "TRON Address" ->
                    "Hardcoded cryptocurrency wallet. Common in scam and extortion apps."
                "Email" ->
                    "Hardcoded email address found in DEX strings."
                else ->
                    "Hardcoded $type value${if (list.size == 1) "" else "s"} found in DEX strings."
            }
            out.add(
                FindingsEngine.Finding(
                    severity = sev,
                    title = "${list.size} × $type",
                    detail = detail,
                    category = "Secrets"
                )
            )
        }
        return out
    }
}