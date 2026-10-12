package com.Cali.droidlens

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import java.io.File
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var tvFileName: TextView
    private lateinit var tvFileMeta: TextView
    private lateinit var tvStatus: TextView
    private lateinit var resultsContainer: View

    // Overview
    private lateinit var tvAppLabel: TextView
    private lateinit var tvPackageName: TextView
    private lateinit var tvVersion: TextView
    private lateinit var tvTargetSdk: TextView
    private lateinit var tvMinSdk: TextView
    private lateinit var tvSize: TextView
    private lateinit var tvDebuggableChip: TextView
    private lateinit var tvBackupChip: TextView
    private lateinit var llLauncher: View
    private lateinit var tvLauncher: TextView

    // Components
    private lateinit var tvActivities: TextView
    private lateinit var tvServices: TextView
    private lateinit var tvReceivers: TextView
    private lateinit var tvProviders: TextView

    // Permissions
    private lateinit var tvPermissions: TextView
    private lateinit var tvPermissionsCount: TextView
    private lateinit var btnPermissionsShowAll: MaterialButton

    // Features (removed)
    // private lateinit var card: MaterialCardView
    // private lateinit var featuresText: TextView

    // Attack surface
    private lateinit var tvExported: TextView

    // Fuzzer (NEW)
    private lateinit var btnRunFuzzer: MaterialButton
    private lateinit var tvFuzzResults: TextView

    // Findings
    private lateinit var tvFindings: TextView
    private lateinit var tvFindingsCount: TextView
    private lateinit var tvFindingsSummary: TextView
    private lateinit var btnFindingsShowAll: MaterialButton

    // Secrets
    private lateinit var headerSecrets: View
    private lateinit var scrollSecrets: View
    private lateinit var tvSecrets: TextView
    private lateinit var tvSecretsSummary: TextView
    private lateinit var tvSecretsToggle: TextView
    private lateinit var btnSecretsShowAll: MaterialButton
    private var secretsExpanded = false
    private var secretsShowAll = false
    private var secretsPreview = ""
    private var secretsFull = ""

    // APK Contents
    private lateinit var headerApkContents: View
    private lateinit var tvApkContents: TextView
    private lateinit var tvApkContentsSummary: TextView
    private lateinit var tvApkContentsToggle: TextView
    private var apkContentsExpanded = false

    // DEX
    private lateinit var headerDex: View
    private lateinit var scrollDex: View
    private lateinit var tvDex: TextView
    private lateinit var tvDexSummary: TextView
    private lateinit var tvDexToggle: TextView
    private lateinit var btnDexShowAll: MaterialButton
    private var dexExpanded = false
    private var dexShowAll = false
    private var dexPreview = ""
    private var dexFull = ""

    // Native
    private lateinit var headerNative: View
    private lateinit var scrollNative: View
    private lateinit var tvNative: TextView
    private lateinit var tvNativeSummary: TextView
    private lateinit var tvNativeToggle: TextView
    private lateinit var btnNativeShowAll: MaterialButton
    private var nativeExpanded = false
    private var nativeShowAll = false
    private var nativePreview = ""
    private var nativeFull = ""

    // Flutter
    private lateinit var cardFlutter: MaterialCardView
    private lateinit var headerFlutter: View
    private lateinit var scrollFlutter: View
    private lateinit var tvFlutter: TextView
    private lateinit var tvFlutterSummary: TextView
    private lateinit var tvFlutterToggle: TextView
    private var flutterExpanded = false

    // Fingerprint
    private lateinit var headerFingerprint: View
    private lateinit var tvFingerprint: TextView
    private lateinit var tvFingerprintToggle: TextView
    private var fingerprintExpanded = false

    // Raw manifest
    private lateinit var headerRawManifest: View
    private lateinit var scrollRawManifest: View
    private lateinit var tvOutput: TextView
    private lateinit var tvManifestToggle: TextView
    private var manifestExpanded = false

    private var permissionsShowAll = false
    private var permissionsPreview = ""
    private var permissionsFull = ""

    private var findingsShowAll = false
    private var findingsPreview = ""
    private var findingsFull = ""

    private lateinit var btnAnalyze: MaterialButton
    private lateinit var btnBrowseClasses: MaterialButton
    private var selectedApk: File? = null

    private val pickApkLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                JadxHolder.release()
                cacheDir.listFiles()?.forEach { f ->
                    if (f.name.startsWith("target_") && f.name.endsWith(".apk")) {
                        f.delete()
                    }
                }

                val temp = File(cacheDir, "target_${System.currentTimeMillis()}.apk")
                try {
                    contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(temp).use { out -> input.copyTo(out) }
                    }
                    selectedApk = temp
                    tvFileName.text = temp.name
                    val kb = temp.length() / 1024.0
                    val mb = kb / 1024.0
                    val sizeText = if (mb >= 1) "%.2f MB".format(mb) else "%.1f KB".format(kb)
                    tvFileMeta.text = "$sizeText  ·  ready to analyze"
                    btnAnalyze.isEnabled = true
                    resultsContainer.visibility = View.GONE
                    tvStatus.visibility = View.GONE
                } catch (e: Exception) {
                    tvStatus.text = "Copy failed: ${e.message}"
                    tvStatus.visibility = View.VISIBLE
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize Shizuku. Permission dialog pops automatically once the
        // binder is up (handled inside ShizukuManager.init).
        ShizukuManager.init()

        bindViews()
        setupCollapsibles()
        setupShowAllButtons()

        findViewById<Button>(R.id.btnPickApk).setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            pickApkLauncher.launch(intent)
        }

        btnAnalyze.setOnClickListener {
            val apk = selectedApk ?: return@setOnClickListener
            runAnalysis(apk)
        }

        btnBrowseClasses.setOnClickListener {
            val apk = selectedApk ?: return@setOnClickListener
            val intent = Intent(this, ClassBrowserActivity::class.java).apply {
                putExtra(ClassBrowserActivity.EXTRA_APK_PATH, apk.absolutePath)
            }
            startActivity(intent)
        }
    }

    private fun bindViews() {
        tvFileName = findViewById<TextView>(R.id.tvFileName)
        tvFileMeta = findViewById<TextView>(R.id.tvFileMeta)
        tvStatus = findViewById<TextView>(R.id.tvStatus)
        resultsContainer = findViewById<View>(R.id.resultsContainer)
        btnAnalyze = findViewById<MaterialButton>(R.id.btnAnalyze)
        btnBrowseClasses = findViewById<MaterialButton>(R.id.btnBrowseClasses)

        tvAppLabel = findViewById<TextView>(R.id.tvAppLabel)
        tvPackageName = findViewById<TextView>(R.id.tvPackageName)
        tvVersion = findViewById<TextView>(R.id.tvVersion)
        tvTargetSdk = findViewById<TextView>(R.id.tvTargetSdk)
        tvMinSdk = findViewById<TextView>(R.id.tvMinSdk)
        tvSize = findViewById<TextView>(R.id.tvSize)
        tvDebuggableChip = findViewById<TextView>(R.id.tvDebuggableChip)
        tvBackupChip = findViewById<TextView>(R.id.tvBackupChip)
        llLauncher = findViewById<View>(R.id.llLauncher)
        tvLauncher = findViewById<TextView>(R.id.tvLauncher)

        tvActivities = findViewById<TextView>(R.id.tvActivities)
        tvServices = findViewById<TextView>(R.id.tvServices)
        tvReceivers = findViewById<TextView>(R.id.tvReceivers)
        tvProviders = findViewById<TextView>(R.id.tvProviders)

        tvPermissions = findViewById<TextView>(R.id.tvPermissions)
        tvPermissionsCount = findViewById<TextView>(R.id.tvPermissionsCount)
        btnPermissionsShowAll = findViewById<MaterialButton>(R.id.btnPermissionsShowAll)

        tvExported = findViewById<TextView>(R.id.tvExported)

        // NEW — Shizuku fuzzer views
        btnRunFuzzer = findViewById<MaterialButton>(R.id.btnRunFuzzer)
        tvFuzzResults = findViewById<TextView>(R.id.tvFuzzResults)

        tvFindings = findViewById<TextView>(R.id.tvFindings)
        tvFindingsCount = findViewById<TextView>(R.id.tvFindingsCount)
        tvFindingsSummary = findViewById<TextView>(R.id.tvFindingsSummary)
        btnFindingsShowAll = findViewById<MaterialButton>(R.id.btnFindingsShowAll)

        headerSecrets = findViewById<View>(R.id.headerSecrets)
        scrollSecrets = findViewById<View>(R.id.scrollSecrets)
        tvSecrets = findViewById<TextView>(R.id.tvSecrets)
        tvSecretsSummary = findViewById<TextView>(R.id.tvSecretsSummary)
        tvSecretsToggle = findViewById<TextView>(R.id.tvSecretsToggle)
        btnSecretsShowAll = findViewById<MaterialButton>(R.id.btnSecretsShowAll)

        headerApkContents = findViewById<View>(R.id.headerApkContents)
        tvApkContents = findViewById<TextView>(R.id.tvApkContents)
        tvApkContentsSummary = findViewById<TextView>(R.id.tvApkContentsSummary)
        tvApkContentsToggle = findViewById<TextView>(R.id.tvApkContentsToggle)

        headerDex = findViewById<View>(R.id.headerDex)
        scrollDex = findViewById<View>(R.id.scrollDex)
        tvDex = findViewById<TextView>(R.id.tvDex)
        tvDexSummary = findViewById<TextView>(R.id.tvDexSummary)
        tvDexToggle = findViewById<TextView>(R.id.tvDexToggle)
        btnDexShowAll = findViewById<MaterialButton>(R.id.btnDexShowAll)

        headerNative = findViewById<View>(R.id.headerNative)
        scrollNative = findViewById<View>(R.id.scrollNative)
        tvNative = findViewById<TextView>(R.id.tvNative)
        tvNativeSummary = findViewById<TextView>(R.id.tvNativeSummary)
        tvNativeToggle = findViewById<TextView>(R.id.tvNativeToggle)
        btnNativeShowAll = findViewById<MaterialButton>(R.id.btnNativeShowAll)

        cardFlutter = findViewById<MaterialCardView>(R.id.cardFlutter)
        headerFlutter = findViewById<View>(R.id.headerFlutter)
        scrollFlutter = findViewById<View>(R.id.scrollFlutter)
        tvFlutter = findViewById<TextView>(R.id.tvFlutter)
        tvFlutterSummary = findViewById<TextView>(R.id.tvFlutterSummary)
        tvFlutterToggle = findViewById<TextView>(R.id.tvFlutterToggle)

        headerFingerprint = findViewById<View>(R.id.headerFingerprint)
        tvFingerprint = findViewById<TextView>(R.id.tvFingerprint)
        tvFingerprintToggle = findViewById<TextView>(R.id.tvFingerprintToggle)

        headerRawManifest = findViewById<View>(R.id.headerRawManifest)
        scrollRawManifest = findViewById<View>(R.id.scrollRawManifest)
        tvOutput = findViewById<TextView>(R.id.tvOutput)
        tvManifestToggle = findViewById<TextView>(R.id.tvManifestToggle)
    }

    private fun setupCollapsibles() {
        headerSecrets.setOnClickListener {
            secretsExpanded = !secretsExpanded
            animateReveal(scrollSecrets, secretsExpanded)
            rotateToggle(tvSecretsToggle, secretsExpanded)
        }
        headerApkContents.setOnClickListener {
            apkContentsExpanded = !apkContentsExpanded
            animateReveal(tvApkContents, apkContentsExpanded)
            rotateToggle(tvApkContentsToggle, apkContentsExpanded)
        }
        headerDex.setOnClickListener {
            dexExpanded = !dexExpanded
            animateReveal(scrollDex, dexExpanded)
            rotateToggle(tvDexToggle, dexExpanded)
        }
        headerNative.setOnClickListener {
            nativeExpanded = !nativeExpanded
            animateReveal(scrollNative, nativeExpanded)
            rotateToggle(tvNativeToggle, nativeExpanded)
        }
        headerFlutter.setOnClickListener {
            flutterExpanded = !flutterExpanded
            animateReveal(scrollFlutter, flutterExpanded)
            rotateToggle(tvFlutterToggle, flutterExpanded)
        }
        headerFingerprint.setOnClickListener {
            fingerprintExpanded = !fingerprintExpanded
            animateReveal(tvFingerprint, fingerprintExpanded)
            rotateToggle(tvFingerprintToggle, fingerprintExpanded)
        }
        headerRawManifest.setOnClickListener {
            manifestExpanded = !manifestExpanded
            animateReveal(scrollRawManifest, manifestExpanded)
            rotateToggle(tvManifestToggle, manifestExpanded)
        }
    }

    private fun setupShowAllButtons() {
        btnSecretsShowAll.setOnClickListener {
            secretsShowAll = !secretsShowAll
            swapText(tvSecrets, if (secretsShowAll) secretsFull else secretsPreview)
            btnSecretsShowAll.text = if (secretsShowAll) "Show less" else "Show all"
        }
        btnDexShowAll.setOnClickListener {
            dexShowAll = !dexShowAll
            swapText(tvDex, if (dexShowAll) dexFull else dexPreview)
            btnDexShowAll.text = if (dexShowAll) "Show less" else "Show all"
        }
        btnNativeShowAll.setOnClickListener {
            nativeShowAll = !nativeShowAll
            swapText(tvNative, if (nativeShowAll) nativeFull else nativePreview)
            btnNativeShowAll.text = if (nativeShowAll) "Show less" else "Show all"
        }
        btnPermissionsShowAll.setOnClickListener {
            permissionsShowAll = !permissionsShowAll
            swapText(tvPermissions, if (permissionsShowAll) permissionsFull else permissionsPreview)
            btnPermissionsShowAll.text = if (permissionsShowAll) "Show less" else "Show all"
        }
        btnFindingsShowAll.setOnClickListener {
            findingsShowAll = !findingsShowAll
            swapText(tvFindings, if (findingsShowAll) findingsFull else findingsPreview)
            btnFindingsShowAll.text = if (findingsShowAll) "Show less" else "Show all"
        }
    }

    private fun animateReveal(view: View, reveal: Boolean) {
        if (reveal) {
            view.alpha = 0f
            view.translationY = -8f
            view.visibility = View.VISIBLE
            view.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(220L)
                .setInterpolator(DecelerateInterpolator())
                .start()
        } else {
            view.animate()
                .alpha(0f)
                .translationY(-8f)
                .setDuration(180L)
                .setInterpolator(DecelerateInterpolator())
                .withEndAction {
                    view.visibility = View.GONE
                    view.alpha = 1f
                    view.translationY = 0f
                }
                .start()
        }
    }

    private fun swapText(view: TextView, newText: String) {
        if (view.text.toString() == newText) return
        view.animate()
            .alpha(0f)
            .setDuration(120L)
            .withEndAction {
                view.text = newText
                view.animate().alpha(1f).setDuration(180L).start()
            }
            .start()
    }

    private fun rotateToggle(toggle: TextView, expanded: Boolean) {
        toggle.animate()
            .rotation(if (expanded) 90f else 0f)
            .setDuration(180L)
            .withEndAction {
                toggle.text = if (expanded) "▾" else "▸"
                toggle.rotation = 0f
            }
            .start()
    }

    private fun runAnalysis(apk: File) {
        btnAnalyze.isEnabled = false
        btnAnalyze.text = "Analyzing…"
        tvStatus.text = "Reading manifest…"
        tvStatus.visibility = View.VISIBLE
        resultsContainer.visibility = View.GONE

        secretsShowAll = false
        dexShowAll = false
        nativeShowAll = false
        permissionsShowAll = false
        findingsShowAll = false

        Thread {
            var fingerprintText = "—"
            var exportedText = "—"
            var apkContentsText = "—"
            var apkContentsSummary = ""
            var xmlText = ""

            try {
                val fp = try {
                    ApkFingerprint.compute(this@MainActivity, apk)
                } catch (_: Throwable) { null }
                fingerprintText = fp?.let { ApkFingerprint.format(it) } ?: "Fingerprint unavailable."

                val fingerprintIncomplete = fp == null || fp.error != null

                try {
                    runOnUiThread { tvStatus.text = "Listing APK contents…" }
                    val fileList = ApkFileList.analyze(apk)
                    apkContentsText = ApkFileList.format(fileList)
                    apkContentsSummary = "${fileList.totalFiles} files"
                } catch (e: Throwable) {
                    apkContentsText = "File listing failed: ${e.message}"
                }

                runOnUiThread { tvStatus.text = "Decoding manifest…" }
                xmlText = ManifestDecoder.decode(apk)
                if (xmlText.startsWith("Decode failed")) {
                    val err = xmlText
                    runOnUiThread {
                        tvStatus.text = err
                        btnAnalyze.isEnabled = true
                        btnAnalyze.text = "Analyze"
                    }
                    return@Thread
                }

                val resources = try {
                    ResourcesDecoder.buildMap(apk)
                } catch (_: Throwable) { emptyMap() }

                val info = ManifestInfo.parse(xmlText, resources)

                val exported = try {
                    ExportedComponents.find(xmlText)
                } catch (_: Throwable) { emptyList() }
                exportedText = ExportedComponents.format(exported)

                // DEX
                runOnUiThread { tvStatus.text = "Parsing DEX files…" }
                var dexPreviewText = "—"
                var dexFullText = "—"
                var dexSummaryText = ""
                try {
                    val dex = DexParser.analyze(apk)
                    dexFullText = DexParser.format(dex)
                    dexPreviewText = buildDexPreview(dex)
                    dexSummaryText = "${dex.dexFiles.size} dex · ${dex.totalClasses} classes"
                } catch (e: Throwable) {
                    dexPreviewText = "DEX parsing failed: ${e.message}"
                    dexFullText = dexPreviewText
                }

                // Secrets
                runOnUiThread { tvStatus.text = "Scanning strings for secrets…" }
                val secrets = try {
                    SecretsScanner.scan(apk)
                } catch (e: Throwable) {
                    SecretsScanner.Summary(emptyList(), 0, 0, "Secrets scan failed: ${e.message}")
                }
                val secretsPreviewText = SecretsScanner.formatPreview(secrets, 3)
                val secretsFullText = SecretsScanner.format(secrets)
                val secretsSummaryText = if (secrets.secrets.isEmpty()) "none found"
                                          else "${secrets.secrets.size} found"
                val secretsHasMore = SecretsScanner.hasMoreThanPreview(secrets, 3)

                // ═══ RECONSTRUCTED — VERIFY ═══
                // ═══ Native libraries ═══
runOnUiThread { tvStatus.text = "Scanning native libraries…" }
var nativePreviewText = "—"
var nativeFullText = "—"
var nativeSummaryText = ""
var nativeHasMore = false
try {
    val natives = NativeScanner.analyze(apk)
    nativePreviewText = NativeScanner.formatPreview(natives)
    nativeFullText = NativeScanner.format(natives)
    nativeSummaryText = if (natives.totalLibs == 0) "none"
                        else "${natives.totalLibs} libs"
    nativeHasMore = nativePreviewText != nativeFullText
} catch (e: Throwable) {
    nativePreviewText = "Native scan failed: ${e.message}"
    nativeFullText = nativePreviewText
}

// ═══ Native threats ═══
val nativeFindings: List<FindingsEngine.Finding> = try {
    val threatSummary = NativeThreatScanner.scan(apk)
    NativeThreatScanner.toFindings(threatSummary)
} catch (_: Throwable) {
    emptyList()
}

// ═══ Flutter ═══
var flutterDetected = false
var flutterText = "—"
val flutterFindings: List<FindingsEngine.Finding> = try {
    val flutter = FlutterDetector.analyze(apk)
    flutterDetected = flutter.detected
    if (flutterDetected) {
        val fl = FlutterScanner.scan(flutter)
        flutterText = FlutterDetector.format(flutter) + "\n\n" + FlutterScanner.format(fl)
        FlutterScanner.toFindings(fl)
    } else {
        emptyList()
    }
} catch (_: Throwable) {
    emptyList()
}

// ═══ Permissions preview ═══
val permissionsPreviewText = if (info.permissions.isEmpty()) "—"
    else info.permissions.joinToString("\n") { "• $it" }
val permissionsFullText = permissionsPreviewText

// ═══ Findings ═══
val baseFindings: List<FindingsEngine.Finding> = if (fp != null) {
    try {
        FindingsEngine.analyze(xmlText, info, exported, fp)
    } catch (_: Throwable) {
        emptyList()
    }
} else {
    emptyList()
}

val findings = (baseFindings + nativeFindings + flutterFindings)
    .sortedBy { it.severity.ordinal }

val findingsPreviewText = formatFindingsPreview(findings, 5)
val findingsFullText = FindingsEngine.format(findings)
// ═══ END RECONSTRUCTED ═══

                // Prepare fuzzer targets
                val activityNames = exported
                    .filter { it.kind.equals("activity", ignoreCase = true) }
                    .map { it.name }

                runOnUiThread {
                    // Overview
                    tvAppLabel.text = info.appLabel ?: "—"
                    tvPackageName.text = info.packageName
                    tvVersion.text = "${info.versionName} (${info.versionCode})"
                    tvTargetSdk.text = "API ${info.targetSdk}"
                    tvMinSdk.text = "API ${info.minSdk}"
                    tvSize.text = "%.2f MB".format(apk.length() / 1024.0 / 1024.0)
                    tvDebuggableChip.visibility = if (info.debuggable) View.VISIBLE else View.GONE
                    tvBackupChip.visibility = if (info.allowBackup) View.VISIBLE else View.GONE
                    tvLauncher.text = info.launcherActivity ?: "—"

                    // Components
                    tvActivities.text = info.activityCount.toString()
                    tvServices.text = info.serviceCount.toString()
                    tvReceivers.text = info.receiverCount.toString()
                    tvProviders.text = info.providerCount.toString()

                    // APK Contents
                    tvApkContents.text = apkContentsText
                    tvApkContentsSummary.text = apkContentsSummary

                    // DEX
                    this.dexPreview = dexPreviewText
                    this.dexFull = dexFullText
                    tvDex.text = dexPreviewText
                    tvDexSummary.text = dexSummaryText
                    btnDexShowAll.visibility =
                        if (dexFullText != dexPreviewText) View.VISIBLE else View.GONE
                    btnDexShowAll.text = "Show all"

                    // Secrets
                    this.secretsPreview = secretsPreviewText
                    this.secretsFull = secretsFullText
                    tvSecrets.text = secretsPreviewText
                    tvSecretsSummary.text = secretsSummaryText
                    btnSecretsShowAll.visibility =
                        if (secretsHasMore) View.VISIBLE else View.GONE
                    btnSecretsShowAll.text = "Show all"

                    // Native
                    this.nativePreview = nativePreviewText
                    this.nativeFull = nativeFullText
                    tvNative.text = nativePreviewText
                    tvNativeSummary.text = nativeSummaryText
                    btnNativeShowAll.visibility =
                        if (nativeHasMore) View.VISIBLE else View.GONE
                    btnNativeShowAll.text = "Show all"

                    // Flutter
                    if (flutterDetected) {
                        cardFlutter.visibility = View.VISIBLE
                        tvFlutter.text = flutterText
                        tvFlutterSummary.text = "detected"
                    } else {
                        cardFlutter.visibility = View.GONE
                    }

                    // Permissions
                    this.permissionsPreview = permissionsPreviewText
                    this.permissionsFull = permissionsFullText
                    tvPermissionsCount.text = info.permissions.size.toString()
                    tvPermissions.text = permissionsPreviewText
                    btnPermissionsShowAll.visibility =
                        if (permissionsFullText != permissionsPreviewText) View.VISIBLE else View.GONE
                    btnPermissionsShowAll.text = "Show all"

                    // Attack surface
                    tvExported.text = exportedText

                    // Fuzzer — wire up with what we have
                    btnRunFuzzer.isEnabled =
                        activityNames.isNotEmpty() && info.packageName.isNotEmpty()
                    btnRunFuzzer.setOnClickListener {
                        if (activityNames.isEmpty()) return@setOnClickListener
                        runFuzzer(info.packageName, activityNames)
                    }
                    tvFuzzResults.visibility = View.GONE

                    // Findings
                    if (fingerprintIncomplete) {
                        tvFindingsCount.text = "!"
                        tvFindingsSummary.text = "Analysis incomplete — fingerprint step failed"
                        tvFindings.text = "The file hashing or signing step failed. Findings may be missing."
                        btnFindingsShowAll.visibility = View.GONE
                    } else if (findings.isEmpty()) {
                        tvFindingsCount.text = "0"
                        tvFindingsSummary.text = "Clean — no heuristic findings."
                        tvFindings.text = "—"
                        btnFindingsShowAll.visibility = View.GONE
                    } else {
                        tvFindingsCount.text = findings.size.toString()
                        val countsBySev = findings.groupingBy { it.severity }.eachCount()
                        val order = listOf(
                            FindingsEngine.Severity.CRITICAL,
                            FindingsEngine.Severity.HIGH,
                            FindingsEngine.Severity.MEDIUM,
                            FindingsEngine.Severity.LOW,
                            FindingsEngine.Severity.INFO,
                        )
                        val summary = order.mapNotNull { s ->
                            val c = countsBySev[s] ?: return@mapNotNull null
                            "$c ${s.label.lowercase()}"
                        }.joinToString(" · ")
                        tvFindingsSummary.text = summary
                        tvFindings.text = findingsPreviewText
                        this.findingsPreview = findingsPreviewText
                        this.findingsFull = findingsFullText
                        btnFindingsShowAll.visibility =
                            if (findingsFullText != findingsPreviewText) View.VISIBLE else View.GONE
                        btnFindingsShowAll.text = "Show all"
                    }

                    // Fingerprint
                    tvFingerprint.text = fingerprintText

                    // Raw manifest
                    tvOutput.text = xmlText

                    // Reset collapsibles
                    secretsExpanded = false
                    scrollSecrets.visibility = View.GONE
                    scrollSecrets.alpha = 1f
                    tvSecretsToggle.text = "▸"

                    apkContentsExpanded = false
                    tvApkContents.visibility = View.GONE
                    tvApkContents.alpha = 1f
                    tvApkContentsToggle.text = "▸"

                    dexExpanded = false
                    scrollDex.visibility = View.GONE
                    scrollDex.alpha = 1f
                    tvDexToggle.text = "▸"

                    nativeExpanded = false
                    scrollNative.visibility = View.GONE
                    scrollNative.alpha = 1f
                    tvNativeToggle.text = "▸"

                    flutterExpanded = false
                    scrollFlutter.visibility = View.GONE
                    scrollFlutter.alpha = 1f
                    tvFlutterToggle.text = "▸"

                    fingerprintExpanded = false
                    tvFingerprint.visibility = View.GONE
                    tvFingerprint.alpha = 1f
                    tvFingerprintToggle.text = "▸"

                    manifestExpanded = false
                    scrollRawManifest.visibility = View.GONE
                    scrollRawManifest.alpha = 1f
                    tvManifestToggle.text = "▸"

                    // Reveal results
                    resultsContainer.visibility = View.VISIBLE
                    tvStatus.visibility = View.GONE
                    btnAnalyze.isEnabled = true
                    btnAnalyze.text = "Analyze"
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    tvStatus.text = "Analysis failed: ${e.message}"
                    tvStatus.visibility = View.VISIBLE
                    btnAnalyze.isEnabled = true
                    btnAnalyze.text = "Analyze"
                }
            }
        }.start()
    }

    // ──────────────────────────────────────────────────────────────
    // NEW — Fuzzer
    // ──────────────────────────────────────────────────────────────

    private fun runFuzzer(packageName: String, activityNames: List<String>) {
        if (!ShizukuManager.isReady) {
            tvFuzzResults.visibility = View.VISIBLE
            tvFuzzResults.text = "Shizuku not ready. Open Shizuku, start it, then return."
            return
        }

        btnRunFuzzer.isEnabled = false
        btnRunFuzzer.text = "Fuzzing…"
        tvFuzzResults.visibility = View.VISIBLE
        tvFuzzResults.text = "Fuzzing ${activityNames.size} activities…"

        Thread {
            val results = IntentFuzzer.fuzz(packageName, activityNames) { msg ->
                runOnUiThread { tvFuzzResults.text = msg }
            }
            val summary = IntentFuzzer.format(results)

            runOnUiThread {
                tvFuzzResults.text = summary
                btnRunFuzzer.isEnabled = true
                btnRunFuzzer.text = "Run Intent Fuzzer (Shizuku)"
            }
        }.start()
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers used above (adjust if your existing signatures differ)
    // ──────────────────────────────────────────────────────────────

    private fun buildDexPreview(dex: DexParser.Summary): String {
    val sb = StringBuilder()
    sb.append("${dex.dexFiles.size} dex · ${dex.totalClasses} classes\n\n")
    for (f in dex.dexFiles) {
        sb.append(f.fileName).append("  ").append(f.classCount).append(" classes\n")
    }
    if (dex.topPackages.isNotEmpty()) {
        sb.append("\nTop packages:\n")
        for ((pkg, count) in dex.topPackages.take(8)) {
            sb.append("  ").append(pkg).append("  ").append(count).append('\n')
        }
    }
    return sb.toString().trimEnd()
}

    private fun formatFindingsPreview(
        findings: List<FindingsEngine.Finding>,
        limit: Int
    ): String {
        if (findings.isEmpty()) return "—"
        val sb = StringBuilder()
        for (f in findings.take(limit)) {
            sb.append("[").append(f.severity.name).append("] ")
              .append(f.title).append('\n')
              .append("  ").append(f.detail).append("\n\n")
        }
        if (findings.size > limit) {
            sb.append("… and ").append(findings.size - limit).append(" more findings")
        }
        return sb.toString().trimEnd()
    }
}