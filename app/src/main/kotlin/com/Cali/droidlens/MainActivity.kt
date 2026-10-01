package com.Cali.droidlens

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import java.io.File
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {

    // Selected file
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

    // Features
    private lateinit var cardFeatures: MaterialCardView
    private lateinit var tvFeatures: TextView

    // Attack surface
    private lateinit var tvExported: TextView

    // Findings
    private lateinit var tvFindings: TextView
    private lateinit var tvFindingsCount: TextView
    private lateinit var tvFindingsSummary: TextView

    // APK Contents (collapsible)
    private lateinit var headerApkContents: View
    private lateinit var tvApkContents: TextView
    private lateinit var tvApkContentsSummary: TextView
    private lateinit var tvApkContentsToggle: TextView
    private var apkContentsExpanded = false

    // DEX Classes (collapsible)
    private lateinit var headerDex: View
    private lateinit var scrollDex: View
    private lateinit var tvDex: TextView
    private lateinit var tvDexSummary: TextView
    private lateinit var tvDexToggle: TextView
    private var dexExpanded = false

    // Fingerprint (collapsible)
    private lateinit var headerFingerprint: View
    private lateinit var tvFingerprint: TextView
    private lateinit var tvFingerprintToggle: TextView
    private var fingerprintExpanded = false

    // Raw manifest (collapsible)
    private lateinit var headerRawManifest: View
    private lateinit var scrollRawManifest: View
    private lateinit var tvOutput: TextView
    private lateinit var tvManifestToggle: TextView
    private var manifestExpanded = false

    private lateinit var btnAnalyze: MaterialButton
    private lateinit var btnBrowseClasses: MaterialButton
    private var selectedApk: File? = null

    private val pickApkLauncher = registerForActivityResult(
    ActivityResultContracts.StartActivityForResult()
) { result ->
    if (result.resultCode == Activity.RESULT_OK) {
        result.data?.data?.let { uri ->
            // Clean up previous APKs — jadx is released before new pick
            JadxHolder.release()
            cacheDir.listFiles()?.forEach { f ->
                if (f.name.startsWith("target_") && f.name.endsWith(".apk")) {
                    f.delete()
                }
            }

            // Unique filename so jadx sees this as a different input
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

        bindViews()
        setupCollapsibles()

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
        tvFileName = findViewById(R.id.tvFileName)
        tvFileMeta = findViewById(R.id.tvFileMeta)
        tvStatus = findViewById(R.id.tvStatus)
        resultsContainer = findViewById(R.id.resultsContainer)
        btnAnalyze = findViewById(R.id.btnAnalyze)
        btnBrowseClasses = findViewById(R.id.btnBrowseClasses)

        tvAppLabel = findViewById(R.id.tvAppLabel)
        tvPackageName = findViewById(R.id.tvPackageName)
        tvVersion = findViewById(R.id.tvVersion)
        tvTargetSdk = findViewById(R.id.tvTargetSdk)
        tvMinSdk = findViewById(R.id.tvMinSdk)
        tvSize = findViewById(R.id.tvSize)
        tvDebuggableChip = findViewById(R.id.tvDebuggableChip)
        tvBackupChip = findViewById(R.id.tvBackupChip)
        llLauncher = findViewById(R.id.llLauncher)
        tvLauncher = findViewById(R.id.tvLauncher)

        tvActivities = findViewById(R.id.tvActivities)
        tvServices = findViewById(R.id.tvServices)
        tvReceivers = findViewById(R.id.tvReceivers)
        tvProviders = findViewById(R.id.tvProviders)

        tvPermissions = findViewById(R.id.tvPermissions)
        tvPermissionsCount = findViewById(R.id.tvPermissionsCount)

        cardFeatures = findViewById(R.id.cardFeatures)
        tvFeatures = findViewById(R.id.tvFeatures)

        tvExported = findViewById(R.id.tvExported)

        tvFindings = findViewById(R.id.tvFindings)
        tvFindingsCount = findViewById(R.id.tvFindingsCount)
        tvFindingsSummary = findViewById(R.id.tvFindingsSummary)

        headerApkContents = findViewById(R.id.headerApkContents)
        tvApkContents = findViewById(R.id.tvApkContents)
        tvApkContentsSummary = findViewById(R.id.tvApkContentsSummary)
        tvApkContentsToggle = findViewById(R.id.tvApkContentsToggle)

        headerDex = findViewById(R.id.headerDex)
        scrollDex = findViewById(R.id.scrollDex)
        tvDex = findViewById(R.id.tvDex)
        tvDexSummary = findViewById(R.id.tvDexSummary)
        tvDexToggle = findViewById(R.id.tvDexToggle)

        headerFingerprint = findViewById(R.id.headerFingerprint)
        tvFingerprint = findViewById(R.id.tvFingerprint)
        tvFingerprintToggle = findViewById(R.id.tvFingerprintToggle)

        headerRawManifest = findViewById(R.id.headerRawManifest)
        scrollRawManifest = findViewById(R.id.scrollRawManifest)
        tvOutput = findViewById(R.id.tvOutput)
        tvManifestToggle = findViewById(R.id.tvManifestToggle)
    }

    private fun setupCollapsibles() {
        headerApkContents.setOnClickListener {
            apkContentsExpanded = !apkContentsExpanded
            tvApkContents.visibility = if (apkContentsExpanded) View.VISIBLE else View.GONE
            tvApkContentsToggle.text = if (apkContentsExpanded) "▾" else "▸"
        }
        headerDex.setOnClickListener {
            dexExpanded = !dexExpanded
            scrollDex.visibility = if (dexExpanded) View.VISIBLE else View.GONE
            tvDexToggle.text = if (dexExpanded) "▾" else "▸"
        }
        headerFingerprint.setOnClickListener {
            fingerprintExpanded = !fingerprintExpanded
            tvFingerprint.visibility = if (fingerprintExpanded) View.VISIBLE else View.GONE
            tvFingerprintToggle.text = if (fingerprintExpanded) "▾" else "▸"
        }
        headerRawManifest.setOnClickListener {
            manifestExpanded = !manifestExpanded
            scrollRawManifest.visibility = if (manifestExpanded) View.VISIBLE else View.GONE
            tvManifestToggle.text = if (manifestExpanded) "▾" else "▸"
        }
    }

    private fun runAnalysis(apk: File) {
        btnAnalyze.isEnabled = false
        btnAnalyze.text = "Analyzing…"
        tvStatus.text = "Reading manifest…"
        tvStatus.visibility = View.VISIBLE
        resultsContainer.visibility = View.GONE

        Thread {
            var fingerprintText = "—"
            var exportedText = "—"
            var apkContentsText = "—"
            var apkContentsSummary = ""
            var dexText = "—"
            var dexSummary = ""
            var xmlText = ""

            try {
                // 1. Fingerprint
                val fp = try {
                    ApkFingerprint.compute(apk)
                } catch (_: Throwable) { null }
                fingerprintText = fp?.let { ApkFingerprint.format(it) } ?: "Fingerprint unavailable."

                // 2. APK file listing
                try {
                    runOnUiThread { tvStatus.text = "Listing APK contents…" }
                    val fileList = ApkFileList.analyze(apk)
                    apkContentsText = ApkFileList.format(fileList)
                    apkContentsSummary = "${fileList.totalFiles} files"
                } catch (e: Throwable) {
                    apkContentsText = "File listing failed: ${e.message}"
                }

                // 3. Manifest decode
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

                // 4. Resources
                val resources = try {
                    ResourcesDecoder.buildMap(apk)
                } catch (_: Throwable) { emptyMap() }

                // 5. Manifest info
                val info = ManifestInfo.parse(xmlText, resources)

                // 6. Exported components
                val exported = try {
                    ExportedComponents.find(xmlText)
                } catch (_: Throwable) { emptyList() }
                exportedText = ExportedComponents.format(exported)

                // 7. DEX parsing (class listing only — fast)
                runOnUiThread { tvStatus.text = "Parsing DEX files…" }
                try {
                    val dex = DexParser.analyze(apk)
                    dexText = DexParser.format(dex)
                    dexSummary = "${dex.dexFiles.size} dex · ${dex.totalClasses} classes"
                } catch (e: Throwable) {
                    dexText = "DEX parsing failed: ${e.message}"
                }

                // 8. Findings
                val findings = if (fp != null) {
                    try {
                        FindingsEngine.analyze(xmlText, info, exported, fp)
                    } catch (_: Throwable) { emptyList() }
                } else emptyList()

                val finalFp = fingerprintText
                val finalExported = exportedText
                val finalApkContents = apkContentsText
                val finalApkContentsSummary = apkContentsSummary
                val finalDex = dexText
                val finalDexSummary = dexSummary
                val finalXml = xmlText

                runOnUiThread {
                    populateResults(
                        info = info,
                        exportedText = finalExported,
                        fingerprintText = finalFp,
                        apkContentsText = finalApkContents,
                        apkContentsSummary = finalApkContentsSummary,
                        dexText = finalDex,
                        dexSummary = finalDexSummary,
                        findings = findings
                    )
                    tvStatus.visibility = View.GONE
                    tvOutput.text = finalXml
                    resultsContainer.visibility = View.VISIBLE
                    btnAnalyze.isEnabled = true
                    btnAnalyze.text = "Analyze"
                }
            } catch (e: Throwable) {
                val err = "ERROR: ${e::class.java.simpleName}\n${e.message}"
                runOnUiThread {
                    tvStatus.text = err
                    tvStatus.visibility = View.VISIBLE
                    btnAnalyze.isEnabled = true
                    btnAnalyze.text = "Analyze"
                }
            }
        }.start()
    }

    private fun populateResults(
        info: ManifestInfo.Info,
        exportedText: String,
        fingerprintText: String,
        apkContentsText: String,
        apkContentsSummary: String,
        dexText: String,
        dexSummary: String,
        findings: List<FindingsEngine.Finding>
    ) {
        // ---------- Overview ----------
        tvAppLabel.text = info.appLabel ?: info.packageName
        tvPackageName.text = info.packageName
        tvVersion.text = if (info.versionCode == "—") info.versionName
                          else "${info.versionName} (${info.versionCode})"
        tvTargetSdk.text = "API ${info.targetSdk}"
        tvMinSdk.text = "API ${info.minSdk}"

        val kb = selectedApk?.length()?.div(1024.0) ?: 0.0
        val mb = kb / 1024.0
        tvSize.text = if (mb >= 1) "%.2f MB".format(mb) else "%.1f KB".format(kb)

        tvDebuggableChip.visibility = if (info.debuggable) View.VISIBLE else View.GONE
        tvBackupChip.visibility = if (info.allowBackup) View.VISIBLE else View.GONE

        if (info.launcherActivity != null) {
            llLauncher.visibility = View.VISIBLE
            tvLauncher.text = info.launcherActivity
        } else {
            llLauncher.visibility = View.GONE
        }

        // ---------- Components ----------
        tvActivities.text = info.activityCount.toString()
        tvServices.text = info.serviceCount.toString()
        tvReceivers.text = info.receiverCount.toString()
        tvProviders.text = info.providerCount.toString()

        // ---------- APK Contents ----------
        tvApkContents.text = apkContentsText
        tvApkContentsSummary.text = apkContentsSummary

        // ---------- DEX Classes ----------
        tvDex.text = dexText
        tvDexSummary.text = dexSummary

        // ---------- Permissions ----------
        tvPermissionsCount.text = info.permissions.size.toString()
        tvPermissions.text = if (info.permissions.isEmpty()) "None declared"
                             else info.permissions.joinToString("\n") { "• $it" }

        // ---------- Features ----------
        if (info.features.isEmpty()) {
            cardFeatures.visibility = View.GONE
        } else {
            cardFeatures.visibility = View.VISIBLE
            tvFeatures.text = info.features.joinToString("\n") { "• $it" }
        }

        // ---------- Attack surface ----------
        tvExported.text = exportedText

        // ---------- Findings ----------
        if (findings.isEmpty()) {
            tvFindingsCount.text = "0"
            tvFindingsSummary.text = "Clean — no heuristic findings."
            tvFindings.text = "—"
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
            tvFindings.text = FindingsEngine.format(findings)
        }

        // ---------- Fingerprint ----------
        tvFingerprint.text = fingerprintText

        // ---------- Reset collapsibles to collapsed ----------
        apkContentsExpanded = false
        tvApkContents.visibility = View.GONE
        tvApkContentsToggle.text = "▸"

        dexExpanded = false
        scrollDex.visibility = View.GONE
        tvDexToggle.text = "▸"

        fingerprintExpanded = false
        tvFingerprint.visibility = View.GONE
        tvFingerprintToggle.text = "▸"

        manifestExpanded = false
        scrollRawManifest.visibility = View.GONE
        tvManifestToggle.text = "▸"
    }
}