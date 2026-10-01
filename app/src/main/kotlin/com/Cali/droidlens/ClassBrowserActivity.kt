package com.Cali.droidlens

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.io.File

class ClassBrowserActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_APK_PATH = "apk_path"
    }

    private lateinit var rv: RecyclerView
    private lateinit var adapter: ClassAdapter
    private lateinit var tvSubtitle: TextView
    private lateinit var tvEmpty: TextView
    private lateinit var tvLoading: TextView
    private lateinit var progressBar: View

    @Volatile private var jadxReady = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_class_browser)

        rv = findViewById(R.id.rvClasses)
        tvSubtitle = findViewById(R.id.tvSubtitle)
        tvEmpty = findViewById(R.id.tvEmpty)
        tvLoading = findViewById(R.id.tvLoading)
        progressBar = findViewById(R.id.progressBar)

        findViewById<ImageButton>(R.id.btnBack).setOnClickListener { finish() }

        adapter = ClassAdapter(mutableListOf()) { fullName ->
            val intent = Intent(this, SourceViewerActivity::class.java).apply {
                putExtra(SourceViewerActivity.EXTRA_CLASS_NAME, fullName)
                putExtra(SourceViewerActivity.EXTRA_JADX_READY, jadxReady)
            }
            startActivity(intent)
        }
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter = adapter

        findViewById<EditText>(R.id.etSearch).addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                adapter.setQuery(s?.toString().orEmpty())
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        val apkPath = intent.getStringExtra(EXTRA_APK_PATH)
        if (apkPath == null) {
            tvEmpty.text = "No APK provided."
            tvEmpty.visibility = View.VISIBLE
            return
        }

        loadAll(File(apkPath))
    }

    private fun loadAll(apk: File) {
        tvLoading.visibility = View.VISIBLE
        progressBar.visibility = View.VISIBLE
        tvSubtitle.text = "Loading classes…"

        Thread {
            // ----- Phase 1: our fast DEX parser -----
            val summary = try {
                DexParser.analyze(apk)
            } catch (e: Throwable) {
                runOnUiThread {
                    tvLoading.visibility = View.GONE
                    progressBar.visibility = View.GONE
                    tvEmpty.text = "DEX parse failed: ${e.message}"
                    tvEmpty.visibility = View.VISIBLE
                }
                return@Thread
            }

            val allClasses = summary.dexFiles
                .flatMap { it.classNames }
                .distinct()
                .sorted()

            runOnUiThread {
                adapter = ClassAdapter(allClasses.toMutableList()) { fullName ->
                    val intent = Intent(this, SourceViewerActivity::class.java).apply {
                        putExtra(SourceViewerActivity.EXTRA_CLASS_NAME, fullName)
                        putExtra(SourceViewerActivity.EXTRA_JADX_READY, jadxReady)
                    }
                    startActivity(intent)
                }
                rv.adapter = adapter
                val q = findViewById<EditText>(R.id.etSearch).text.toString()
                if (q.isNotEmpty()) adapter.setQuery(q)

                tvSubtitle.text = "${allClasses.size} classes · jadx loading…"
                tvLoading.visibility = View.GONE
                progressBar.visibility = View.GONE
                tvEmpty.visibility = if (allClasses.isEmpty()) View.VISIBLE else View.GONE
            }

            // ----- Phase 2: jadx -----
            // Do NOT swallow the error. Capture the message and show it.
            val loadResult = try {
                JadxHolder.ensureLoaded(apk)
            } catch (e: Throwable) {
                JadxHolder.LoadResult(
                    null,
                    "Exception from ensureLoaded: ${e::class.java.simpleName}: ${e.message}",
                    false
                )
            }

            val jadxCount = JadxHolder.loadedClassCount()
            jadxReady = jadxCount > 1

            val errMsg = loadResult.error

            runOnUiThread {
                tvSubtitle.text = when {
                    jadxReady -> "${allClasses.size} classes · jadx ready ($jadxCount)"
                    errMsg != null -> "${allClasses.size} classes · jadx ERROR"
                    else -> "${allClasses.size} classes · jadx loaded $jadxCount"
                }

                // If jadx failed, show the error message right below the title
                if (!jadxReady && errMsg != null) {
                    tvEmpty.text = "jadx error:\n\n$errMsg"
                    tvEmpty.visibility = View.VISIBLE
                }
            }
        }.start()
    }
}