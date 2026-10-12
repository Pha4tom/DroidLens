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
    private lateinit var adapter: ClassTreeAdapter
    private lateinit var tvSubtitle: TextView
    private lateinit var tvEmpty: TextView
    private lateinit var tvLoading: TextView
    private lateinit var progressBar: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_class_browser)

        rv = findViewById(R.id.rvClasses)
        tvSubtitle = findViewById(R.id.tvSubtitle)
        tvEmpty = findViewById(R.id.tvEmpty)
        tvLoading = findViewById(R.id.tvLoading)
        progressBar = findViewById(R.id.progressBar)

        findViewById<ImageButton>(R.id.btnBack).setOnClickListener { finish() }

        val apkPath = intent.getStringExtra(EXTRA_APK_PATH)
        if (apkPath == null) {
            tvEmpty.text = "No APK provided."
            tvEmpty.visibility = View.VISIBLE
            return
        }

        loadClasses(File(apkPath))
    }

    private fun loadClasses(apk: File) {
        tvLoading.visibility = View.VISIBLE
        progressBar.visibility = View.VISIBLE
        tvSubtitle.text = "Loading…"

        Thread {
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

            val tree = ClassTreeBuilder.build(allClasses)

            runOnUiThread {
                adapter = ClassTreeAdapter(tree) { klass ->
                    val intent = Intent(this, SourceViewerActivity::class.java).apply {
                        putExtra(SourceViewerActivity.EXTRA_CLASS_NAME, klass.fullName)
                        putExtra(SourceViewerActivity.EXTRA_JADX_READY, true)
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

                tvSubtitle.text = "${allClasses.size} classes · ${tree.size} roots"
                tvLoading.visibility = View.GONE
                progressBar.visibility = View.GONE
                tvEmpty.visibility = if (allClasses.isEmpty()) View.VISIBLE else View.GONE
            }

            try { JadxHolder.ensureLoaded(apk) } catch (_: Throwable) { }
        }.start()
    }
}