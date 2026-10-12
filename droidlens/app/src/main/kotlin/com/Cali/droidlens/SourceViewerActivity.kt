package com.Cali.droidlens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class SourceViewerActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_CLASS_NAME = "class_name"
        const val EXTRA_JADX_READY = "jadx_ready"
    }

    private lateinit var tvClassName: TextView
    private lateinit var tvClassMeta: TextView
    private lateinit var tvSource: TextView
    private lateinit var progressBar: View
    private var sourceCode: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_source_viewer)

        tvClassName = findViewById(R.id.tvClassName)
        tvClassMeta = findViewById(R.id.tvClassMeta)
        tvSource = findViewById(R.id.tvSource)
        progressBar = findViewById(R.id.progressBar)

        findViewById<ImageButton>(R.id.btnBack).setOnClickListener { finish() }

        findViewById<ImageButton>(R.id.btnCopy).setOnClickListener {
            if (sourceCode.isNotEmpty()) {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("source", sourceCode))
                Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
            }
        }

        val fullName = intent.getStringExtra(EXTRA_CLASS_NAME)
        if (fullName.isNullOrEmpty()) {
            tvSource.text = "No class name provided."
            return
        }

        tvClassName.text = fullName

        // If jadx wasn't ready when the class was tapped, wait for it here.
        val jadxWasReady = intent.getBooleanExtra(EXTRA_JADX_READY, true)
        if (!jadxWasReady) {
            waitForJadxThenDecompile(fullName)
        } else {
            decompile(fullName)
        }
    }

    private fun waitForJadxThenDecompile(fullName: String) {
        progressBar.visibility = View.VISIBLE
        tvSource.text = "Waiting for jadx to finish loading…"
        tvClassMeta.text = "waiting"

        Thread {
            // Poll up to 60 seconds for jadx to be ready
            var waited = 0
            while (waited < 60_000) {
                if (JadxHolder.loadedClassCount() > 1) break
                Thread.sleep(500)
                waited += 500
            }
            runOnUiThread { decompile(fullName) }
        }.start()
    }

    private fun decompile(fullName: String) {
        progressBar.visibility = View.VISIBLE
        tvSource.text = "Decompiling…"
        tvClassMeta.text = "working"

        Thread {
            val code: String? = try {
                JadxHolder.decompileClass(fullName)
            } catch (e: Throwable) {
                "// Unexpected error: ${e::class.java.simpleName}: ${e.message}"
            }

            runOnUiThread {
                progressBar.visibility = View.GONE

                if (code == null) {
                    tvSource.text = "// Decompilation returned null.\n" +
                            "// jadx loaded ${JadxHolder.loadedClassCount()} classes.\n" +
                            "// If this is 1, the DEX input plugin did not register."
                    tvClassMeta.text = "failed"
                    return@runOnUiThread
                }

                sourceCode = code
                tvSource.text = code
                val lines = code.count { ch -> ch == '\n' } + 1
                tvClassMeta.text = "$lines lines"
            }
        }.start()
    }
}