package com.Cali.droidlens

import android.util.Log

object IntentFuzzer {

    private const val TAG = "DroidLens.Fuzzer"

    data class FuzzResult(
        val componentName: String,
        val payloadKind: String,
        val crashed: Boolean,
        val exceptionName: String?,
        val stackSnippet: String?,
        val message: String
    )

    private open class Payload(val name: String, val args: Array<String>)
    private class SimplePayload(name: String, vararg args: String) : Payload(name, arrayOf(*args))

    /**
     * Two families of payloads:
     *  - STRING: malformed string values on a generic key
     *  - TYPE:   correct-key / wrong-type to trigger ClassCastException
     *
     * The generic key "extra" won't match real components. Type confusion
     * still catches apps that blindly call getStringExtra() on an int extra,
     * or vice versa. Null delivery catches apps that don't null-check.
     */
    private val PAYLOADS: List<Payload> = listOf(
        // ── string family ────────────────────────────────────────────
        SimplePayload("empty-string",     "--es", "extra", ""),
        SimplePayload("long-string",      "--es", "extra", "A".repeat(2048)),
        SimplePayload("path-traversal",   "--es", "extra", "../../../etc/passwd"),
        SimplePayload("format-string",    "--es", "extra", "%s%s%s%n%n%n"),
        SimplePayload("null-string",      "--esn", "extra"),

        // ── type confusion family ────────────────────────────────────
        SimplePayload("int-as-string",    "--ei", "extra", "2147483647"),
        SimplePayload("long-as-string",   "--el", "extra", "9223372036854775807"),
        SimplePayload("bool-as-string",   "--ez", "extra", "true"),
        SimplePayload("float-as-string",  "--ef", "extra", "1.5"),
        SimplePayload("uri-as-string",    "--eu", "extra", "content://invalid"),
    )

    fun fuzz(
        packageName: String,
        activityNames: List<String>,
        onProgress: (String) -> Unit = {}
    ): List<FuzzResult> {
        if (!ShizukuManager.isReady) {
            return listOf(FuzzResult("", "", false, null, null, "Shizuku not ready."))
        }

        val (installedOut, _) = ShizukuManager.execShell(
            arrayOf("pm", "list", "packages", packageName)
        )
        if (!installedOut.contains(packageName)) {
            return listOf(
                FuzzResult("", "", false, null, null,
                    "Package $packageName is not installed. Install the APK first.")
            )
        }

        val results = mutableListOf<FuzzResult>()
        val cap = 5
        val targets = activityNames.take(cap)
        val payloads = PAYLOADS

        Log.d(TAG, "Starting fuzz: ${targets.size} targets × ${payloads.size} payloads")
        onProgress("Starting: ${targets.size} components × ${payloads.size} payloads")

        for ((ai, activity) in targets.withIndex()) {
            for ((pi, payload) in payloads.withIndex()) {
                val tag = "[${ai + 1}/${targets.size}] " +
                        "${activity.substringAfterLast('.')} · " +
                        "${payload.name} (${pi + 1}/${payloads.size})"
                try {
                    onProgress("$tag\nforce-stop…")
                    ShizukuManager.forceStop(packageName)
                    safeSleep(200)

                    onProgress("$tag\nbaseline log…")
                    val baseline = ShizukuManager.dumpLogcat(60)

                    onProgress("$tag\nfiring intent…")
                    val cmd = mutableListOf(
                        "am", "start",
                        "-n", "$packageName/$activity"
                    )
                    cmd.addAll(payload.args)
                    val (_, amErr) = ShizukuManager.execShell(cmd.toTypedArray())

                    if (amErr.contains("Error", ignoreCase = true) ||
                        amErr.contains("does not exist", ignoreCase = true)) {
                        Log.w(TAG, "$tag am-error: $amErr")
                        results.add(
                            FuzzResult(
                                componentName = activity,
                                payloadKind = payload.name,
                                crashed = false,
                                exceptionName = null,
                                stackSnippet = null,
                                message = "am error: ${amErr.take(120)}"
                            )
                        )
                        continue
                    }

                    safeSleep(800)

                    onProgress("$tag\nanalyzing log…")
                    val after = ShizukuManager.dumpLogcat(200)
                    val newLines = linesInAfterNotBefore(after, baseline)
                    val crash = extractCrash(newLines, packageName)

                    Log.d(TAG, "$tag → ${if (crash != null) "CRASH ${crash.first}" else "no crash"} (${newLines.size} new lines)")

                    results.add(
                        FuzzResult(
                            componentName = activity,
                            payloadKind = payload.name,
                            crashed = crash != null,
                            exceptionName = crash?.first,
                            stackSnippet = crash?.second,
                            message = crash?.let { "CRASH: ${it.first}" } ?: "no crash"
                        )
                    )
                } catch (e: Throwable) {
                    Log.e(TAG, "$tag threw: ${e.javaClass.simpleName}: ${e.message}", e)
                    results.add(
                        FuzzResult(
                            componentName = activity,
                            payloadKind = payload.name,
                            crashed = false,
                            exceptionName = null,
                            stackSnippet = null,
                            message = "iteration threw: ${e.javaClass.simpleName}: ${e.message}"
                        )
                    )
                }
            }
        }

        Log.d(TAG, "Fuzz complete: ${results.size} iterations logged")
        onProgress("Done.")
        return results
    }

    fun format(results: List<FuzzResult>): String {
        if (results.isEmpty()) return "No results."

        if (results.size == 1 && results[0].componentName.isEmpty()) {
            return "⚠ Fuzzer did not run\n\n${results[0].message}"
        }

        val crashes = results.filter { it.crashed }
        val uniqueComponents = results.map { it.componentName }
            .filter { it.isNotEmpty() }
            .distinct()
            .size
        val errors = results.filter {
            it.message.startsWith("am error") || it.message.startsWith("iteration threw")
        }

        val sb = StringBuilder()

        if (crashes.isEmpty()) {
            sb.append("No crashes observed across ")
              .append(results.size)
              .append(" payload(s).\n")
            sb.append("Components tested: ").append(uniqueComponents).append('\n')
            if (errors.isNotEmpty()) {
                sb.append("\nWarnings: ").append(errors.size).append('\n')
                for (e in errors.take(3)) {
                    sb.append("  · ").append(e.componentName.substringAfterLast('.'))
                      .append(" — ").append(e.message).append('\n')
                }
            }
            return sb.toString()
        }

        sb.append("⚠ ").append(crashes.size)
          .append(" crash(es) across ")
          .append(uniqueComponents)
          .append(" component(s) of ")
          .append(results.size)
          .append(" total payload(s).\n\n")

        // Group crashes by component so repeats don't spam
        val grouped = crashes.groupBy { it.componentName }
        for ((component, list) in grouped) {
            sb.append("[CRASH] ").append(component.substringAfterLast('.')).append('\n')
            val payloads = list.map { it.payloadKind }.distinct()
            sb.append("  payloads: ").append(payloads.joinToString(", ")).append('\n')
            val causes = list.mapNotNull { it.exceptionName }.distinct()
            sb.append("  cause:    ").append(causes.joinToString(", ")).append('\n')
            sb.append('\n')
        }

        return sb.toString().trimEnd()
    }

    // ──────────────────────────────────────────────────────────────
    // internals
    // ──────────────────────────────────────────────────────────────

    private fun safeSleep(ms: Long) {
        try { Thread.sleep(ms) } catch (_: InterruptedException) { }
    }

    private fun linesInAfterNotBefore(after: String, before: String): List<String> {
        val baseline = before.lines().toHashSet()
        return after.lines().filter { it.isNotBlank() && it !in baseline }
    }

    private fun extractCrash(lines: List<String>, packageName: String): Pair<String, String>? {
        var seenFatal = false
        var exception: String? = null
        val stack = mutableListOf<String>()

        for (line in lines) {
            if (!seenFatal && line.contains("FATAL EXCEPTION")) {
                seenFatal = true
                continue
            }
            if (!seenFatal) continue

            if (exception == null) {
                val m = Regex("""([A-Za-z_][A-Za-z0-9_.]*(Exception|Error))""").find(line)
                if (m != null) exception = m.value
            }
            stack.add(line.trim())
            if (stack.size >= 6) break
        }

        val combined = stack.joinToString("\n")
        if (exception == null) return null
        if (!combined.contains(packageName) && !lines.any { it.contains(packageName) }) return null

        return exception to combined
    }
}