package com.Cali.droidlens

import android.content.pm.PackageManager
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuRemoteProcess
import java.lang.reflect.Method

object ShizukuManager {

    const val REQUEST_CODE = 1001

    var isReady = false
        private set

    fun init() {
        Shizuku.addBinderReceivedListenerSticky {
            refresh()
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                try { Shizuku.requestPermission(REQUEST_CODE) } catch (_: Throwable) { }
            }
        }
        Shizuku.addBinderDeadListener { isReady = false }
        Shizuku.addRequestPermissionResultListener { _, grantResult ->
            isReady = grantResult == PackageManager.PERMISSION_GRANTED
        }
        refresh()
    }

    private fun refresh() {
        isReady = try {
            Shizuku.pingBinder() &&
                    Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        } catch (_: Throwable) { false }
    }

    /**
     * Executes a shell command with shell (adb) privileges.
     * Returns Pair(stdout, stderr).
     */
    fun execShell(cmd: Array<String>): Pair<String, String> {
    if (!isReady) return "" to "Shizuku not ready"
    return try {
        val method = Shizuku::class.java.getDeclaredMethod(
            "newProcess",
            Array<String>::class.java,
            Array<String>::class.java,
            String::class.java
        )
        method.isAccessible = true
        val process = method.invoke(null, cmd, null, null) as ShizukuRemoteProcess
        val out = process.inputStream.bufferedReader().use { it.readText() }
        val err = process.errorStream.bufferedReader().use { it.readText() }
        process.waitFor()
        process.destroy()
        out.trim() to err.trim()
    } catch (e: Throwable) {
        "" to "Exception: ${e.javaClass.simpleName}: ${e.message}"
    }
}

    /**
     * Force-stops the target package using `am force-stop` under the shell UID.
     */
    fun forceStop(packageName: String): Boolean {
        if (!isReady) return false
        val (_, err) = execShell(arrayOf("am", "force-stop", packageName))
        return err.isEmpty()
    }

    /**
     * Launches a specific component by fully-qualified name.
     * Works even if the component is not exported.
     */
    fun startActivity(
        packageName: String,
        activityName: String,
        extras: Map<String, String> = emptyMap()
    ): Boolean {
        if (!isReady) return false
        val cmd = mutableListOf(
            "am", "start",
            "-n", "$packageName/$activityName"
        )
        for ((k, v) in extras) {
            cmd.add("--es"); cmd.add(k); cmd.add(v)
        }
        val (_, err) = execShell(cmd.toTypedArray())
        return !err.contains("Error", ignoreCase = true)
    }

    /**
     * Dumps the recent logcat buffer. Default: last 300 lines.
     */
    fun dumpLogcat(lines: Int = 300): String {
        if (!isReady) return ""
        val (out, _) = execShell(arrayOf("logcat", "-d", "-t", lines.toString()))
        return out
    }
}