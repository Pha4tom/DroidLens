package com.Cali.droidlens

object ExportedComponents {

    data class Component(
        val kind: String,
        val name: String,
        val permission: String?,
        val authorities: String?,
        val actions: List<String>,
        val categories: List<String>
    )

    fun find(xml: String): List<Component> {
        val out = mutableListOf<Component>()
        val lines = xml.lines()

        var kind: String? = null
        var attrs: String = ""
        val actions = mutableListOf<String>()
        val categories = mutableListOf<String>()

        fun flush() {
            val k = kind ?: return
            flushComponent(out, k, attrs, actions.toList(), categories.toList())
            kind = null
            actions.clear()
            categories.clear()
        }

        for (raw in lines) {
            val line = raw.trim()
            when {
                line.startsWith("<activity") -> { flush(); kind = "activity"; attrs = line }
                line.startsWith("<service") -> { flush(); kind = "service"; attrs = line }
                line.startsWith("<receiver") -> { flush(); kind = "receiver"; attrs = line }
                line.startsWith("<provider") -> { flush(); kind = "provider"; attrs = line }
                line.startsWith("</activity") || line.startsWith("</service") ||
                line.startsWith("</receiver") || line.startsWith("</provider") -> flush()
                kind != null && line.contains("android.intent.action.") -> {
                    Regex("""android\.intent\.action\.([A-Z0-9_]+)""")
                        .find(line)?.groupValues?.get(1)?.let { actions.add(it) }
                }
                kind != null && line.contains("android.intent.category.") -> {
                    Regex("""android\.intent\.category\.([A-Z0-9_]+)""")
                        .find(line)?.groupValues?.get(1)?.let { categories.add(it) }
                }
            }
        }
        flush()
        return out
    }

    private fun flushComponent(
        out: MutableList<Component>,
        kind: String,
        attrs: String,
        actions: List<String>,
        categories: List<String>
    ) {
        val name = attr(attrs, "name") ?: return
        val exportedAttr = attr(attrs, "exported")
        val permission = attr(attrs, "permission")
        val authorities = attr(attrs, "authorities")

        val isExported = when (exportedAttr) {
            "true" -> true
            "false" -> false
            // Legacy: no exported attr + has intent-filter = implicitly exported
            null -> actions.isNotEmpty() || categories.isNotEmpty()
            else -> false
        }
        if (!isExported) return

        out.add(Component(kind, name, permission, authorities, actions, categories))
    }

    private fun attr(tag: String, name: String): String? =
        Regex("""\s$name="([^"]*)"""").find(tag)?.groupValues?.get(1)

    fun format(list: List<Component>): String {
        if (list.isEmpty()) {
            return "None.\n\nNo components are exported — no other app on the device " +
                    "can directly launch or bind to this app's internals."
        }
        return buildString {
            for (c in list) {
                append("[${c.kind.uppercase()}]\n")
                append("  ${c.name}\n")
                c.permission?.let { append("  permission: $it\n") }
                c.authorities?.let { append("  authorities: $it\n") }
                for (a in c.actions) append("  → $a\n")
                for (cat in c.categories) append("  # $cat\n")
                append("\n")
            }
        }.trimEnd()
    }
}