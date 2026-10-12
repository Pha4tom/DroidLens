package com.Cali.droidlens

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ClassTreeAdapter(
    private val rootNodes: List<ClassTreeNode>,
    private val onClassTap: (ClassTreeNode.Klass) -> Unit
) : RecyclerView.Adapter<ClassTreeAdapter.VH>() {

    private val rendered = mutableListOf<RenderItem>()
    private var isSearchMode = false
    private var query = ""

    data class RenderItem(val node: ClassTreeNode, val fromSearch: Boolean)

    init {
        rebuildTree()
    }

    private fun rebuildTree() {
        rendered.clear()
        for (node in rootNodes) addVisible(node)
    }

    private fun addVisible(node: ClassTreeNode) {
        rendered.add(RenderItem(node, false))
        if (node.expanded) {
            for (child in node.children) addVisible(child)
        }
    }

    fun toggleExpand(node: ClassTreeNode) {
        if (isSearchMode) return
        node.expanded = !node.expanded
        rebuildTree()
        notifyDataSetChanged()
    }

    fun setQuery(q: String) {
        query = q.trim()
        isSearchMode = query.isNotEmpty()
        rendered.clear()
        if (isSearchMode) {
            collectMatching(rootNodes, query.lowercase())
        } else {
            rebuildTree()
        }
        notifyDataSetChanged()
    }

    private fun collectMatching(nodes: List<ClassTreeNode>, lower: String) {
        if (rendered.size >= 500) return  // cap for perf
        for (node in nodes) {
            if (node is ClassTreeNode.Klass && node.fullName.lowercase().contains(lower)) {
                rendered.add(RenderItem(node, true))
            }
            collectMatching(node.children, lower)
            if (rendered.size >= 500) return
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_class, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(h: VH, position: Int) {
        val item = rendered[position]
        val node = item.node
        val density = h.itemView.resources.displayMetrics.density

        // Indentation based on tree depth
        val baseIndent = (12 * density).toInt()
        val indentPerLevel = (18 * density).toInt()
        val leftPad = baseIndent + (node.depth.coerceAtLeast(0) * indentPerLevel)
        h.itemView.setPaddingRelative(
            leftPad,
            h.itemView.paddingTop,
            h.itemView.paddingEnd,
            h.itemView.paddingBottom
        )

        when (node) {
            is ClassTreeNode.Package -> {
                h.icon.text = "📁"
                h.name.text = node.displayName
                h.meta.text = "${node.childCount} item${if (node.childCount == 1) "" else "s"}"
                h.arrow.visibility = if (node.hasChildren) View.VISIBLE else View.GONE
                h.arrow.text = if (node.expanded) "▾" else "▸"
                h.itemView.setOnClickListener { toggleExpand(node) }
            }
            is ClassTreeNode.Klass -> {
                h.icon.text = if (node.isInner) "•" else "📄"
                h.name.text = node.displayName
                h.meta.text = if (node.isInner) "inner" else classifyClass(node.fullName)
                if (node.hasChildren) {
                    h.arrow.visibility = View.VISIBLE
                    h.arrow.text = if (node.expanded) "▾" else "▸"
                    h.arrow.setOnClickListener { toggleExpand(node) }
                } else {
                    h.arrow.visibility = View.GONE
                    h.arrow.setOnClickListener(null)
                }
                h.itemView.setOnClickListener { onClassTap(node) }
            }
        }
    }

    private fun classifyClass(fullName: String): String {
        val lower = fullName.lowercase()
        return when {
            lower.startsWith("androidx.") -> "library"
            lower.startsWith("com.google.") -> "library"
            lower.startsWith("kotlin") -> "library"
            lower.startsWith("android.") -> "framework"
            else -> "app"
        }
    }

    override fun getItemCount() = rendered.size

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val arrow: TextView = v.findViewById(R.id.tvArrow)
        val icon: TextView = v.findViewById(R.id.tvIcon)
        val name: TextView = v.findViewById(R.id.tvClassName)
        val meta: TextView = v.findViewById(R.id.tvClassMeta)
    }
}