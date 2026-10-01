package com.Cali.droidlens

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ClassAdapter(
    private val fullList: MutableList<String>,
    private val onTap: (String) -> Unit
) : RecyclerView.Adapter<ClassAdapter.VH>() {

    private val filtered: MutableList<String> = fullList.toMutableList()
    private var query: String = ""

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val name: TextView = v.findViewById(R.id.tvClassName)
        val meta: TextView = v.findViewById(R.id.tvClassMeta)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_class, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(h: VH, position: Int) {
        val full = filtered[position]
        h.name.text = full
        h.meta.text = when {
            full.startsWith("androidx.") -> "library"
            full.startsWith("com.google.") -> "library"
            full.startsWith("kotlin") -> "library"
            full.startsWith("android.") -> "framework"
            else -> "app"
        }
        h.itemView.setOnClickListener { onTap(full) }
    }

    override fun getItemCount(): Int = filtered.size

    fun setQuery(q: String) {
        query = q.trim()
        filtered.clear()
        if (query.isEmpty()) {
            filtered.addAll(fullList)
        } else {
            val lower = query.lowercase()
            for (c in fullList) {
                if (c.lowercase().contains(lower)) {
                    filtered.add(c)
                    if (filtered.size >= 500) break  // cap for perf
                }
            }
        }
        notifyDataSetChanged()
    }
}