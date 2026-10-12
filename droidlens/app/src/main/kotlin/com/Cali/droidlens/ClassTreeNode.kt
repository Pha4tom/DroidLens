package com.Cali.droidlens

sealed class ClassTreeNode {
    abstract val displayName: String
    abstract val fullName: String
    abstract var depth: Int
    var expanded: Boolean = false
    val children: MutableList<ClassTreeNode> = mutableListOf()

    val hasChildren: Boolean get() = children.isNotEmpty()
    val childCount: Int get() = children.size

    class Package(
        override var displayName: String,
        override val fullName: String,
        override var depth: Int
    ) : ClassTreeNode()

    class Klass(
        override val displayName: String,
        override val fullName: String,
        override var depth: Int,
        val isInner: Boolean
    ) : ClassTreeNode()
}

object ClassTreeBuilder {

    fun build(classNames: List<String>): List<ClassTreeNode> {
        val root = ClassTreeNode.Package("", "", -1)
        for (name in classNames) {
            insertClass(root, name)
        }
        sortRecursive(root)
        compact(root)
        reindexDepths(root, 0)
        return root.children.toList()
    }

    private fun insertClass(root: ClassTreeNode.Package, fullName: String) {
        // Split inner class chain: "com.foo.Bar$a$b" → outer = "com.foo.Bar", inners = ["a", "b"]
        val dollarIdx = fullName.indexOf('$')
        val outerPart = if (dollarIdx >= 0) fullName.substring(0, dollarIdx) else fullName
        val innerParts = if (dollarIdx >= 0) fullName.substring(dollarIdx + 1).split('$') else emptyList()

        val segments = outerPart.split('.').filter { it.isNotEmpty() }
        if (segments.isEmpty()) return

        val className = segments.last()
        val packageSegments = segments.dropLast(1)

        // Walk package chain
        var currentPkg = root
        var currentPath = ""
        for (pkg in packageSegments) {
            currentPath = if (currentPath.isEmpty()) pkg else "$currentPath.$pkg"
            val existing = currentPkg.children.firstOrNull {
                it is ClassTreeNode.Package && it.displayName == pkg
            } as? ClassTreeNode.Package
            currentPkg = existing ?: run {
                val newNode = ClassTreeNode.Package(
                    displayName = pkg,
                    fullName = currentPath,
                    depth = currentPkg.depth + 1
                )
                currentPkg.children.add(newNode)
                newNode
            }
        }

        // Create class node
        val classFullName = if (currentPath.isEmpty()) className else "$currentPath.$className"
        val classNode = currentPkg.children.firstOrNull {
            it is ClassTreeNode.Klass && it.fullName == classFullName
        } as? ClassTreeNode.Klass ?: run {
            val newNode = ClassTreeNode.Klass(
                displayName = className,
                fullName = classFullName,
                depth = currentPkg.depth + 1,
                isInner = false
            )
            currentPkg.children.add(newNode)
            newNode
        }

        // Walk inner classes
        var innerParent: ClassTreeNode = classNode
        var innerPath = classFullName
        for (innerName in innerParts) {
            innerPath = "$innerPath\$$innerName"
            val existing = innerParent.children.firstOrNull {
                it is ClassTreeNode.Klass && it.displayName == innerName
            } as? ClassTreeNode.Klass
            innerParent = existing ?: run {
                val newNode = ClassTreeNode.Klass(
                    displayName = innerName,
                    fullName = innerPath,
                    depth = innerParent.depth + 1,
                    isInner = true
                )
                innerParent.children.add(newNode)
                newNode
            }
        }
    }

    private fun sortRecursive(node: ClassTreeNode) {
        node.children.sortWith(
            compareBy(
                { it is ClassTreeNode.Klass },   // packages before classes
                { it.displayName.lowercase() }
            )
        )
        for (child in node.children) sortRecursive(child)
    }

    /**
     * Compact linear package chains: `com` → `example` → `bet` becomes
     * a single `com.example.bet` row when each level has exactly one child.
     */
    private fun compact(node: ClassTreeNode) {
        for (child in node.children.toList()) compact(child)

        val newChildren = mutableListOf<ClassTreeNode>()
        for (child in node.children) {
            if (child is ClassTreeNode.Package) {
                var curDisplay = child.displayName
                var curFullName = child.fullName
                var curChildren = child.children
                var curExpanded = child.expanded
                var safety = 0
                while (curChildren.size == 1 && curChildren[0] is ClassTreeNode.Package && safety < 20) {
                    val next = curChildren[0] as ClassTreeNode.Package
                    curDisplay = "$curDisplay.${next.displayName}"
                    curFullName = next.fullName
                    curExpanded = curExpanded || next.expanded
                    curChildren = next.children
                    safety++
                }
                val merged = ClassTreeNode.Package(
                    displayName = curDisplay,
                    fullName = curFullName,
                    depth = child.depth
                )
                merged.expanded = curExpanded
                merged.children.addAll(curChildren)
                newChildren.add(merged)
            } else {
                newChildren.add(child)
            }
        }
        node.children.clear()
        node.children.addAll(newChildren)
    }

    private fun reindexDepths(node: ClassTreeNode, depth: Int) {
        node.depth = depth
        for (child in node.children) reindexDepths(child, depth + 1)
    }
}