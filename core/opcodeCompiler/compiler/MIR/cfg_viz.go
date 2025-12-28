package MIR

import (
	"fmt"
	"strings"
)

// ToDot returns a Graphviz DOT representation of the CFG.
func (c *CFG) ToDot() string {
	var sb strings.Builder
	sb.WriteString("digraph CFG {\n")
	sb.WriteString("  rankdir=TB;\n") // Top to Bottom layout
	sb.WriteString("  node [shape=box, fontname=\"Courier\"];\n")

	for _, block := range c.basicBlocks {
		// Node Label: Block ID + PC Range + stack heights
		entryH := 0
		if block.entryStack != nil {
			entryH = len(block.entryStack)
		}
		exitH := 0
		if block.exitStack != nil {
			exitH = len(block.exitStack)
		}
		label := fmt.Sprintf(
			"Block %d\\nPC: %d..%d\\nStack: in=%d out=%d",
			block.blockNum,
			block.firstPC,
			block.lastPC,
			entryH,
			exitH,
		)
		if block.unresolvedJump {
			label += "\\n(unresolved jump)"
		}

		// Add instructions to the label for debugging
		// We limit the number of instructions shown to keep graph readable
		const maxInstrShown = 20
		count := 0
		for _, mir := range block.instructions {
			if count >= maxInstrShown {
				label += "\\n..."
				break
			}

			opStr := fmt.Sprintf("%s (0x%02x)", mir.op.String(), byte(mir.op))
			// Simple operand formatting
			if len(mir.operands) > 0 {
				opStr += " ["
				for i, opnd := range mir.operands {
					if i > 0 {
						opStr += ", "
					}
					if opnd != nil {
						if opnd.kind == Konst {
							opStr += "const"
						} else {
							opStr += "var"
						}
					} else {
						opStr += "?"
					}
				}
				opStr += "]"
			}

			// Escape quotes for DOT format
			opStr = strings.ReplaceAll(opStr, "\"", "\\\"")
			label += fmt.Sprintf("\\n%s", opStr)
			count++
		}

		// Write Node definition
		sb.WriteString(fmt.Sprintf("  %d [label=\"%s\"];\n", block.blockNum, label))

		// Write Edges to children
		for _, child := range block.children {
			sb.WriteString(fmt.Sprintf("  %d -> %d;\n", block.blockNum, child.blockNum))
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}
