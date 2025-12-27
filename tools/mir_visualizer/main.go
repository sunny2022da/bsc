package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler/MIR"
)

func main() {
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/visualize", handleVisualize)

	fmt.Println("Starting MIR Visualizer at http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "tools/mir_visualizer/index.html")
}

func handleVisualize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	// Clean up input (remove 0x prefix, whitespace)
	hexStr := strings.TrimSpace(string(body))
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, " ", "")

	bytecode, err := hex.DecodeString(hexStr)
	if err != nil {
		http.Error(w, "Invalid hex string: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create and Parse CFG
	cfg := MIR.NewCFG(common.Hash{}, bytecode)
	if err := cfg.Parse(); err != nil {
		http.Error(w, "Parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Generate DOT
	dot := cfg.ToDot()

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(dot))
}

