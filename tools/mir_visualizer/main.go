package main

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler/MIR"
)

type session struct {
	cfg      *MIR.CFG
	bytecode []byte
}

var (
	sessMu sync.Mutex
	sess   = make(map[string]*session)
)

func main() {
	http.HandleFunc("/", serveIndex)
	// Backwards-compatible: parse-only endpoint returning DOT text.
	http.HandleFunc("/visualize", handleVisualize)
	// New interactive endpoints:
	// - /init: parse CFG once and store it (so runtime can expand it)
	// - /run: execute MIR with calldata, expanding CFG, and return updated DOT
	http.HandleFunc("/init", handleInit)
	http.HandleFunc("/run", handleRun)

	fmt.Println("Starting MIR Visualizer at http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "tools/mir_visualizer/index.html")
}

func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ToLower(s)
	return s
}

func decodeHexBytes(hexStr string) ([]byte, error) {
	hexStr = normalizeHex(hexStr)
	if hexStr == "" {
		return nil, fmt.Errorf("empty hex")
	}
	// Allow odd-length hex (treat as leading 0 nibble), consistent with many tooling conventions.
	if len(hexStr)%2 == 1 {
		hexStr = "0" + hexStr
	}
	return hex.DecodeString(hexStr)
}

func sessionIDForBytecode(code []byte) string {
	sum := sha256.Sum256(code)
	return hex.EncodeToString(sum[:])
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

	bytecode, err := decodeHexBytes(string(body))
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

type initResp struct {
	SessionID string `json:"sessionId"`
	DOT       string `json:"dot"`
}

func handleInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}
	bytecode, err := decodeHexBytes(string(body))
	if err != nil {
		http.Error(w, "Invalid hex string: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg := MIR.NewCFG(common.Hash{}, bytecode)
	if err := cfg.Parse(); err != nil {
		http.Error(w, "Parse error: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := sessionIDForBytecode(bytecode)

	sessMu.Lock()
	sess[id] = &session{cfg: cfg, bytecode: bytecode}
	sessMu.Unlock()

	out := initResp{SessionID: id, DOT: cfg.ToDot()}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

type runReq struct {
	SessionID string `json:"sessionId"`
	Calldata  string `json:"calldata"`
}
type runResp struct {
	DOT        string `json:"dot"`
	ReturnHex  string `json:"returnHex"`
	GasUsed    uint64 `json:"gasUsed"`
	GasLeft    uint64 `json:"gasLeft"`
	HaltOp     string `json:"haltOp"`
	Err        string `json:"err,omitempty"`
	ExpandedTo string `json:"expandedTo,omitempty"`
}

func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req runReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.SessionID == "" {
		http.Error(w, "missing sessionId", http.StatusBadRequest)
		return
	}
	calldata, err := decodeHexBytes(req.Calldata)
	if err != nil && normalizeHex(req.Calldata) != "" {
		http.Error(w, "Invalid calldata hex: "+err.Error(), http.StatusBadRequest)
		return
	}

	sessMu.Lock()
	s := sess[req.SessionID]
	sessMu.Unlock()
	if s == nil || s.cfg == nil {
		http.Error(w, "unknown sessionId (parse/init again)", http.StatusBadRequest)
		return
	}

	// Execute MIR to allow runtime dynamic CFG expansion to backfill edges/blocks.
	it := MIR.NewMIRInterpreter(s.cfg)
	it.SetGasLimit(10_000_000)
	it.SetCallData(calldata)
	res := it.Run()

	out := runResp{
		DOT:       s.cfg.ToDot(),
		ReturnHex: "0x" + hex.EncodeToString(res.ReturnData),
		GasUsed:   res.GasUsed,
		GasLeft:   res.GasLeft,
		HaltOp:    res.HaltOp.String(),
	}
	if res.Err != nil {
		out.Err = res.Err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

