// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Reachability levels the reducer reads. "import" and "module" exist only for a
// package or module scan; stage B refuses those scans, and the fold keeps them
// so the producer table is implemented whole and a parity test can exercise it.
const (
	levelSymbol    = "symbol"
	levelImport    = "import"
	levelNotCalled = "not_called"
	levelModule    = "module"
)

// Scan levels govulncheck reports in its config message.
const (
	scanLevelSymbol  = "symbol"
	scanLevelPackage = "package"
	scanLevelModule  = "module"
)

// stdlibModule is govulncheck's name for the standard library. A finding there
// has no go.mod evidence to anchor it, so the reducer could never join it.
const stdlibModule = "stdlib"

// Finding depths, deepest last.
const (
	depthModule = iota
	depthPackage
	depthFunction
)

// foldedFinding is the one answer for one (advisory, module) pair.
type foldedFinding struct {
	osv            string
	module         string
	level          string
	deepestPackage string
	deepestSymbol  string
	// trace is one call trace in Eshu's order: entry point first, vulnerable
	// symbol last. It is empty unless the level is symbol.
	trace []scanFrame
	// traceCount is how many call traces the scan found for the pair.
	traceCount int
}

// foldFindings folds every finding of one module's scan to one answer per
// (advisory, module) pair. govulncheck reports an advisory several times as the
// scan goes deeper, so the answer comes from the deepest finding of the pair,
// never from one message. It also counts the distinct standard-library pairs it
// drops. A depth the scan level cannot produce is an error: it means the stream
// is not what it claims, and guessing a level would invent a claim.
func foldFindings(scanLevel string, findings []scanFinding) ([]foldedFinding, int, error) {
	type pair struct{ osv, module string }
	grouped := make(map[pair][]scanFinding)
	stdlib := make(map[string]struct{})
	for _, finding := range findings {
		module := finding.Trace[0].Module
		if module == stdlibModule {
			stdlib[finding.OSV] = struct{}{}
			continue
		}
		key := pair{osv: finding.OSV, module: module}
		grouped[key] = append(grouped[key], finding)
	}
	folded := make([]foldedFinding, 0, len(grouped))
	for key, group := range grouped {
		answer, err := foldPair(scanLevel, key.osv, key.module, group)
		if err != nil {
			return nil, 0, err
		}
		folded = append(folded, answer)
	}
	slices.SortFunc(folded, func(a, b foldedFinding) int {
		return cmp.Or(cmp.Compare(a.osv, b.osv), cmp.Compare(a.module, b.module))
	})
	return folded, len(stdlib), nil
}

// foldPair picks the deepest finding of one pair and its level.
func foldPair(scanLevel, osv, module string, group []scanFinding) (foldedFinding, error) {
	answer := foldedFinding{osv: osv, module: module}
	deepest := depthModule
	for _, finding := range group {
		deepest = max(deepest, findingDepth(finding))
	}
	level, err := levelFor(scanLevel, deepest)
	if err != nil {
		return foldedFinding{}, err
	}
	answer.level = level
	switch deepest {
	case depthFunction:
		chosen, count := shortestTrace(group)
		answer.traceCount = count
		answer.deepestPackage = chosen[0].Package
		answer.deepestSymbol = chosen[0].Function
		answer.trace = entryPointFirst(chosen)
	case depthPackage:
		answer.deepestPackage = lowestPackage(group)
	}
	return answer, nil
}

// findingDepth reads how deep one finding goes, by its vulnerable frame.
func findingDepth(finding scanFinding) int {
	switch first := finding.Trace[0]; {
	case first.Function != "":
		return depthFunction
	case first.Package != "":
		return depthPackage
	default:
		return depthModule
	}
}

// levelFor is the SDK producer table. A symbol scan that stops at a package or a
// module is not_called: only a symbol scan can show nothing calls it, and an
// import level from it would be a reachable claim the scan disproved.
func levelFor(scanLevel string, depth int) (string, error) {
	switch scanLevel {
	case scanLevelSymbol:
		if depth == depthFunction {
			return levelSymbol, nil
		}
		return levelNotCalled, nil
	case scanLevelPackage:
		switch depth {
		case depthPackage:
			return levelImport, nil
		case depthModule:
			return levelModule, nil
		}
	case scanLevelModule:
		if depth == depthModule {
			return levelModule, nil
		}
	}
	return "", fmt.Errorf("finding depth %d does not fit scan level %q", depth, scanLevel)
}

// shortestTrace chooses one symbol-level trace deterministically, fewest frames
// then lexically, and counts the symbol-level traces. Message order never
// decides, so retries agree.
func shortestTrace(group []scanFinding) ([]*scanFrame, int) {
	var chosen []*scanFrame
	chosenKey := ""
	count := 0
	for _, finding := range group {
		if findingDepth(finding) != depthFunction {
			continue
		}
		count++
		key := traceKey(finding.Trace)
		if chosen == nil || len(finding.Trace) < len(chosen) || (len(finding.Trace) == len(chosen) && key < chosenKey) {
			chosen, chosenKey = finding.Trace, key
		}
	}
	return chosen, count
}

// traceKey renders a trace for the lexical tie-break.
func traceKey(trace []*scanFrame) string {
	var key strings.Builder
	for _, frame := range trace {
		if frame == nil {
			continue
		}
		key.WriteString(frame.Package)
		key.WriteByte('.')
		key.WriteString(frame.Receiver)
		key.WriteByte('.')
		key.WriteString(frame.Function)
		key.WriteByte('\n')
	}
	return key.String()
}

// entryPointFirst reverses upstream's order into a new slice, so the fold never
// changes its input.
func entryPointFirst(trace []*scanFrame) []scanFrame {
	out := make([]scanFrame, 0, len(trace))
	for i := len(trace) - 1; i >= 0; i-- {
		if trace[i] != nil {
			out = append(out, *trace[i])
		}
	}
	return out
}

// lowestPackage names the package deterministically when a pair reached several.
func lowestPackage(group []scanFinding) string {
	lowest := ""
	for _, finding := range group {
		if pkg := finding.Trace[0].Package; pkg != "" && (lowest == "" || pkg < lowest) {
			lowest = pkg
		}
	}
	return lowest
}
