// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"go/version"
	"path"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// requirement is one require line with its replace applied.
type requirement struct {
	modulePath         string
	requiredVersion    string
	indirect           bool
	lineNumber         int
	replacementPath    string
	replacementVersion string
	replaceFromVersion string
}

// goModule is one parsed go.mod.
type goModule struct {
	relativePath string
	dir          string
	modulePath   string
	goVersion    string
	toolchain    string
	requirements []requirement
	// invalidPaths counts the requires dropped for text that must not reach a fact.
	invalidPaths int
}

// parseGoMod parses one go.mod. It uses the strict modfile.Parse because
// modfile.ParseLax drops replace directives, and that parser does not validate
// paths, so this does. The parse error is not returned to callers as text: it
// quotes the file.
func parseGoMod(relativePath string, body []byte) (goModule, error) {
	parsed, err := modfile.Parse(relativePath, body, nil)
	if err != nil {
		return goModule{}, err
	}
	parsedModule := goModule{relativePath: relativePath, dir: path.Dir(relativePath)}
	if parsed.Module != nil {
		parsedModule.modulePath = parsed.Module.Mod.Path
		if !isValidModulePath(parsedModule.modulePath) {
			parsedModule.invalidPaths++
			return parsedModule, nil
		}
	}
	if parsed.Go != nil {
		parsedModule.goVersion = parsed.Go.Version
	}
	if parsed.Toolchain != nil {
		parsedModule.toolchain = parsed.Toolchain.Name
	}
	replaces := newReplaceIndex(parsed.Replace)
	seen := make(map[[2]string]struct{}, len(parsed.Require))
	for _, require := range parsed.Require {
		key := [2]string{require.Mod.Path, require.Mod.Version}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		item := requirement{
			modulePath:      require.Mod.Path,
			requiredVersion: require.Mod.Version,
			indirect:        require.Indirect,
		}
		if require.Syntax != nil {
			item.lineNumber = require.Syntax.Start.Line
		}
		if match := replaces.match(item.modulePath, item.requiredVersion); match != nil {
			item.replacementPath = match.New.Path
			item.replacementVersion = match.New.Version
			item.replaceFromVersion = match.Old.Version
		}
		if !item.isSafe() {
			parsedModule.invalidPaths++
			continue
		}
		parsedModule.requirements = append(parsedModule.requirements, item)
	}
	return parsedModule, nil
}

// isSafe reports whether every string of a requirement may reach a fact.
func (r requirement) isSafe() bool {
	return isValidModulePath(r.modulePath) && isSafeText(r.requiredVersion) && isSafeText(r.replacementPath) && isSafeText(r.replacementVersion)
}

// isValidModulePath applies the go command's own import path rule. It is
// module.CheckImportPath and not module.CheckPath, because a private module with no
// dot in its first element is a real require that CheckPath would drop.
func isValidModulePath(modulePath string) bool {
	return module.CheckImportPath(modulePath) == nil
}

// replaceIndex is a go.mod's replaces, keyed for a lookup per require. A linear
// scan per require made one hostile file quadratic.
type replaceIndex struct {
	exact    map[[2]string]*modfile.Replace
	anyMatch map[string]*modfile.Replace
}

func newReplaceIndex(replaces []*modfile.Replace) replaceIndex {
	index := replaceIndex{
		exact:    make(map[[2]string]*modfile.Replace, len(replaces)),
		anyMatch: make(map[string]*modfile.Replace, len(replaces)),
	}
	for _, candidate := range replaces {
		if candidate.Old.Version == "" {
			if _, taken := index.anyMatch[candidate.Old.Path]; !taken {
				index.anyMatch[candidate.Old.Path] = candidate
			}
			continue
		}
		key := [2]string{candidate.Old.Path, candidate.Old.Version}
		if _, taken := index.exact[key]; !taken {
			index.exact[key] = candidate
		}
	}
	return index
}

// match applies Go's replace rule: a replace naming this exact version wins over
// one naming only the module path.
func (i replaceIndex) match(modulePath, moduleVersion string) *modfile.Replace {
	if candidate, ok := i.exact[[2]string{modulePath, moduleVersion}]; ok {
		return candidate
	}
	return i.anyMatch[modulePath]
}

// exceedsToolchain reports whether a go.mod's go or toolchain directive asks for
// more than the pinned toolchain. It reads the directives as text and runs no
// toolchain, so a file the strict parser rejects still reports its directive.
func exceedsToolchain(body []byte, pinned string) bool {
	for line := range strings.Lines(string(body)) {
		code, _, _ := strings.Cut(line, "//")
		fields := strings.Fields(code)
		if len(fields) != 2 {
			continue
		}
		wanted := ""
		switch fields[0] {
		case "go":
			wanted = "go" + fields[1]
		case "toolchain":
			wanted = fields[1]
		default:
			continue
		}
		if version.IsValid(wanted) && version.Compare(wanted, pinned) > 0 {
			return true
		}
	}
	return false
}

// pinnedToolchain normalizes runtime.Version output, which may append build
// experiments, to the toolchain name.
func pinnedToolchain(raw string) string {
	name, _, _ := strings.Cut(strings.TrimSpace(raw), " ")
	return name
}
