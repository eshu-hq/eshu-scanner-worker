// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"go/version"
	"path"
	"strings"

	"golang.org/x/mod/modfile"
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
}

// parseGoMod parses one go.mod. It uses the strict modfile.Parse because
// modfile.ParseLax drops replace directives. The parse error is not returned to
// callers as text: it quotes the file.
func parseGoMod(relativePath string, body []byte) (goModule, error) {
	parsed, err := modfile.Parse(relativePath, body, nil)
	if err != nil {
		return goModule{}, err
	}
	module := goModule{relativePath: relativePath, dir: path.Dir(relativePath)}
	if parsed.Module != nil {
		module.modulePath = parsed.Module.Mod.Path
	}
	if parsed.Go != nil {
		module.goVersion = parsed.Go.Version
	}
	if parsed.Toolchain != nil {
		module.toolchain = parsed.Toolchain.Name
	}
	seen := make(map[string]struct{}, len(parsed.Require))
	for _, require := range parsed.Require {
		key := require.Mod.Path + "\x00" + require.Mod.Version
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
		if match := matchReplace(item.modulePath, item.requiredVersion, parsed.Replace); match != nil {
			item.replacementPath = match.New.Path
			item.replacementVersion = match.New.Version
			item.replaceFromVersion = match.Old.Version
		}
		module.requirements = append(module.requirements, item)
	}
	return module, nil
}

// matchReplace applies Go's replace rule: a replace naming this exact version
// wins over one naming only the module path.
func matchReplace(modulePath, moduleVersion string, replaces []*modfile.Replace) *modfile.Replace {
	var pathMatch *modfile.Replace
	for _, candidate := range replaces {
		if candidate.Old.Path != modulePath {
			continue
		}
		if candidate.Old.Version == moduleVersion {
			return candidate
		}
		if candidate.Old.Version == "" && pathMatch == nil {
			pathMatch = candidate
		}
	}
	return pathMatch
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
