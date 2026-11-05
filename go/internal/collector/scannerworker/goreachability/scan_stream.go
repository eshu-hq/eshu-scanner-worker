// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// maxScanStreamBytes bounds one module's govulncheck output. The bulk is osv
// message bodies, which the parser reads and discards one value at a time; a
// real run measured under a megabyte, so a stream past this bound is not a scan
// this component can trust.
const maxScanStreamBytes = int64(256 * 1024 * 1024)

var errScanStreamTooLarge = errors.New("govulncheck output above the byte bound")

// scanConfig is the upstream govulncheck config message.
type scanConfig struct {
	ProtocolVersion string `json:"protocol_version"`
	ScannerName     string `json:"scanner_name"`
	ScannerVersion  string `json:"scanner_version"`
	DBLastModified  string `json:"db_last_modified"`
	GoVersion       string `json:"go_version"`
	ScanLevel       string `json:"scan_level"`
	ScanMode        string `json:"scan_mode"`
}

// scanPosition is the upstream position object. It is an object on the wire, not
// a string.
type scanPosition struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// scanFrame is one upstream trace frame. Upstream lists the vulnerable symbol
// first and the entry point last.
type scanFrame struct {
	Module   string        `json:"module"`
	Version  string        `json:"version"`
	Package  string        `json:"package"`
	Function string        `json:"function"`
	Receiver string        `json:"receiver"`
	Position *scanPosition `json:"position"`
}

// scanFinding is one upstream finding message.
type scanFinding struct {
	OSV   string       `json:"osv"`
	Trace []*scanFrame `json:"trace"`
}

// scanStream is one module's parsed output.
type scanStream struct {
	config   *scanConfig
	findings []scanFinding
}

// parseScanStream parses a whole govulncheck stream under the default bound.
func parseScanStream(reader io.Reader) (scanStream, error) {
	return parseBoundedScanStream(reader, maxScanStreamBytes)
}

// parseBoundedScanStream decodes one JSON value at a time. A value that does not
// decode, a second config, or a finding with no advisory or module fails the
// whole stream: dropping one silently would turn a called advisory into a missing
// or not-called one. An unknown message type is not a failure.
func parseBoundedScanStream(reader io.Reader, limit int64) (scanStream, error) {
	counted := &cappedReader{reader: reader, remaining: limit}
	decoder := json.NewDecoder(counted)
	var stream scanStream
	for {
		var message map[string]json.RawMessage
		err := decoder.Decode(&message)
		if errors.Is(err, io.EOF) {
			return stream, nil
		}
		if err != nil {
			if counted.exceeded {
				return scanStream{}, errScanStreamTooLarge
			}
			return scanStream{}, errors.New("govulncheck output did not decode")
		}
		if err := stream.add(message); err != nil {
			return scanStream{}, err
		}
	}
}

// add reads the two message types this parser keeps.
func (s *scanStream) add(message map[string]json.RawMessage) error {
	if raw, ok := message["config"]; ok {
		if s.config != nil {
			return errors.New("govulncheck output holds a second config")
		}
		var config scanConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return errors.New("govulncheck config did not decode")
		}
		s.config = &config
	}
	raw, ok := message["finding"]
	if !ok {
		return nil
	}
	var finding scanFinding
	if err := json.Unmarshal(raw, &finding); err != nil {
		return errors.New("govulncheck finding did not decode")
	}
	if strings.TrimSpace(finding.OSV) == "" || len(finding.Trace) == 0 || finding.Trace[0] == nil || strings.TrimSpace(finding.Trace[0].Module) == "" {
		return errors.New("govulncheck finding names no advisory or module")
	}
	s.findings = append(s.findings, finding)
	return nil
}

// cappedReader fails a read past its budget.
type cappedReader struct {
	reader    io.Reader
	remaining int64
	exceeded  bool
}

// Read implements io.Reader.
func (c *cappedReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.exceeded = true
		return 0, errScanStreamTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	read, err := c.reader.Read(p)
	c.remaining -= int64(read)
	return read, err
}
