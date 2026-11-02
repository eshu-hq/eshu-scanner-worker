// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/metrics"
	"strings"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const (
	osReleasePath       = "etc/os-release"
	apkReposPath        = "etc/apk/repositories"
	apkInstalledPath    = "lib/apk/db/installed"
	dpkgStatusPath      = "var/lib/dpkg/status"
	rpmSQLitePath       = "usr/lib/sysimage/rpm/rpmdb.sqlite"
	rpmSQLiteLegacyPath = "var/lib/rpm/rpmdb.sqlite"
	rpmNDBPath          = "var/lib/rpm/Packages.db"
	rpmBDBPath          = "var/lib/rpm/Packages"
	layerRegularFiles   = int64(4)
)

type layerSnapshotReader struct {
	remainingBytes  int64
	inflatedBytes   int64
	compressedBytes int64
	maxInflated     int64
	maxFiles        int64
	filesSeen       int64
	peakBytes       int64
	startCPUSeconds float64
	files           map[string][]byte
	oversizedRPM    map[string]bool
	meter           metaMeter
}

func newLayerSnapshotReader(limits scannerworker.ResourceLimits) *layerSnapshotReader {
	return &layerSnapshotReader{
		remainingBytes:  limits.MaxInputBytes,
		maxFiles:        limits.MaxFiles,
		maxInflated:     inflateBudget(limits.MaxInputBytes),
		startCPUSeconds: currentUserCPUSeconds(),
		files:           make(map[string][]byte, layerRegularFiles),
		oversizedRPM:    make(map[string]bool),
	}
}

func readLayerSnapshot(
	ctx context.Context,
	target TargetConfig,
	limits scannerworker.ResourceLimits,
) (Snapshot, scannerworker.ResourceUsage, error) {
	reader := newLayerSnapshotReader(limits)
	for _, layerPath := range target.LayerPaths {
		if err := reader.readLayer(ctx, layerPath); err != nil {
			if errors.Is(err, errUnsupportedTarget) {
				return unsupportedLayerSnapshot(target, extractionMalformedImage), reader.usage(), err
			}
			return Snapshot{}, reader.usage(), err
		}
	}
	osRelease := reader.files[osReleasePath]
	fields := parseOSRelease(osRelease)
	snapshot := Snapshot{
		Distro:             firstNonBlankDistro(target.Distro, ospackagevulnerability.NormalizeDistroID(ospackagevulnerability.Distro(fields["ID"]))),
		DistroVersion:      firstNonBlank(target.DistroVersion, fields["VERSION_ID"], fields["VERSION"]),
		PackageManager:     target.PackageManager,
		Repositories:       target.Repositories,
		RPMOriginBindings:  target.RPMOriginBindings,
		ThirdPartyPackages: target.ThirdPartyPackages,
		SourceURI:          target.SourceURI,
		SourceRecordID:     target.SourceRecordID,
		ImageReference:     target.ImageReference,
		ImageDigest:        target.ImageDigest,
		EvidenceSource:     EvidenceSourceLayer,
		ExtractionReason:   extractionUnsupported,
	}
	oversizedRPM := rpmLayerDatabaseTooLarge(reader.files, reader.oversizedRPM)
	distro, manager, err := resolvePackageDatabase(target, fields, reader.files, oversizedRPM)
	if err != nil {
		return snapshot, reader.usage(), err
	}
	snapshot.Distro = distro
	snapshot.PackageManager = manager
	snapshot.ExtractionReason = extractionOK
	switch manager {
	case ospackagevulnerability.PackageManagerAPK:
		snapshot.Repositories = alpineRepositories(target.Repositories, reader.files[apkReposPath])
		snapshot.InstalledDB = reader.files[apkInstalledPath]
	case ospackagevulnerability.PackageManagerDPKG:
		snapshot.Status = reader.files[dpkgStatusPath]
	case ospackagevulnerability.PackageManagerRPM:
		snapshot.InstalledDB = rpmLayerDatabase(reader.files)
		snapshot.RPMDatabaseTooLarge = oversizedRPM
	default:
		return Snapshot{}, reader.usage(), fmt.Errorf("%w: unsupported package manager", errUnsupportedTarget)
	}
	return snapshot, reader.usage(), nil
}

func unsupportedLayerSnapshot(target TargetConfig, reason string) Snapshot {
	return Snapshot{
		Distro:             target.Distro,
		DistroVersion:      target.DistroVersion,
		PackageManager:     target.PackageManager,
		Repositories:       target.Repositories,
		RPMOriginBindings:  target.RPMOriginBindings,
		ThirdPartyPackages: target.ThirdPartyPackages,
		SourceURI:          target.SourceURI,
		SourceRecordID:     target.SourceRecordID,
		ImageReference:     target.ImageReference,
		ImageDigest:        target.ImageDigest,
		EvidenceSource:     EvidenceSourceLayer,
		ExtractionReason:   reason,
	}
}

func firstNonBlankDistro(values ...ospackagevulnerability.Distro) ospackagevulnerability.Distro {
	for _, value := range values {
		if strings.TrimSpace(string(value)) != "" {
			return value
		}
	}
	return ""
}

func (r *layerSnapshotReader) readLayer(ctx context.Context, layerPath string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: context canceled", errSourceUnavailable)
	}
	file, err := os.OpenFile(layerPath, readOpenFlags, 0) // #nosec G304 -- reads indexed container image layer at a path derived from the scan target, not user-supplied input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: layer unavailable", errTargetUnavailable)
		}
		return fmt.Errorf("%w: open layer", errTargetUnavailable)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat layer", errTargetUnavailable)
	}
	if info.IsDir() {
		return fmt.Errorf("%w: layer path is directory", errUnsupportedTarget)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: layer path is not a regular file", errUnsupportedTarget)
	}
	if info.Size() > r.remainingBytes {
		return fmt.Errorf("%w: layer byte budget exceeded", errInputLimitExceeded)
	}
	r.remainingBytes -= info.Size()
	r.compressedBytes += info.Size()
	if info.Size() > r.peakBytes {
		r.peakBytes = info.Size()
	}
	tarReader, guard, closeFn, err := r.newLayerTarReader(ctx, file)
	if err != nil {
		if errors.Is(err, errSourceUnavailable) {
			return err
		}
		return fmt.Errorf("%w: unsupported layer archive", errUnsupportedTarget)
	}
	defer closeFn()
	for {
		header, err := tarReader.Next()
		if guard != nil && guard.err != nil {
			return guard.err
		}
		if errors.Is(err, io.EOF) {
			return r.chargeTrailing()
		}
		if err != nil {
			return fmt.Errorf("%w: read layer archive", errUnsupportedTarget)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: context canceled", errSourceUnavailable)
		}
		if err := r.handleEntry(header, tarReader); err != nil {
			if guard != nil && guard.err != nil {
				return guard.err
			}
			return err
		}
		r.meter.arm(r.maxFiles - r.filesSeen)
	}
}

// newLayerTarReader opens the layer as gzip when it parses as gzip and as a
// plain tar otherwise. A gzip layer is read through an inflateGuard; a plain
// tar inflates nothing, so its bytes stay charged once as the layer size.
func (r *layerSnapshotReader) newLayerTarReader(ctx context.Context, file *os.File) (*tar.Reader, *inflateGuard, func(), error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, func() {}, err
	}
	gzipReader, err := gzip.NewReader(ctxReader{ctx: ctx, src: file})
	if err == nil {
		guard := &inflateGuard{ctx: ctx, src: gzipReader, budget: r}
		r.meter = newMetaMeter(func() int64 { return r.inflatedBytes }, r.maxFiles-r.filesSeen)
		return tar.NewReader(guard), guard, func() { _ = gzipReader.Close() }, nil
	}
	if errors.Is(err, errSourceUnavailable) {
		return nil, nil, func() {}, err
	}
	if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
		return nil, nil, func() {}, seekErr
	}
	tracked := &trackedFile{file: file}
	r.meter = newMetaMeter(func() int64 { return tracked.pos }, r.maxFiles-r.filesSeen)
	return tar.NewReader(tracked), nil, func() {}, nil
}

func (r layerSnapshotReader) usage() scannerworker.ResourceUsage {
	cpuSeconds := currentUserCPUSeconds() - r.startCPUSeconds
	if cpuSeconds < 0 {
		cpuSeconds = 0
	}
	return scannerworker.ResourceUsage{CPUSeconds: cpuSeconds, PeakMemoryBytes: r.peakBytes}
}

func isPackageEvidencePath(name string) bool {
	switch name {
	case osReleasePath, apkReposPath, apkInstalledPath, dpkgStatusPath, rpmSQLitePath, rpmSQLiteLegacyPath, rpmNDBPath, rpmBDBPath:
		return true
	default:
		return false
	}
}

func resolvePackageDatabase(
	target TargetConfig,
	fields map[string]string,
	files map[string][]byte,
	oversizedRPM bool,
) (ospackagevulnerability.Distro, ospackagevulnerability.PackageManager, error) {
	distro := target.Distro
	if distro == "" {
		distro = ospackagevulnerability.NormalizeDistroID(ospackagevulnerability.Distro(fields["ID"]))
	}
	manager := target.PackageManager
	if manager == "" {
		switch {
		case len(files[apkInstalledPath]) > 0:
			manager = ospackagevulnerability.PackageManagerAPK
		case len(files[dpkgStatusPath]) > 0:
			manager = ospackagevulnerability.PackageManagerDPKG
		case len(rpmLayerDatabase(files)) > 0 || oversizedRPM:
			manager = ospackagevulnerability.PackageManagerRPM
		case distro == ospackagevulnerability.DistroAlpine:
			manager = ospackagevulnerability.PackageManagerAPK
		case distro == ospackagevulnerability.DistroDebian:
			manager = ospackagevulnerability.PackageManagerDPKG
		}
	}
	if err := validateDistro(distro); err != nil {
		return "", "", err
	}
	if err := validatePackageManager(manager); err != nil {
		return "", "", err
	}
	switch manager {
	case ospackagevulnerability.PackageManagerAPK:
		if distro != ospackagevulnerability.DistroAlpine || len(files[apkInstalledPath]) == 0 {
			return "", "", fmt.Errorf("%w: missing apk installed database", errUnsupportedTarget)
		}
	case ospackagevulnerability.PackageManagerDPKG:
		if distro != ospackagevulnerability.DistroDebian || len(files[dpkgStatusPath]) == 0 {
			return "", "", fmt.Errorf("%w: missing dpkg status database", errUnsupportedTarget)
		}
	case ospackagevulnerability.PackageManagerRPM:
		if strings.TrimSpace(string(distro)) == "" || firstNonBlank(target.DistroVersion, fields["VERSION_ID"], fields["VERSION"]) == "" {
			return "", "", fmt.Errorf("%w: missing rpm distro identity", errUnsupportedTarget)
		}
		if len(rpmLayerDatabase(files)) == 0 && !oversizedRPM {
			return "", "", fmt.Errorf("%w: missing rpm database", errUnsupportedTarget)
		}
	default:
		return "", "", fmt.Errorf("%w: missing supported package database", errUnsupportedTarget)
	}
	return distro, manager, nil
}

func alpineRepositories(configured []ospackagevulnerability.Repository, body []byte) []ospackagevulnerability.Repository {
	if len(configured) > 0 {
		return configured
	}
	var repos []ospackagevulnerability.Repository
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		repos = append(repos, ospackagevulnerability.Repository{
			URL:   trimmed,
			Class: ospackagevulnerability.ClassifyAlpineRepositoryURL(trimmed),
		})
	}
	return repos
}

func parseOSRelease(body []byte) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key != "" {
			fields[key] = value
		}
	}
	return fields
}

func currentUserCPUSeconds() float64 {
	samples := []metrics.Sample{{Name: "/cpu/classes/user:cpu-seconds"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	return samples[0].Value.Float64()
}

func rpmLayerDatabase(files map[string][]byte) []byte {
	for _, path := range []string{rpmSQLitePath, rpmSQLiteLegacyPath, rpmNDBPath, rpmBDBPath} {
		if len(files[path]) > 0 {
			return files[path]
		}
	}
	return nil
}

func isRPMDatabasePath(name string) bool {
	switch name {
	case rpmSQLitePath, rpmSQLiteLegacyPath, rpmNDBPath, rpmBDBPath:
		return true
	default:
		return false
	}
}

func rpmLayerDatabaseTooLarge(files map[string][]byte, oversized map[string]bool) bool {
	for _, path := range []string{rpmSQLitePath, rpmSQLiteLegacyPath, rpmNDBPath, rpmBDBPath} {
		if oversized[path] {
			return true
		}
		if len(files[path]) > 0 {
			return false
		}
	}
	return false
}
