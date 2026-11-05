// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// defaultCloneHost is the only host the token may reach unless the operator names
// others through the activation's allowed_clone_hosts.
const defaultCloneHost = "github.com"

var (
	// cloneHostPattern is a lowercase DNS name with at least two labels and a
	// final label that is not numeric, so no form of an IP literal, a port, or a
	// single-label name such as localhost can pass.
	cloneHostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]*[a-z-][a-z0-9-]*$`)
	// clonePathSegmentPattern is one lowercase path segment. Core normalizes the
	// path to lowercase, and refusing "%" keeps an encoded dot segment away from
	// curl's path handling.
	clonePathSegmentPattern = regexp.MustCompile(`^[a-z0-9._~-]+$`)
)

// ValidateCloneHosts checks the operator's allowed_clone_hosts. The list replaces
// the default, so it must name at least one host. Errors never echo a value.
func ValidateCloneHosts(hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("allowed_clone_hosts must name at least one host")
	}
	for _, host := range hosts {
		if !cloneHostPattern.MatchString(host) || strings.HasSuffix(host, "-") {
			return errors.New("allowed_clone_hosts entry is not a lowercase host name")
		}
	}
	return nil
}

// cloneURLOrigin allows only a plain URL on an allowed transport and returns its
// scheme://host. Rejecting everything else keeps option-shaped values and git's
// remote helpers (ext::, fd::) away from the git command line. An https URL must
// also be a canonical remote on an allowed host, because the token follows it.
// Other transports exist only through the test seam Options.AllowedSchemes.
func cloneURLOrigin(raw string, schemes, hosts []string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n\\") {
		return "", errors.New("clone_url is not a plain URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("clone_url is not a plain URL")
	}
	if !slices.Contains(schemes, parsed.Scheme) {
		return "", errors.New("clone_url uses a transport this component does not allow")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("clone_url must not carry userinfo, a query, or a fragment")
	}
	if parsed.Scheme != "file" && parsed.Host == "" {
		return "", errors.New("clone_url has no host")
	}
	if parsed.Scheme == "https" {
		if err := checkCanonicalRemote(raw, parsed.Host, hosts); err != nil {
			return "", err
		}
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// checkCanonicalRemote mirrors core's scannercomponent.ValidCloneURL, which
// accepts only what repositoryidentity.NormalizeRemoteURL leaves unchanged: no
// port, a lowercase host and path, no .git suffix, no empty or dot segment, and at
// least an owner and a repository. The host comes from the URL's whole authority,
// so a port or a trailing colon never matches an allowed name.
func checkCanonicalRemote(raw, host string, hosts []string) error {
	if !slices.Contains(hosts, host) {
		return errors.New("clone_url host is not in allowed_clone_hosts")
	}
	segments := strings.Split(strings.TrimPrefix(raw, "https://"+host+"/"), "/")
	if len(segments) < 2 {
		return errors.New("clone_url must name an owner and a repository")
	}
	for _, segment := range segments {
		if !clonePathSegmentPattern.MatchString(segment) || strings.Trim(segment, ".") == "" {
			return errors.New("clone_url path is not canonical")
		}
	}
	if strings.HasSuffix(raw, ".git") {
		return errors.New("clone_url path is not canonical")
	}
	return nil
}
