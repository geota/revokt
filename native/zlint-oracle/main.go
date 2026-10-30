// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// Command zlint-oracle records the pinned zlint result of spec §9.2 for D8-gap entries: zlint (pinned in go.mod) run
// over a certificate parsed by zcrypto. It is its own module so that zlint's zcrypto never moves the producer's pin
// (native/producer-oracle). It reads one base64 DER certificate per line on stdin and writes one line per input:
//
//	LINT <errors> <fatals> <warnings>
//	UNPARSEABLE <error>
//	PANIC <error>
//
// <errors> are the lints with status error, <fatals> those with status fatal (the lint could not run: it failed to
// decode what it checks, or panicked) and <warnings> those with status warn, each comma-joined in name order, or "-"
// when there are none. Warnings may drift across re-records: a few lints consult the current time. A line "##" ends a
// batch: it is echoed and stdout is flushed (spec §9.1). It is a test oracle: never linked, bundled or published
// (CONTRIBUTING §3).
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

// result is the oracle's answer for one certificate.
func result(der []byte) (r string) {
	defer func() {
		if p := recover(); p != nil {
			r = "PANIC " + oneLine(fmt.Errorf("%v", p))
		}
	}()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "UNPARSEABLE " + oneLine(err)
	}
	var errs, fatals, warns []string
	for name, lr := range zlint.LintCertificate(cert).Results {
		switch lr.Status {
		case lint.Error:
			errs = append(errs, name)
		case lint.Fatal:
			fatals = append(fatals, name)
		case lint.Warn:
			warns = append(warns, name)
		}
	}
	return fmt.Sprintf("LINT %s %s %s", joined(errs), joined(fatals), joined(warns))
}

func joined(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// pointer is a Go memory address as fmt prints a pointer field, which zcrypto's asn1 errors embed (the field
// parameters' tag): it differs on every run, so the oracle writes it as "0x?" (#67).
var pointer = regexp.MustCompile(`0x[0-9a-f]{8,}`)

func oneLine(err error) string {
	return pointer.ReplaceAllString(strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error()), "0x?")
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20) // base64 of RevoktLimits.MAX_CERT_BYTES + 1 fits
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		switch {
		case line == "##":
			fmt.Fprintln(out, "##")
			out.Flush()
		case line == "":
			fmt.Fprintln(out, "UNPARSEABLE empty input")
		default:
			der, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				fmt.Fprintln(out, "UNPARSEABLE base64: "+oneLine(err))
				continue
			}
			fmt.Fprintln(out, result(der))
		}
	}
	if err := in.Err(); err != nil {
		out.Flush()
		fmt.Fprintln(os.Stderr, "zlint-oracle:", err)
		os.Exit(1)
	}
}
