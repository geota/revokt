// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// Command producer-oracle is oracle 4 of spec §9.2: Mozilla's CRLite producer code (mozilla/crlite go/types,
// pinned in go.mod) asked whether it can key a certificate and with which bytes. It reads one base64 DER
// certificate per line on stdin and writes one line per input:
//
//	OK <serial-hex> <spki-sha256-hex> <ct|lax|zc>
//	REJECT <error>
//
// A line "##" ends a batch: it is echoed and stdout is flushed (spec §9.1). The serial is the producer's
// NewSerialFromCertificate bytes; the SPKI is the certificate's own RawSubjectPublicKeyInfo as the producer
// records it (the key's SPKI when the certificate is an issuer); the last field says which parser accepted
// (ct = certificate-transparency-go's strict parse: ParseCertificate without a lax retry, non-fatal x509
// errors allowed; lax = ct-go only through one of its "lax" retries; zc = the zcrypto fallback). A panic anywhere in the producer is a REJECT, as it
// would stop ct-fetch from keying the certificate (spec §9.2 D8: a crash counts as a rejection).
// It is a test oracle: never linked, bundled or published (CONTRIBUTING §3).
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	types "github.com/mozilla/crlite/go"
)

// Verdict is the oracle's answer for one certificate.
func verdict(der []byte) (v string) {
	defer func() {
		if r := recover(); r != nil {
			v = "REJECT " + oneLine(fmt.Errorf("producer panic: %v", r))
		}
	}()
	cert, err := types.ParseCertificate(der)
	if cert == nil {
		return "REJECT " + oneLine(err)
	}
	serial, perr := keyedSerial(cert)
	if perr != nil {
		return "REJECT " + oneLine(perr)
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo())
	// types.ParseCertificate tries certificate-transparency-go first and falls back to zcrypto; ask the first
	// directly, since types.Certificate does not expose which one it kept.
	which := "zc"
	if ct, cerr := ctx509.ParseCertificate(der); ct != nil {
		which = "ct"
		if usedLax(cerr) {
			which = "lax"
		}
	}
	return fmt.Sprintf("OK %s %s %s", serial, hex.EncodeToString(spki[:]), which)
}

// usedLax reports whether ct-go accepted only through a "lax" retry: every retry site in x509.go records the strict
// parse's own asn1 error as a non-fatal error, while every other non-fatal error is an x509 message (the SCT branch
// wraps its asn1 errors), so an asn1 error type in NonFatalErrors marks the lax path.
func usedLax(err error) bool {
	var nfe ctx509.NonFatalErrors
	if !errors.As(err, &nfe) {
		return false
	}
	for _, e := range nfe.Errors {
		switch e.(type) {
		case ctasn1.StructuralError, ctasn1.SyntaxError, *ctasn1.StructuralError, *ctasn1.SyntaxError:
			return true
		}
	}
	return false
}

func keyedSerial(cert *types.Certificate) (s string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("NewSerialFromCertificate panic: %v", r)
		}
	}()
	return types.NewSerialFromCertificate(cert).HexString(), nil
}

func oneLine(err error) string {
	if err == nil {
		return "nil error"
	}
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
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
			// An empty DER base64-encodes to an empty line; answer it so replies stay one per input.
			fmt.Fprintln(out, "REJECT empty input")
		default:
			der, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				fmt.Fprintln(out, "REJECT base64: "+oneLine(err))
				continue
			}
			fmt.Fprintln(out, verdict(der))
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "producer-oracle:", err)
		os.Exit(1)
	}
}
