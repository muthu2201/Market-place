// Package clamdsim is a local server that speaks clamd's INSTREAM protocol:
// the same commands, the same length-prefixed framing, the same replies.
//
// It exists for the same reason the payment gateway simulator does. The code
// under test is then the REAL antivirus client — its framing, its chunking, its
// reply parsing and its error classification — rather than a mock that returns
// whatever it was told to. A mocked Scanner interface would prove only that the
// mock works.
//
// What it deliberately does NOT simulate, and what therefore still has to be
// exercised against a real clamd before go-live:
//   - a real signature database and its false-positive behaviour,
//   - clamd's own StreamMaxLength and the mid-transfer termination it causes,
//   - memory and concurrency limits under a real scanning workload.
//
// Verdicts here follow the EICAR convention: the industry-standard antivirus
// test string is reported as a threat, and everything else is clean. That is
// enough to exercise every branch of the client without shipping malware in a
// repository.
package clamdsim

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// EICAR is the industry-standard antivirus test file. Every real scanner
// reports it as a threat, which makes it the one payload that can safely be
// committed and still prove the infected path works end to end.
const EICAR = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// Harness is a running simulator.
type Harness struct {
	t  *testing.T
	ln net.Listener
	wg sync.WaitGroup

	mu       sync.Mutex
	scans    int
	lastSeen []byte
}

// Start listens on a loopback port and stops with the test.
func Start(t *testing.T) *Harness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("clamdsim: listen: %v", err)
	}
	h := &Harness{t: t, ln: ln}
	h.wg.Add(1)
	go h.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		h.wg.Wait()
	})
	return h
}

// Address is what to configure as CLAMAV_ADDRESS.
func (h *Harness) Address() string { return h.ln.Addr().String() }

// Scans is how many streams have been scanned, for a test that needs to assert
// the scanner was actually reached.
func (h *Harness) Scans() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.scans
}

// LastBytes returns the most recently scanned stream, so a test can assert the
// scanner saw exactly what was uploaded.
func (h *Harness) LastBytes() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]byte(nil), h.lastSeen...)
}

func (h *Harness) serve() {
	defer h.wg.Done()
	for {
		conn, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer conn.Close()
			h.handle(conn)
		}()
	}
}

func (h *Harness) handle(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))

	cmd, err := readCommand(conn)
	if err != nil {
		return
	}
	switch cmd {
	case "PING":
		_, _ = conn.Write([]byte("PONG\x00"))
		return
	case "VERSION":
		_, _ = conn.Write([]byte("ClamAV 1.0.5/27100/simulated\x00"))
		return
	case "INSTREAM":
	default:
		_, _ = conn.Write([]byte("UNKNOWN COMMAND\x00"))
		return
	}

	// Reassemble the length-prefixed chunks exactly as clamd does. A client
	// that framed them wrongly produces garbage here rather than a pass.
	var body bytes.Buffer
	for {
		var length [4]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(length[:])
		if n == 0 {
			break
		}
		if n > 4<<20 {
			_, _ = conn.Write([]byte("stream: INSTREAM size limit exceeded ERROR\x00"))
			return
		}
		if _, err := io.CopyN(&body, conn, int64(n)); err != nil {
			return
		}
	}

	h.mu.Lock()
	h.scans++
	h.lastSeen = body.Bytes()
	h.mu.Unlock()

	if bytes.Contains(body.Bytes(), []byte(EICAR)) {
		_, _ = conn.Write([]byte("stream: Win.Test.EICAR_HDB-1 FOUND\x00"))
		return
	}
	_, _ = conn.Write([]byte("stream: OK\x00"))
}

// readCommand reads clamd's "z<COMMAND>\0" framing.
func readCommand(conn net.Conn) (string, error) {
	buf := make([]byte, 0, 32)
	one := make([]byte, 1)
	for len(buf) < 32 {
		if _, err := io.ReadFull(conn, one); err != nil {
			return "", err
		}
		if one[0] == 0 {
			break
		}
		buf = append(buf, one[0])
	}
	return strings.TrimPrefix(string(buf), "z"), nil
}
