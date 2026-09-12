package antivirus

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// EICAR is the industry-standard antivirus test file. Every real scanner
// reports it as a threat, which makes it the one payload that can be committed
// to a repository to prove the infected path works end to end.
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// fakeClamd speaks the real clamd wire protocol.
//
// It is a test double at the network boundary, for the same reason the payment
// gateway simulator is: the code under test is then the real client, including
// its framing, its chunking and its reply parsing. A mocked Scanner interface
// would prove only that the mock returns what it was told to.
type fakeClamd struct {
	t       *testing.T
	ln      net.Listener
	wg      sync.WaitGroup
	verdict func(received []byte) string

	mu       sync.Mutex
	commands []string
	received []byte
}

func startFakeClamd(t *testing.T, verdict func([]byte) string) *fakeClamd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeClamd{t: t, ln: ln, verdict: verdict}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		f.wg.Wait()
	})
	return f
}

func (f *fakeClamd) addr() string { return f.ln.Addr().String() }

func (f *fakeClamd) serve() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer conn.Close()
			f.handle(conn)
		}()
	}
}

func (f *fakeClamd) handle(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	cmd, err := readCommand(conn)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.commands = append(f.commands, cmd)
	f.mu.Unlock()

	switch cmd {
	case "PING":
		_, _ = conn.Write([]byte("PONG\x00"))
		return
	case "VERSION":
		_, _ = conn.Write([]byte("ClamAV 1.0.5/27100/Thu Sep 11 2026\x00"))
		return
	case "INSTREAM":
	default:
		_, _ = conn.Write([]byte("UNKNOWN COMMAND\x00"))
		return
	}

	// Reassemble the length-prefixed chunks exactly as clamd would. A client
	// that framed them wrongly produces garbage here, not a passing test.
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
		if n > 1<<20 {
			_, _ = conn.Write([]byte("stream: INSTREAM size limit exceeded ERROR\x00"))
			return
		}
		if _, err := io.CopyN(&body, conn, int64(n)); err != nil {
			return
		}
	}

	f.mu.Lock()
	f.received = body.Bytes()
	f.mu.Unlock()

	_, _ = conn.Write([]byte(f.verdict(body.Bytes()) + "\x00"))
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

func (f *fakeClamd) bytesReceived() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.received
}

func (f *fakeClamd) commandsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// signatureVerdict answers the way clamd does: FOUND for EICAR, OK otherwise.
func signatureVerdict(b []byte) string {
	if bytes.Contains(b, []byte(eicar)) {
		return "stream: Win.Test.EICAR_HDB-1 FOUND"
	}
	return "stream: OK"
}

func newTestScanner(t *testing.T, addr string) *ClamAV {
	t.Helper()
	c, err := NewClamAV(Config{Driver: "clamav", Address: addr, Timeout: 10 * time.Second},
		func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatalf("NewClamAV: %v", err)
	}
	return c
}

func TestScanCleanFile(t *testing.T) {
	f := startFakeClamd(t, signatureVerdict)
	c := newTestScanner(t, f.addr())

	body := []byte("%PDF-1.7\n" + strings.Repeat("harmless content ", 500))
	res, err := c.Scan(context.Background(), bytes.NewReader(body),
		ScanOptions{Filename: "guide.pdf", DeclaredType: "application/pdf"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Status != StatusClean {
		t.Errorf("status = %q, want clean (reason: %s)", res.Status, res.Reason)
	}
	if !res.Publishable() {
		t.Error("a clean asset must be publishable")
	}
	if res.Bytes != int64(len(body)) {
		t.Errorf("scanned %d bytes, sent %d", res.Bytes, len(body))
	}
	if res.DetectedType != "application/pdf" {
		t.Errorf("detected %q, want application/pdf", res.DetectedType)
	}
}

// TestScanTransmitsExactBytes is the point of using the real protocol: if the
// framing were wrong, the scanner would be examining something other than what
// the buyer will download, and every other test here would still pass.
func TestScanTransmitsExactBytes(t *testing.T) {
	f := startFakeClamd(t, signatureVerdict)
	c := newTestScanner(t, f.addr())

	// Larger than one chunk, so multi-chunk framing is exercised, and with a
	// byte pattern that would show any reordering or truncation.
	body := make([]byte, 300_000)
	for i := range body {
		body[i] = byte(i * 7 % 251)
	}

	if _, err := c.Scan(context.Background(), bytes.NewReader(body), ScanOptions{Filename: "big.bin"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := f.bytesReceived(); !bytes.Equal(got, body) {
		t.Fatalf("scanner received %d bytes, sent %d; contents equal: %v",
			len(got), len(body), bytes.Equal(got, body))
	}
	if cmds := f.commandsSeen(); len(cmds) != 1 || cmds[0] != "INSTREAM" {
		t.Errorf("commands = %v, want exactly [INSTREAM]", cmds)
	}
}

func TestScanDetectsEICAR(t *testing.T) {
	f := startFakeClamd(t, signatureVerdict)
	c := newTestScanner(t, f.addr())

	res, err := c.Scan(context.Background(), strings.NewReader(eicar),
		ScanOptions{Filename: "bundle.zip", DeclaredType: "application/zip"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Status != StatusInfected {
		t.Fatalf("status = %q, want infected", res.Status)
	}
	if res.Signature != "Win.Test.EICAR_HDB-1" {
		t.Errorf("signature = %q, want the matched threat name", res.Signature)
	}
	if res.Publishable() {
		t.Fatal("an infected asset must never be publishable")
	}
}

// TestScanReportsTypeMismatchOnCleanBytes: clean by signature and dishonest
// about what it is are different findings, and the second still holds the asset.
func TestScanReportsTypeMismatchOnCleanBytes(t *testing.T) {
	f := startFakeClamd(t, signatureVerdict)
	c := newTestScanner(t, f.addr())

	res, err := c.Scan(context.Background(), bytes.NewReader([]byte("MZ\x90\x00\x03\x00\x00\x00padding")),
		ScanOptions{Filename: "helvetica.otf", DeclaredType: "font/otf"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Status != StatusSuspicious {
		t.Fatalf("status = %q, want suspicious", res.Status)
	}
	if res.Publishable() {
		t.Fatal("a suspicious asset must not be publishable")
	}
	if !strings.Contains(res.Reason, "executable") {
		t.Errorf("reason %q does not explain the finding", res.Reason)
	}
}

// TestScanErrorIsNotClean is the most important property in this file. A
// scanner that cannot answer must never be read as having answered "fine".
func TestScanErrorIsNotClean(t *testing.T) {
	f := startFakeClamd(t, func([]byte) string { return "stream: Can't allocate memory ERROR" })
	c := newTestScanner(t, f.addr())

	res, err := c.Scan(context.Background(), strings.NewReader("content"), ScanOptions{Filename: "a.bin"})
	if err != nil {
		t.Fatalf("a scanner error reply is a verdict, not a transport failure: %v", err)
	}
	if res.Status != StatusError {
		t.Fatalf("status = %q, want error", res.Status)
	}
	if res.Publishable() {
		t.Fatal("an unscannable asset must never be publishable")
	}
	if res.Reason == "" {
		t.Error("an error status must carry the scanner's explanation")
	}
}

// TestScanUnavailableScannerFails covers the outage case. It must surface as
// ErrUnavailable so the worker retries, and must not produce a clean result.
func TestScanUnavailableScannerFails(t *testing.T) {
	c := newTestScanner(t, "127.0.0.1:1")

	res, err := c.Scan(context.Background(), strings.NewReader("content"), ScanOptions{Filename: "a.bin"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if res.Publishable() {
		t.Fatal("an unreachable scanner must never yield a publishable result")
	}
}

func TestScanRefusesOversizedStream(t *testing.T) {
	f := startFakeClamd(t, signatureVerdict)
	c, err := NewClamAV(Config{Driver: "clamav", Address: f.addr(), MaxBytes: 1024},
		func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}

	// Declared size over the limit is refused before a byte is transferred.
	if _, err := c.Scan(context.Background(), strings.NewReader("x"),
		ScanOptions{Filename: "big.bin", Size: 2048}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("declared oversize: error = %v, want ErrTooLarge", err)
	}

	// Undeclared size is caught mid-transfer, which is what protects against a
	// reader that lies about its length.
	if _, err := c.Scan(context.Background(), bytes.NewReader(make([]byte, 4096)),
		ScanOptions{Filename: "big.bin"}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("undeclared oversize: error = %v, want ErrTooLarge", err)
	}
}

func TestPingAndVersion(t *testing.T) {
	f := startFakeClamd(t, signatureVerdict)
	c := newTestScanner(t, f.addr())

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !strings.HasPrefix(v, "ClamAV") {
		t.Errorf("version = %q", v)
	}
	if err := newTestScanner(t, "127.0.0.1:1").Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("ping to a dead address: error = %v, want ErrUnavailable", err)
	}
}

func TestScanRespectsContextCancellation(t *testing.T) {
	f := startFakeClamd(t, signatureVerdict)
	c := newTestScanner(t, f.addr())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Scan(ctx, strings.NewReader("content"), ScanOptions{Filename: "a.bin"}); err == nil {
		t.Fatal("a cancelled context must not produce a scan result")
	}
}

// TestDisabledScannerIsHonest: the developer convenience must not be able to
// masquerade as a passing scan.
func TestDisabledScannerIsHonest(t *testing.T) {
	s, err := New(Config{Driver: "disabled"}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), strings.NewReader(eicar), ScanOptions{Filename: "x.zip"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSkipped {
		t.Errorf("status = %q, want skipped", res.Status)
	}
	if res.Publishable() {
		t.Fatal("a skipped scan must never be publishable — that is the whole point")
	}
}

func TestNewRejectsUnknownDriverAndMissingAddress(t *testing.T) {
	now := func() time.Time { return time.Now().UTC() }
	if _, err := New(Config{Driver: "definitely-not-a-scanner"}, now); err == nil {
		t.Error("an unknown driver must not silently become a no-op scanner")
	}
	if _, err := New(Config{Driver: "clamav", Address: ""}, now); err == nil {
		t.Error("the clamav driver without an address must fail at construction, not at first scan")
	}
}
