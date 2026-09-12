package antivirus

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ClamAV speaks clamd's INSTREAM protocol directly.
//
// The protocol is small and stable, and implementing it here rather than taking
// a library keeps the dependency surface at what the binary actually needs. It
// is also the only way to guarantee the streaming property that matters: the
// file is forwarded in chunks and never held in memory, so a 2 GiB asset costs
// one 64 KiB buffer rather than 2 GiB of heap.
//
// Wire format, from clamd(8):
//
//	send    "zINSTREAM\0"
//	then    repeated { uint32 big-endian length, that many bytes }
//	end     uint32 zero
//	read    "stream: OK\0"
//	        "stream: <Signature> FOUND\0"
//	        "stream: <text> ERROR\0"
//
// A zero-length chunk sent early terminates the stream, so chunk lengths are
// checked rather than assumed.
type ClamAV struct {
	address   string
	network   string
	timeout   time.Duration
	maxBytes  int64
	chunkSize int
	now       func() time.Time
}

// NewClamAV builds a client. The address is "host:port", or "unix:/path" for a
// local socket, which is the deployment that avoids putting file contents on a
// network at all.
func NewClamAV(cfg Config, now func() time.Time) (*ClamAV, error) {
	cfg.applyDefaults()
	if now == nil {
		return nil, errors.New("antivirus: a clock is required")
	}
	addr := strings.TrimSpace(cfg.Address)
	if addr == "" {
		return nil, errors.New("antivirus: CLAMAV_ADDRESS is required for the clamav driver")
	}
	network := "tcp"
	if rest, ok := strings.CutPrefix(addr, "unix:"); ok {
		network, addr = "unix", rest
	}
	return &ClamAV{
		address: addr, network: network, timeout: cfg.Timeout,
		maxBytes: cfg.MaxBytes, chunkSize: cfg.ChunkSize, now: now,
	}, nil
}

// Name reports the engine. The signature-database version is appended to the
// per-scan Engine field instead, because it changes several times a day and a
// stored result must record the version that produced it.
func (c *ClamAV) Name() string { return "clamav" }

// Ping issues clamd's PING and expects PONG.
func (c *ClamAV) Ping(ctx context.Context) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	reply, err := readReply(conn)
	if err != nil {
		return err
	}
	if reply != "PONG" {
		return fmt.Errorf("%w: PING answered %q", ErrProtocol, reply)
	}
	return nil
}

// Version returns clamd's engine and signature-database version string.
func (c *ClamAV) Version(ctx context.Context) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zVERSION\x00")); err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return readReply(conn)
}

// Scan streams r to clamd and interprets the verdict.
//
// It also sniffs the leading bytes for a type mismatch. Those are two
// independent findings and both are reported: a file can be perfectly clean by
// signature and still be an ELF binary named .otf, which is the case a
// signature database is least likely to catch and a moderator most needs to see.
func (c *ClamAV) Scan(ctx context.Context, r io.Reader, opts ScanOptions) (Result, error) {
	res := Result{
		Engine: "clamav", DeclaredType: opts.DeclaredType, ScannedAt: c.now(),
	}
	if opts.Size > 0 && opts.Size > c.maxBytes {
		return res, fmt.Errorf("%w: %d bytes exceeds the %d byte limit", ErrTooLarge, opts.Size, c.maxBytes)
	}

	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return res, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	// The first chunk is retained so the type can be sniffed without a second
	// pass over a stream that may not be seekable.
	head := make([]byte, 0, sniffLen)
	sent, err := c.stream(conn, r, &head)
	if err != nil {
		return res, err
	}
	res.Bytes = sent

	detected, mismatch := DetectType(head, opts.Filename)
	res.DetectedType = detected

	reply, err := readReply(conn)
	if err != nil {
		return res, err
	}

	switch {
	case strings.HasSuffix(reply, "OK"):
		res.Status = StatusClean
	case strings.HasSuffix(reply, "FOUND"):
		res.Status = StatusInfected
		res.Signature = strings.TrimSpace(strings.TrimSuffix(
			strings.TrimPrefix(reply, "stream:"), "FOUND"))
		res.Reason = "the scanner matched a known threat signature"
		// An infection outranks a type mismatch: report the worse finding.
		return res, nil
	case strings.HasSuffix(reply, "ERROR"):
		res.Status = StatusError
		res.Reason = strings.TrimSpace(strings.TrimSuffix(
			strings.TrimPrefix(reply, "stream:"), "ERROR"))
		if strings.Contains(strings.ToLower(res.Reason), "size limit") {
			return res, fmt.Errorf("%w: %s", ErrTooLarge, res.Reason)
		}
		return res, nil
	default:
		return res, fmt.Errorf("%w: %q", ErrProtocol, reply)
	}

	// Clean by signature. A declared-versus-actual mismatch still holds the
	// asset, because "not known-bad" and "is what it claims to be" are
	// different questions and a seller is entitled to an answer to both.
	if mismatch != "" {
		res.Status = StatusSuspicious
		res.Reason = mismatch
	}
	return res, nil
}

// stream writes r to conn in length-prefixed chunks, capturing the first
// sniffLen bytes into head, and terminates the stream.
func (c *ClamAV) stream(conn net.Conn, r io.Reader, head *[]byte) (int64, error) {
	buf := make([]byte, c.chunkSize)
	var length [4]byte
	var total int64

	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > c.maxBytes {
				return total, fmt.Errorf("%w: stream exceeded %d bytes", ErrTooLarge, c.maxBytes)
			}
			if len(*head) < sniffLen {
				want := min(sniffLen-len(*head), n)
				*head = append(*head, buf[:want]...)
			}
			binary.BigEndian.PutUint32(length[:], uint32(n))
			if _, err := conn.Write(length[:]); err != nil {
				return total, fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return total, fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return total, fmt.Errorf("antivirus: reading the asset: %w", readErr)
		}
	}

	// A zero-length chunk ends the stream. Without it clamd waits for the
	// deadline and then reports a timeout rather than a verdict.
	binary.BigEndian.PutUint32(length[:], 0)
	if _, err := conn.Write(length[:]); err != nil {
		return total, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return total, nil
}

// withTimeout bounds the operation, unless the caller already bounded it more
// tightly.
//
// The context is the single timeout mechanism here, deliberately. A connection
// deadline is an absolute instant on the operating system's clock, so deriving
// one from the injected clock would break the moment the two disagreed — which
// is exactly what a test with a fixed clock, or a host with a skewed one, makes
// happen. The injected clock records when a scan happened; it does not schedule.
func (c *ClamAV) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

func (c *ClamAV) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, c.network, c.address)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s %s: %v", ErrUnavailable, c.network, c.address, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

// readReply reads one NUL-terminated clamd reply.
//
// The reply is bounded: a scanner that streams unbounded output at us is a
// scanner we stop reading, not one we buffer.
func readReply(conn net.Conn) (string, error) {
	br := bufio.NewReader(io.LimitReader(conn, maxReplyBytes))
	line, err := br.ReadString(0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	line = strings.TrimRight(line, "\x00\n\r ")
	if line == "" {
		return "", fmt.Errorf("%w: empty reply", ErrProtocol)
	}
	return line, nil
}

const maxReplyBytes = 4 << 10
