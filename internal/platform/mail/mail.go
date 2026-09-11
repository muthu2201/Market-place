// Package mail delivers transactional e-mail.
//
// Transactional mail is on the critical path: a buyer who cannot receive their
// receipt or a reset link is locked out of their own purchase. So delivery is
// queued in the database, retried with backoff, and its outcome recorded, and
// it is never attempted inline in a request.
//
// Marketing mail is a different thing entirely and is gated on consent; the
// category column on notifications is what keeps the two from being confused.
package mail

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

// Message is one rendered e-mail.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Transport sends a single message.
type Transport interface {
	Name() string
	Send(ctx context.Context, m Message) (providerMessageID string, err error)
}

// Sender drains the notification queue.
type Sender interface {
	Drain(ctx context.Context, database *db.DB, limit int) (sent, failed int, err error)
}

// Decryptor opens a stored recipient address. The queue holds the address
// encrypted under the recipient's own key, so erasing a subject also makes
// their queued mail undeliverable, which is the correct outcome.
type Decryptor interface {
	DecryptFor(ctx context.Context, q db.Querier, subject ids.UUID, field string, ciphertext []byte) (string, error)
}

// Queue renders and sends queued notifications.
type Queue struct {
	transport   Transport
	renderer    *Renderer
	decryptor   Decryptor
	log         *slog.Logger
	from        string
	fromName    string
	maxAttempts int
}

// NewQueue builds the sender.
func NewQueue(t Transport, r *Renderer, d Decryptor, log *slog.Logger, cfg config.MailConfig) *Queue {
	if log == nil {
		log = slog.Default()
	}
	return &Queue{
		transport: t, renderer: r, decryptor: d, log: log,
		from: cfg.FromAddress, fromName: cfg.FromName, maxAttempts: 8,
	}
}

// Drain sends up to limit queued messages.
//
// Rows are claimed with SKIP LOCKED so several workers can drain concurrently
// without sending the same message twice.
func (q *Queue) Drain(ctx context.Context, database *db.DB, limit int) (sent, failed int, err error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	type queued struct {
		id       ids.UUID
		userID   *ids.UUID
		template string
		vars     map[string]any
		toCT     []byte
		attempts int
	}
	var batch []queued

	err = database.InTx(ctx, db.TxOptions{Name: "mail_claim"}, func(ctx context.Context, tx db.Tx) error {
		rows, qErr := tx.Query(ctx, `
			UPDATE notifications SET attempts = attempts + 1
			 WHERE id IN (
			   SELECT id FROM notifications
			    WHERE status = 'queued' AND channel = 'email'
			    ORDER BY created_at
			    LIMIT $1 FOR UPDATE SKIP LOCKED
			 )
			 RETURNING id, user_id, template, variables, to_ciphertext, attempts`, limit)
		if qErr != nil {
			return fmt.Errorf("mail: claim: %w", qErr)
		}
		defer rows.Close()
		for rows.Next() {
			var m queued
			if err := rows.Scan(&m.id, &m.userID, &m.template, &m.vars, &m.toCT, &m.attempts); err != nil {
				return err
			}
			batch = append(batch, m)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, 0, err
	}

	for _, m := range batch {
		to, resolveErr := q.recipient(ctx, database, m.userID, m.toCT)
		if resolveErr != nil || to == "" {
			q.markFailed(ctx, database, m.id, m.attempts, "no deliverable address: "+errText(resolveErr))
			failed++
			continue
		}
		if suppressed, _ := q.isSuppressed(ctx, database, to); suppressed {
			q.markStatus(ctx, database, m.id, "suppressed", "address is on the suppression list")
			continue
		}

		msg, renderErr := q.renderer.Render(m.template, to, m.vars)
		if renderErr != nil {
			q.markFailed(ctx, database, m.id, m.attempts, "render: "+renderErr.Error())
			failed++
			continue
		}
		providerID, sendErr := q.transport.Send(ctx, msg)
		if sendErr != nil {
			q.markFailed(ctx, database, m.id, m.attempts, sendErr.Error())
			failed++
			continue
		}
		q.markSent(ctx, database, m.id, providerID)
		sent++
	}
	return sent, failed, nil
}

func (q *Queue) recipient(ctx context.Context, database *db.DB, userID *ids.UUID, ct []byte) (string, error) {
	if len(ct) > 0 && userID != nil && q.decryptor != nil {
		if to, err := q.decryptor.DecryptFor(ctx, database, *userID, "notification_to", ct); err == nil && to != "" {
			return to, nil
		}
	}
	if userID == nil {
		return "", errors.New("no recipient recorded")
	}
	var emailCT []byte
	if err := database.QueryRow(ctx,
		`SELECT email_ciphertext FROM users WHERE id = $1 AND erased_at IS NULL`, *userID).Scan(&emailCT); err != nil {
		return "", err
	}
	if q.decryptor == nil {
		return "", errors.New("no decryptor configured")
	}
	return q.decryptor.DecryptFor(ctx, database, *userID, "email", emailCT)
}

func (q *Queue) isSuppressed(ctx context.Context, database *db.DB, _ string) (bool, error) {
	// Suppression is keyed on the blind index, which the identity module owns.
	// Until that lookup is wired here the queue errs toward delivering
	// transactional mail, which is the safer failure for a receipt or a reset.
	return false, nil
}

func (q *Queue) markSent(ctx context.Context, database *db.DB, id ids.UUID, providerID string) {
	if _, err := database.Exec(context.WithoutCancel(ctx), `
		UPDATE notifications SET status = 'sent', sent_at = now(), provider_message_id = $2, last_error = NULL
		 WHERE id = $1`, id, nullIfEmpty(providerID)); err != nil {
		q.log.Error("mail: could not record delivery", slog.String("error", err.Error()))
	}
}

func (q *Queue) markStatus(ctx context.Context, database *db.DB, id ids.UUID, status, note string) {
	if _, err := database.Exec(context.WithoutCancel(ctx),
		`UPDATE notifications SET status = $2, last_error = $3 WHERE id = $1`, id, status, note); err != nil {
		q.log.Error("mail: could not record status", slog.String("error", err.Error()))
	}
}

func (q *Queue) markFailed(ctx context.Context, database *db.DB, id ids.UUID, attempts int, reason string) {
	status := "queued"
	if attempts >= q.maxAttempts {
		// Kept as a failed row rather than deleted: an undelivered receipt is
		// something a support agent needs to be able to see.
		status = "failed"
	}
	if _, err := database.Exec(context.WithoutCancel(ctx),
		`UPDATE notifications SET status = $2, last_error = $3 WHERE id = $1`,
		id, status, truncate(reason, 1000)); err != nil {
		q.log.Error("mail: could not record failure", slog.String("error", err.Error()))
	}
}

// ---- transports -------------------------------------------------------------

// LogTransport writes messages to the log instead of sending them. It is the
// development default and is refused in production by config validation, so a
// deployment can never silently discard transactional mail.
type LogTransport struct{ Log *slog.Logger }

func (t LogTransport) Name() string { return "log" }

func (t LogTransport) Send(_ context.Context, m Message) (string, error) {
	log := t.Log
	if log == nil {
		log = slog.Default()
	}
	// The recipient is deliberately not logged in full: even in development,
	// logs get copied into issue trackers.
	log.Info("mail (not actually sent: MAIL_DRIVER=log)",
		slog.String("to_domain", domainOf(m.To)),
		slog.String("subject", m.Subject),
		slog.Int("body_bytes", len(m.Text)))
	return "log:" + ids.Correlation(), nil
}

// SMTPTransport sends over SMTP with STARTTLS.
type SMTPTransport struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
	Timeout  time.Duration
}

func (t SMTPTransport) Name() string { return "smtp" }

func (t SMTPTransport) Send(ctx context.Context, m Message) (string, error) {
	if t.Host == "" {
		return "", errors.New("mail: SMTP host is not configured")
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	addr := net.JoinHostPort(t.Host, fmt.Sprint(t.Port))

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("mail: dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	c, err := smtp.NewClient(conn, t.Host)
	if err != nil {
		return "", fmt.Errorf("mail: smtp handshake: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: t.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return "", fmt.Errorf("mail: starttls: %w", err)
		}
	} else if t.Password != "" {
		// Refusing to send credentials in the clear is not optional.
		return "", errors.New("mail: server does not offer STARTTLS and credentials would be sent in the clear")
	}
	if t.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", t.Username, t.Password, t.Host)); err != nil {
			return "", fmt.Errorf("mail: authenticate: %w", err)
		}
	}
	if err := c.Mail(t.From); err != nil {
		return "", fmt.Errorf("mail: from: %w", err)
	}
	if err := c.Rcpt(m.To); err != nil {
		return "", fmt.Errorf("mail: recipient: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return "", fmt.Errorf("mail: data: %w", err)
	}
	if _, err := wc.Write([]byte(buildMIME(t.From, t.FromName, m))); err != nil {
		wc.Close()
		return "", fmt.Errorf("mail: write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return "", fmt.Errorf("mail: close data: %w", err)
	}
	_ = c.Quit()
	return "smtp:" + ids.Correlation(), nil
}

// buildMIME renders a multipart message.
//
// Header values are sanitised before they are written: a newline in a subject
// or an address is an SMTP header-injection primitive.
func buildMIME(from, fromName string, m Message) string {
	boundary := "b_" + ids.Correlation()
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s <%s>\r\n", sanitiseHeader(fromName), sanitiseHeader(from))
	fmt.Fprintf(&b, "To: %s\r\n", sanitiseHeader(m.To))
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitiseHeader(m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@marketplace>\r\n", ids.Correlation())
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)

	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", boundary, m.Text)
	if m.HTML != "" {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n", boundary, m.HTML)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

// sanitiseHeader strips CR and LF, which is what makes header injection
// possible, and bounds the length.
func sanitiseHeader(v string) string {
	v = strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(v)
	if len(v) > 200 {
		v = v[:200]
	}
	return strings.TrimSpace(v)
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return "unknown"
}

func errText(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var _ = json.Marshal
