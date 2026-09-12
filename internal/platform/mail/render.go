package mail

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	texttemplate "text/template"
)

// Renderer turns a template name and variables into a message.
//
// HTML bodies are rendered with html/template, which escapes by context. A
// seller-supplied product title in a receipt therefore cannot become script,
// and the plain-text alternative is generated from a separate text template
// rather than by stripping tags, which is how injection sneaks back in.
type Renderer struct {
	html *template.Template
	text *texttemplate.Template
	// brand appears in every subject line.
	brand string
	// baseURL is used for absolute links; relative links do not work in mail.
	baseURL string
	support string
}

// NewRenderer compiles the built-in templates.
func NewRenderer(brand, baseURL, supportEmail string) (*Renderer, error) {
	h := template.New("html")
	t := texttemplate.New("text")
	for name, body := range htmlBodies {
		if _, err := h.New(name).Parse(body); err != nil {
			return nil, fmt.Errorf("mail: parse html template %s: %w", name, err)
		}
	}
	for name, body := range textBodies {
		if _, err := t.New(name).Parse(body); err != nil {
			return nil, fmt.Errorf("mail: parse text template %s: %w", name, err)
		}
	}
	return &Renderer{html: h, text: t, brand: brand, baseURL: baseURL, support: supportEmail}, nil
}

// Render produces the message for a template.
func (r *Renderer) Render(name, to string, vars map[string]any) (Message, error) {
	subject, ok := subjects[name]
	if !ok {
		return Message{}, fmt.Errorf("mail: no template named %q", name)
	}
	data := map[string]any{
		"Brand": r.brand, "BaseURL": r.baseURL, "Support": r.support, "To": to,
	}
	for k, v := range vars {
		// Variables are namespaced under Vars so a template variable can never
		// shadow a platform value like BaseURL.
		data[k] = v
	}
	data["Vars"] = vars

	var textBuf bytes.Buffer
	if err := r.text.ExecuteTemplate(&textBuf, name, data); err != nil {
		return Message{}, fmt.Errorf("mail: render text %s: %w", name, err)
	}
	var htmlBuf bytes.Buffer
	if r.html.Lookup(name) != nil {
		if err := r.html.ExecuteTemplate(&htmlBuf, name, data); err != nil {
			return Message{}, fmt.Errorf("mail: render html %s: %w", name, err)
		}
	}
	return Message{
		To:      to,
		Subject: strings.ReplaceAll(subject, "{{brand}}", r.brand),
		Text:    textBuf.String(),
		HTML:    htmlBuf.String(),
	}, nil
}

// Templates returns the known template names, used by tests to assert that
// every topic the worker publishes has something to render.
func (r *Renderer) Templates() []string {
	out := make([]string, 0, len(subjects))
	for name := range subjects {
		out = append(out, name)
	}
	return out
}

var subjects = map[string]string{
	"email_verification": "Confirm your e-mail address",
	"password_reset":     "Reset your {{brand}} password",
	"order_receipt":      "Your {{brand}} order",
	"order_fulfilled":    "Your downloads are ready",
	"order_refunded":     "Your refund has been processed",
	"payment_failed":     "Your payment did not go through",
	"seller_settlement":  "A settlement is on its way to you",
	"grievance_ack":      "We have received your complaint",
}

// Plain text first: it is what most clients actually render, and it is what a
// screen reader reads. Every template says plainly what happened and what, if
// anything, the reader needs to do.
var textBodies = map[string]string{
	"email_verification": `Confirm your e-mail address

Open this link to confirm your address:

  {{.verify_url}}

The link expires in {{.expires_in}}. If you did not create an account, you can
ignore this message and nothing further will happen.

{{.Brand}}
Questions: {{.Support}}
`,
	"password_reset": `Reset your password

Open this link to choose a new password:

  {{.reset_url}}

The link expires in {{.expires_in}} and can be used once. Every other session
will be signed out when you use it.

If you did not ask for this, you can ignore this message. Your password has not
changed and nobody has been given access to your account.

{{.Brand}}
Questions: {{.Support}}
`,
	"order_receipt": `Thank you for your order

Order {{.order_number}}
Total: {{.currency}} {{.total_minor}} (in minor units)

You can see the full tax breakdown, including how GST was calculated, on your
order page:

  {{.BaseURL}}/orders/{{.order_id}}

{{.Brand}}
Questions: {{.Support}}
`,
	"order_fulfilled": `Your downloads are ready

Order {{.order_number}} is complete. Your files are in your library:

  {{.BaseURL}}/library

Download links are single use and short-lived, so generate a fresh one from
your library whenever you need the file again.

{{.Brand}}
`,
	"order_refunded": `Your refund has been processed

Order {{.order_number}} has been refunded. Depending on your bank, it usually
appears within five to seven working days.

  {{.BaseURL}}/orders/{{.order_id}}

{{.Brand}}
Questions: {{.Support}}
`,
	"payment_failed": `Your payment did not go through

We could not complete payment for order {{.order_number}}. No money has been
taken. You can try again here:

  {{.BaseURL}}/orders/{{.order_id}}

{{.Brand}}
Questions: {{.Support}}
`,
	"seller_settlement": `A settlement is on its way

{{.currency}} {{.net_minor}} (in minor units) has been released to your
registered bank account.

Your statement shows the full breakdown: commission, GST on that commission,
TCS collected under section 52, TDS deducted under section 194-O, and any
rolling reserve withheld.

  {{.BaseURL}}/seller/statements

{{.Brand}}
`,
	"grievance_ack": `We have received your complaint

Reference: {{.ticket_number}}

We acknowledge your complaint and will respond within 15 days, as required.
You can follow it here:

  {{.BaseURL}}/grievances/{{.ticket_number}}

{{.Brand}}
Grievance Officer: {{.Support}}
`,
}

// The HTML alternative is deliberately plain: inline styles only, no images, no
// tracking pixel, no remote fonts. Transactional mail should render identically
// in every client and should not report back when it is opened.
var htmlBodies = map[string]string{
	"email_verification": htmlShell(`<p>Open this link to confirm your address:</p>
<p><a href="{{.verify_url}}">Confirm my e-mail address</a></p>
<p>The link expires in {{.expires_in}}. If you did not create an account, you can ignore this message.</p>`),

	"password_reset": htmlShell(`<p>Open this link to choose a new password:</p>
<p><a href="{{.reset_url}}">Reset my password</a></p>
<p>The link expires in {{.expires_in}} and can be used once. Every other session will be signed out when you use it.</p>
<p>If you did not ask for this, you can ignore this message. Your password has not changed.</p>`),

	"order_receipt": htmlShell(`<p>Thank you for your order.</p>
<p><strong>Order {{.order_number}}</strong></p>
<p><a href="{{.BaseURL}}/orders/{{.order_id}}">See your order and its full tax breakdown</a></p>`),

	"order_fulfilled": htmlShell(`<p>Order {{.order_number}} is complete.</p>
<p><a href="{{.BaseURL}}/library">Open your library</a></p>
<p>Download links are single use and short-lived. Generate a fresh one whenever you need the file again.</p>`),

	"order_refunded": htmlShell(`<p>Order {{.order_number}} has been refunded.</p>
<p>Depending on your bank, it usually appears within five to seven working days.</p>`),

	"payment_failed": htmlShell(`<p>We could not complete payment for order {{.order_number}}. No money has been taken.</p>
<p><a href="{{.BaseURL}}/orders/{{.order_id}}">Try again</a></p>`),
}

func htmlShell(body string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f6f6f4;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#1a1a1a;line-height:1.55">
<div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e4e4e0;border-radius:10px;padding:28px">
<h1 style="margin:0 0 16px;font-size:19px;font-weight:600">{{.Brand}}</h1>
` + body + `
<hr style="border:none;border-top:1px solid #e4e4e0;margin:24px 0">
<p style="font-size:13px;color:#6b6b66;margin:0">Questions? Write to <a href="mailto:{{.Support}}" style="color:#3a5f8a">{{.Support}}</a>.</p>
</div></body></html>`
}
