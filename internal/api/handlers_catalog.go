package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/modules/ranking"
	"github.com/muthu2201/market-place/internal/outbox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/httpx"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
)

// productSummary is the public shape of a listing. Internal columns (object
// keys, risk scores, seller identifiers other than the public one) never appear.
type productSummary struct {
	ID           string      `json:"id"`
	Slug         string      `json:"slug"`
	Title        string      `json:"title"`
	Summary      string      `json:"summary"`
	SellerHandle string      `json:"seller_handle"`
	Category     string      `json:"category"`
	Price        money.Money `json:"price"`
	LicenseType  string      `json:"license_type"`
	DeliveryType string      `json:"delivery_type"`
	AIDisclosure string      `json:"ai_disclosure"`
	Rating       *float64    `json:"rating,omitempty"`
	RatingCount  int         `json:"rating_count"`
	PublishedAt  time.Time   `json:"published_at"`
	// RankExplanation is the per-listing disclosure required by P2B Article 5.
	RankExplanation []string `json:"rank_explanation,omitempty"`
	RankScore       int      `json:"rank_score,omitempty"`
}

func (s *Server) handleListProducts(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r, 24, 60)
	sortMode := r.URL.Query().Get("sort")
	switch sortMode {
	case "", "ranked", "newest", "price_asc", "price_desc", "rating":
	default:
		httpx.Fail(w, r, problem.Validation(problem.FieldError{
			Field: "sort", Code: "invalid_choice",
			Detail: "Sort must be one of: ranked, newest, price_asc, price_desc, rating."}))
		return
	}
	if sortMode == "" {
		sortMode = "ranked"
	}

	category := r.URL.Query().Get("category")
	items, err := s.queryProducts(r.Context(), productQuery{
		Category: category, Sort: sortMode, Limit: limit, Offset: offset,
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}

	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"products": items,
		"sort":     sortMode,
		"limit":    limit, "offset": offset,
		// Stated on every listing response, not buried on a policy page.
		"ranking_disclosure_url": "/legal/ranking",
		"ranking_note": "Order is produced by a published formula. There is no paid placement: " +
			"no position on this marketplace can be bought.",
	})
}

func (s *Server) handleGetProduct(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := ids.ParsePublic(ids.PrefixProduct, id); err != nil {
		httpx.Fail(w, r, problem.NotFound("That product could not be found."))
		return
	}
	items, err := s.queryProducts(r.Context(), productQuery{PublicID: id, Limit: 1})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	if len(items) == 0 {
		httpx.Fail(w, r, problem.NotFound("That product could not be found."))
		return
	}

	variants, err := s.variantsOf(r.Context(), id)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	detail, err := s.productDetail(r.Context(), id)
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}

	// A view is counted best-effort and never blocks the response.
	go func(pid string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
		defer cancel()
		_, _ = s.db.Exec(ctx, `UPDATE products SET view_count = view_count + 1 WHERE public_id = $1`, pid)
	}(id)

	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"product":  items[0],
		"detail":   detail,
		"variants": variants,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if d := s.limiter.Allow(httpx.ClientIP(r.Context()), ratelimit.RuleSearchPerIP); !d.Allowed {
		httpx.Fail(w, r, problem.RateLimited(int(d.RetryAfter.Seconds())+1))
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	if q == "" {
		httpx.Fail(w, r, problem.Validation(problem.FieldError{
			Field: "q", Code: "required", Detail: "Enter something to search for."}))
		return
	}
	limit, offset := pagination(r, 24, 60)

	start := s.clk.Now()
	items, err := s.queryProducts(r.Context(), productQuery{
		Search: q, Sort: "relevance", Limit: limit, Offset: offset,
	})
	if err != nil {
		httpx.Fail(w, r, err)
		return
	}
	if s.m != nil {
		s.m.SearchDuration.Observe(s.clk.Now().Sub(start).Seconds(), "fulltext")
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"query": q, "results": items, "limit": limit, "offset": offset,
		"ranking_disclosure_url": "/legal/ranking",
	})
}

type productQuery struct {
	PublicID string
	Category string
	Search   string
	Sort     string
	Limit    int
	Offset   int
}

// queryProducts reads published listings.
//
// Every branch below selects a fixed ORDER BY from a closed set; no part of the
// statement is built from user input, and every value is a bind parameter.
func (s *Server) queryProducts(ctx context.Context, q productQuery) ([]productSummary, error) {
	const base = `
		SELECT p.public_id, p.slug, p.title, p.summary, sel.handle, c.slug,
		       v.price_minor, v.currency, p.license_type, p.delivery_type, p.ai_disclosure,
		       p.rating_sum, p.rating_count, COALESCE(p.ranking_anchor_at, p.published_at),
		       COALESCE(rs.final_score, 0), sel.id
		  FROM products p
		  JOIN sellers sel ON sel.id = p.seller_id
		  JOIN categories c ON c.id = p.category_id
		  JOIN LATERAL (
		      SELECT price_minor, currency FROM product_variants
		       WHERE product_id = p.id AND active
		       ORDER BY price_minor LIMIT 1
		  ) v ON TRUE
		  LEFT JOIN ranking_state rs ON rs.product_id = p.id
		 WHERE p.status = 'published'`

	var (
		sql  strings.Builder
		args []any
	)
	sql.WriteString(base)

	switch {
	case q.PublicID != "":
		args = append(args, q.PublicID)
		sql.WriteString(` AND p.public_id = $1`)
	case q.Search != "":
		args = append(args, q.Search)
		// websearch_to_tsquery parses user input safely: it never throws on
		// malformed syntax and it is a bind parameter, not interpolation.
		sql.WriteString(` AND (p.search_vector @@ websearch_to_tsquery('english', $1)
		                       OR p.title % $1)`)
	case q.Category != "":
		args = append(args, q.Category)
		sql.WriteString(` AND c.slug = $1`)
	}

	// The ORDER BY is chosen from a closed set in code; sort keys never come
	// from the request string.
	switch q.Sort {
	case "newest":
		sql.WriteString(` ORDER BY COALESCE(p.ranking_anchor_at, p.published_at) DESC, p.id`)
	case "price_asc":
		sql.WriteString(` ORDER BY v.price_minor ASC, p.id`)
	case "price_desc":
		sql.WriteString(` ORDER BY v.price_minor DESC, p.id`)
	case "rating":
		sql.WriteString(` ORDER BY (CASE WHEN p.rating_count = 0 THEN 0 ELSE p.rating_sum::numeric / p.rating_count END) DESC, p.id`)
	case "relevance":
		args = append(args, q.Search)
		sql.WriteString(` ORDER BY ts_rank(p.search_vector, websearch_to_tsquery('english', $` +
			strconv.Itoa(len(args)) + `)) DESC, COALESCE(rs.final_score,0) DESC, p.id`)
	default: // "ranked"
		sql.WriteString(` ORDER BY COALESCE(rs.final_score, 0) DESC, COALESCE(p.ranking_anchor_at, p.published_at) DESC, p.id`)
	}

	args = append(args, q.Limit, q.Offset)
	sql.WriteString(` LIMIT $` + strconv.Itoa(len(args)-1) + ` OFFSET $` + strconv.Itoa(len(args)))

	rows, err := s.db.Query(ctx, sql.String(), args...)
	if err != nil {
		return nil, problem.Internal(err)
	}
	defer rows.Close()

	var out []productSummary
	for rows.Next() {
		var p productSummary
		var priceMinor int64
		var currency string
		var ratingSum, ratingCount int
		var rankScore int
		var sellerID ids.UUID
		if err := rows.Scan(&p.ID, &p.Slug, &p.Title, &p.Summary, &p.SellerHandle, &p.Category,
			&priceMinor, &currency, &p.LicenseType, &p.DeliveryType, &p.AIDisclosure,
			&ratingSum, &ratingCount, &p.PublishedAt, &rankScore, &sellerID); err != nil {
			return nil, problem.Internal(err)
		}
		m, err := money.New(priceMinor, money.Currency(currency))
		if err != nil {
			return nil, problem.Internal(err)
		}
		p.Price = m
		p.RatingCount = ratingCount
		if ratingCount > 0 {
			avg := float64(ratingSum) / float64(ratingCount)
			p.Rating = &avg
		}
		p.RankScore = rankScore
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Internal(err)
	}
	return out, nil
}

func (s *Server) variantsOf(ctx context.Context, productPublicID string) ([]map[string]any, error) {
	rows, err := s.db.Query(ctx, `
		SELECT v.public_id, v.name, v.price_minor, v.currency, v.compare_at_minor,
		       v.max_sales, v.sales_count
		  FROM product_variants v
		  JOIN products p ON p.id = v.product_id
		 WHERE p.public_id = $1 AND v.active
		 ORDER BY v.position, v.price_minor`, productPublicID)
	if err != nil {
		return nil, problem.Internal(err)
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var pub, name, currency string
		var price int64
		var compareAt *int64
		var maxSales *int
		var sold int
		if err := rows.Scan(&pub, &name, &price, &currency, &compareAt, &maxSales, &sold); err != nil {
			return nil, problem.Internal(err)
		}
		m, err := money.New(price, money.Currency(currency))
		if err != nil {
			return nil, problem.Internal(err)
		}
		entry := map[string]any{"id": pub, "name": name, "price": m}
		if maxSales != nil {
			entry["limited_edition"] = map[string]any{"total": *maxSales, "remaining": *maxSales - sold}
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (s *Server) productDetail(ctx context.Context, publicID string) (map[string]any, error) {
	var description, licenseTerms, refundPolicy, aiNote string
	var aiDisclosure string
	var previewCount int
	err := s.db.QueryRow(ctx, `
		SELECT p.description, p.license_terms, p.refund_policy,
		       COALESCE(p.ai_disclosure_note, ''), p.ai_disclosure,
		       (SELECT count(*) FROM product_assets a WHERE a.product_id = p.id AND a.is_preview)
		  FROM products p WHERE p.public_id = $1 AND p.status = 'published'`,
		publicID).Scan(&description, &licenseTerms, &refundPolicy, &aiNote, &aiDisclosure, &previewCount)
	if db.IsNoRows(err) {
		return nil, problem.NotFound("That product could not be found.")
	}
	if err != nil {
		return nil, problem.Internal(err)
	}
	return map[string]any{
		"description":   description,
		"license_terms": licenseTerms,
		"refund_policy": refundPolicy,
		// Refund terms are stated before purchase, in plain words, because that
		// is what makes "no refund once downloaded" fair as well as lawful.
		"refund_policy_plain": refundPolicyPlain(refundPolicy),
		"ai_disclosure":       aiDisclosure,
		"ai_disclosure_plain": aiDisclosurePlain(aiDisclosure),
		"ai_disclosure_note":  aiNote,
		"preview_count":       previewCount,
	}, nil
}

func refundPolicyPlain(p string) string {
	switch p {
	case "no_refund_after_download":
		return "Refundable until you download the files. Once a file has been downloaded it cannot be recalled, so it cannot be refunded."
	case "refundable_14_days":
		return "Refundable within 14 days of purchase."
	case "no_refund":
		return "This item is sold without a refund option."
	case "case_by_case":
		return "Refunds are considered individually. Open a dispute and a person will review it."
	}
	return p
}

func aiDisclosurePlain(d string) string {
	switch d {
	case "no_ai":
		return "The seller declares this work was made without generative AI."
	case "ai_assisted":
		return "The seller declares generative AI was used to assist, with substantial human authorship."
	case "ai_generated":
		return "The seller declares this work was generated by AI."
	case "ai_generated_edited":
		return "The seller declares this work was generated by AI and then edited by a person."
	}
	return "The seller has not declared how this work was made."
}

var _ = ranking.FormulaVersion
var _ = outbox.TopicProductPublished
