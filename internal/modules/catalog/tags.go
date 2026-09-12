package catalog

import (
	"context"
	"strings"

	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

// Tagging follows the AO3 model: sellers tag in their own words, and a
// wrangling pipeline maps synonyms and misspellings onto canonical tags behind
// the scenes.
//
// The reason is worth stating, because the obvious alternative — a fixed
// vocabulary the seller picks from — fails in a specific way. A fixed list is
// always behind: it has no entry for a technique invented last month, so the
// work either gets mis-filed under the nearest wrong thing or does not get
// found at all. A free-text field alone fails the other way, fragmenting the
// same concept across a dozen spellings until faceted search is useless.
//
// Wrangling keeps both properties: the seller's own wording is displayed, and
// search runs on the canonical tag it resolves to. A tag nobody has wrangled
// yet is stored as `proposed` and still attributed to itself, so a new concept
// works from the first use rather than from the first wrangler's shift.

// maxTagLabel matches the schema's CHECK on tags.label.
const maxTagLabel = 40

// applyTags attaches tags to a product, creating proposed tags as needed and
// resolving every one to its canonical form.
func (s *Service) applyTags(ctx context.Context, tx db.Tx, productID ids.UUID, labels []string) error {
	seen := map[string]bool{}

	for _, raw := range labels {
		label := normaliseTagLabel(raw)
		if label == "" {
			continue
		}
		slug := slugify(label)
		if slug == "" || seen[slug] {
			continue
		}
		seen[slug] = true

		var tagID ids.UUID
		// Create-or-fetch in one atomic statement. The read-then-write version
		// of this returns nothing when a concurrent transaction inserted first,
		// which is precisely the race the load test found elsewhere in this
		// codebase; there is no reason to reintroduce it here.
		err := tx.QueryRow(ctx, `
			INSERT INTO tags (id, public_id, slug, label, status)
			VALUES ($1, $2, $3, $4, 'proposed')
			ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug
			RETURNING id`,
			ids.NewUUIDv7(), ids.NewPublic(ids.PrefixTag), slug, label).Scan(&tagID)
		if err != nil {
			return err
		}

		// A banned tag is silently dropped rather than refused. Refusing would
		// tell someone probing the moderation list exactly which words are on
		// it, and the seller has no legitimate use for that information.
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM tags WHERE id = $1`, tagID).Scan(&status); err != nil {
			return err
		}
		if status == "banned" || status == "rejected" {
			continue
		}

		// resolve_tag follows the synonym chain with its own cycle guard, so a
		// mis-wrangled loop raises rather than hanging.
		if _, err := tx.Exec(ctx, `
			INSERT INTO product_tags (product_id, tag_id, canonical_tag_id)
			VALUES ($1, $2, resolve_tag($2))
			ON CONFLICT (product_id, tag_id) DO NOTHING`,
			productID, tagID); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx,
			`UPDATE tags SET usage_count = usage_count + 1 WHERE id = resolve_tag($1)`, tagID); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceTags sets a product's tags to exactly this list.
func (s *Service) ReplaceTags(ctx context.Context, sellerID ids.UUID, productPublicID string, labels []string) error {
	return s.db.InTx(ctx, db.TxOptions{Name: "catalog_replace_tags"}, func(ctx context.Context, tx db.Tx) error {
		productID, _, err := s.ownedProduct(ctx, tx, sellerID, productPublicID)
		if err != nil {
			return err
		}
		// Usage counts follow the rows, so removing a tag decrements what it
		// contributed. A counter that only ever goes up would make the popular
		// tags list a record of what was once popular.
		if _, err := tx.Exec(ctx, `
			UPDATE tags SET usage_count = GREATEST(usage_count - 1, 0)
			 WHERE id IN (SELECT canonical_tag_id FROM product_tags WHERE product_id = $1)`,
			productID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM product_tags WHERE product_id = $1`, productID); err != nil {
			return err
		}
		return s.applyTags(ctx, tx, productID, labels)
	})
}

// normaliseTagLabel folds the variations that would otherwise fragment a tag,
// while keeping the seller's own words readable.
func normaliseTagLabel(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ") // collapse internal whitespace
	if len([]rune(s)) > maxTagLabel {
		s = string([]rune(s)[:maxTagLabel])
		s = strings.TrimSpace(s)
	}
	return s
}
