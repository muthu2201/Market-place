// Package migrations carries the SQL schema files compiled into every binary.
//
// The files live here rather than under internal/ so that a reviewer, a DBA or
// a migration tool can read the schema without navigating Go package layout,
// while go:embed still guarantees the binary and the SQL ship together.
package migrations

import "embed"

//go:embed *.sql
var Files embed.FS
