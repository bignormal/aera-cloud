package migrations

import "embed"

// FS contains forward-only AgentEra Cloud database migrations.
//
//go:embed *.sql
var FS embed.FS
