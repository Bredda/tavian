package store

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// AuditorTables are the tables the read-only role of an auditor may read: what
// `tavian verify-audit` and `tavian audit-export` look at, and the history of
// the configuration and of the administrators' changes. Every table is in this
// list or in ReservedTables; a test fails when a migration adds one that is in
// neither, so that who may read it is decided when it is created.
var AuditorTables = []string{
	"admin_changes", "audit_chain", "audit_seals", "config_active", "config_revisions",
	"outbox", "outbox_consumers", "outbox_prunes", "schema_migrations",
}

// ReservedTables are the tables the auditor role does not get: accounting
// detail and the use of the admin tokens, which the auditor reads through the
// administration API if at all.
var ReservedTables = []string{"admin_token_use", "usage_hourly"}

var identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// AuditorRoleSQL is the script that creates the read-only role of an auditor
// and grants it what AuditorTables names, for the given database and schema.
// The gateway never runs it: it needs a database administrator, who also sets
// the password or the certificate of the role.
func AuditorRoleSQL(role, database, schema string) (string, error) {
	for what, v := range map[string]string{"role": role, "database": database, "schema": schema} {
		if !identifier.MatchString(v) {
			return "", fmt.Errorf("%s %q: use lower-case letters, digits and underscores, starting with a letter or an underscore (63 at most)", what, v)
		}
	}
	q := func(parts ...string) string { return pgx.Identifier(parts).Sanitize() }
	tables := make([]string, 0, len(AuditorTables))
	for _, t := range AuditorTables {
		tables = append(tables, q(schema, t))
	}
	var b strings.Builder
	fmt.Fprintf(&b, `-- A role that can read the audit trail of a Tavian gateway and change nothing.
-- Run it as a database administrator, then give the role a password or a
-- certificate as your policy says, for example:
--   ALTER ROLE %[1]s PASSWORD '...';
-- The auditor puts the connection URL of this role in the environment variable
-- that database.url_env names in the configuration given to tavian verify-audit
-- and tavian audit-export (docs/AUDIT.md).

CREATE ROLE %[1]s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Every session of the role starts read-only. This is a second lock: the grants
-- below are what actually keeps the role from writing.
ALTER ROLE %[1]s SET default_transaction_read_only = on;

GRANT CONNECT ON DATABASE %[2]s TO %[1]s;
GRANT USAGE ON SCHEMA %[3]s TO %[1]s;

-- Only what the checks and the export read. Not usage_hourly (accounting) nor
-- admin_token_use. The outbox also holds usage events (who used which model, at
-- what cost, never the content of a request): see docs/AUDIT.md.
GRANT SELECT ON
    %[4]s
  TO %[1]s;

-- On PostgreSQL 14 and older, every role may create tables in the public
-- schema: run  REVOKE CREATE ON SCHEMA public FROM PUBLIC;  (version 15 and later
-- already do).
`, q(role), q(database), q(schema), strings.Join(tables, ",\n    "))
	return b.String(), nil
}
