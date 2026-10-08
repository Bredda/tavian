-- The policy files in force at each configuration revision (docs/POLICY.md), as
-- [{"name": "finance.yaml", "yaml": "..."}]. The revision identifier covers them,
-- so a decision record's config_revision resolves to the exact rules that
-- decided it. Revisions recorded before policies existed have none.
ALTER TABLE config_revisions ADD COLUMN policies jsonb NOT NULL DEFAULT '[]';
