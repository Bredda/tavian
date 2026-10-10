-- Which configuration revision is the active one, once the administration API
-- is on: applying or rolling back through the API moves this pointer, in the
-- same transaction as the change record and the revision itself. A single row.
--
-- file_revision is the revision of the configuration file the gateway last
-- started or reloaded from. At startup the file wins when it differs from
-- that (the operator edited it); otherwise the active revision wins, so that
-- what the API applied survives a restart.
CREATE TABLE config_active (
    only_row      boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    revision      text        NOT NULL REFERENCES config_revisions (revision),
    activated_at  timestamptz NOT NULL,
    activated_by  text        NOT NULL,
    file_revision text        NOT NULL DEFAULT ''
);

-- Revisions are listed newest first by when they were first seen.
ALTER TABLE config_revisions ADD COLUMN seq bigserial;
CREATE UNIQUE INDEX config_revisions_seq_idx ON config_revisions (seq);
