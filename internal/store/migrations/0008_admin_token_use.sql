-- When each administration token was last used, and how many times. The
-- gateway counts in memory and writes the changes here every few seconds in one
-- statement, never once per request (admin.use_flush_every). A row stays after
-- its token is removed from the configuration: it is the record of what the
-- token did. Nothing here is a secret: a token id is a name.
CREATE TABLE admin_token_use (
    token_id     text PRIMARY KEY,
    last_used_at timestamptz NOT NULL,
    uses         bigint      NOT NULL,
    last_remote  text        NOT NULL DEFAULT ''
);
