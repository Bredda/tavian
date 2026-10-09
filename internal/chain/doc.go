// Package chain makes the decision records tamper-evident (docs/SECURITY.md,
// "Integrity").
//
// A consumer of the outbox (the Sealer) links every decision record to the one
// before it: each chain entry holds a hash of the record and the hash of the
// previous entry, so changing, removing or reordering a record breaks every
// entry after it. The chain alone does not stop someone who can write to the
// database from recomputing all of it, so the Sealer also signs seals (a
// statement about a stretch of the chain) with a key that is not in the
// database. An auditor who keeps the seals elsewhere can tell that history was
// rewritten. Verify checks all of it, and `tavian verify-audit` runs it.
package chain
