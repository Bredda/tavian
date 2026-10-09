// Package quota implements admission control and reserve/settle accounting for
// rpm, concurrency, tpm and tokens per day (docs/QUOTAS_AND_METERING.md,
// ADR-0007).
//
// Counters are keyed by scope and dimension, not by policy: the tokens a team
// used today are one fact, whichever policies limit them, and renaming a policy
// resets nothing. They live in memory and are lost on restart; the limits come
// from the configuration snapshot on every call, so a reload changes them
// without touching the counts. The Store is the single-instance implementation;
// a shared one (Redis) will sit behind the same calls.
package quota
