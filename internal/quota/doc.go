// Package quota will implement admission control and reserve/settle accounting
// for rpm, concurrency, tpm, daily tokens and budget (M2). See
// docs/QUOTAS_AND_METERING.md and ADR-0007. The counter store sits behind an
// interface: in memory for one instance, Redis for several.
package quota
