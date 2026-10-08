// Package inspect will hold the content inspection engine: detectors that
// turn request and response content into findings and a classification label
// (M2: L0 deterministic and L1 configurable detectors). See docs/SECURITY.md
// and ADR-0004. Detectors are local only; the interface must stay remote-friendly
// so L2 detectors can run in a sidecar (ADR-0012).
package inspect
