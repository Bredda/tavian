# ADR-0015: Go version policy

- Status: Accepted (2026-10-09)
- Date: 2026-10-09

## Context
`go.mod` could target the previous stable Go release while the CI and the Docker image track the latest, which left it open how many releases back are supported. Tavian is distributed as binaries and a container image; nobody is meant to import it as a library, so there is no downstream build that needs an older toolchain.

## Decision
Tavian is built with the **latest stable Go release**, and only that one is supported.

- The `go` line of `go.mod` names that release; the CI reads it (`go-version-file: go.mod`) and the Dockerfile builds with the same minor version.
- When a new Go release comes out, the `go` line and the Dockerfile are moved to it within a month, in one `build` pull request. Dependabot proposes the image bump; the `go` line is bumped by hand, since Dependabot does not change it. Security fixes in the Go standard library arrive in patch releases of the current line, which the toolchain download and the image pick up.
- No promise is made that the code builds with older Go releases, and CI does not test them.

## Consequences
- One toolchain to test and to reason about; the standard library fixes and the language and runtime improvements are available at once.
- Someone who wants to build from source needs a recent Go; the toolchain download of the `go` command covers a machine with an older one.
- If Tavian ever publishes a Go package meant to be imported, this ADR is superseded by a policy of N and N-1 for that package.

## Alternatives considered
- **N and N-1** (`go.mod` on the previous release, CI on both) — useful for libraries; costs a second CI matrix and constrains the code to the older language level for no benefit to a binary.
- **Decide at the next release of Go** — keeps the question open without a reason.
