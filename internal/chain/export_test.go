package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

func (e *env) export(pool *pgxpool.Pool, opt ExportOptions) []Entry {
	e.t.Helper()
	var out []Entry
	n, err := Export(context.Background(), pool, opt, func(x Entry) error { out = append(out, x); return nil })
	if err != nil || n != len(out) {
		e.t.Fatalf("export: %d entries, %d returned (%v)", len(out), n, err)
	}
	return out
}

func TestExportGivesWhatAnAuditorNeedsToCheckTheChainWithOtherTools(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(3, "d")
	e.adminChange("a-1", store.OutcomeApplied)
	e.chained(4)
	all := e.export(e.st.Pool(), ExportOptions{})
	if len(all) != 4 {
		t.Fatalf("entries = %d", len(all))
	}
	prev := hex.EncodeToString(Genesis())
	for i, x := range all {
		if x.Position != int64(i+1) || x.PrevHash != prev || x.Pruned || x.EventID == "" || x.OccurredAt.IsZero() {
			t.Fatalf("entry %d = %+v (previous hash %s)", i, x, prev)
		}
		// the record hashes to what the chain says, and the entry hash follows from it
		content, err := ContentHash(x.Record)
		if err != nil || hex.EncodeToString(content) != x.ContentHash {
			t.Errorf("entry %d: the record hashes to %x, the entry says %s (%v)", i, content, x.ContentHash, err)
		}
		pb, _ := hex.DecodeString(x.PrevHash)
		if got := EntryHash(x.Position, pb, x.EventID, x.OccurredAt, content); hex.EncodeToString(got) != x.EntryHash {
			t.Errorf("entry %d: the entry hash is not the one computed from its parts", i)
		}
		prev = x.EntryHash
	}
	if all[0].Kind != "decision" || all[3].Kind != "admin_change" {
		t.Errorf("kinds: %s ... %s", all[0].Kind, all[3].Kind)
	}
	var rec map[string]any
	if err := json.Unmarshal(all[3].Record, &rec); err != nil || rec["actor"] != "ops-alice" || rec["action"] != "config.reload" {
		t.Errorf("the admin change record = %s", all[3].Record)
	}
}

func TestExportFilters(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(2, "d")
	e.adminChange("a-1", store.OutcomeApplied)
	e.decisions(2, "e")
	e.chained(5)
	pool := e.st.Pool()
	if got := e.export(pool, ExportOptions{Kinds: []string{KindAdminChange}}); len(got) != 1 || got[0].EventID != "a-1" {
		t.Errorf("admin changes only: %+v", got)
	}
	if got := e.export(pool, ExportOptions{Kinds: []string{KindDecision}}); len(got) != 4 {
		t.Errorf("decisions only: %d", len(got))
	}
	if got := e.export(pool, ExportOptions{Kinds: []string{KindDecision, KindAdminChange}}); len(got) != 5 {
		t.Errorf("both kinds: %d", len(got))
	}
	if got := e.export(pool, ExportOptions{FromPosition: 3}); len(got) != 2 || got[0].Position != 4 {
		t.Errorf("after position 3: %+v", got)
	}
	// time bounds: since is included, until is not
	all := e.export(pool, ExportOptions{})
	mid := all[2].OccurredAt
	if got := e.export(pool, ExportOptions{Since: mid}); len(got) == 0 || got[0].OccurredAt.Before(mid) {
		t.Errorf("since: %+v", got)
	}
	if got := e.export(pool, ExportOptions{Until: mid}); len(got) == 5 || len(got) == 0 && !mid.After(all[0].OccurredAt) {
		t.Errorf("until: %d entries", len(got))
	}
	if got := e.export(pool, ExportOptions{Since: time.Now().Add(time.Hour)}); len(got) != 0 {
		t.Errorf("a window in the future: %d", len(got))
	}
	if got := e.export(pool, ExportOptions{Until: time.Now().Add(-24 * time.Hour)}); len(got) != 0 {
		t.Errorf("a window in the past: %d", len(got))
	}
}

func TestExportPagesThroughALongChain(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(pageSize+120, "d")
	e.chained(int64(pageSize + 120))
	got := e.export(e.st.Pool(), ExportOptions{})
	if len(got) != pageSize+120 || got[len(got)-1].Position != int64(pageSize+120) {
		t.Fatalf("%d entries, last at %d", len(got), got[len(got)-1].Position)
	}
	for i, x := range got {
		if x.Position != int64(i+1) {
			t.Fatalf("entry %d is at position %d: a page was skipped or repeated", i, x.Position)
		}
	}
}

func TestExportOfARecordThatRetentionRemoved(t *testing.T) {
	e := newEnv(t, false)
	ids := e.decisions(2, "d")
	e.chained(2)
	e.exec(`DELETE FROM outbox WHERE event_id = $1`, ids[0])
	got := e.export(e.st.Pool(), ExportOptions{})
	if len(got) != 2 || !got[0].Pruned || string(got[0].Record) != "null" || got[0].Kind != "decision" || got[0].EntryHash == "" || got[1].Pruned {
		t.Errorf("entries = %+v", got)
	}
	// the kind of a removed record is known: only decision records are ever removed
	if only := e.export(e.st.Pool(), ExportOptions{Kinds: []string{KindAdminChange}}); len(only) != 0 {
		t.Errorf("a removed record showed up as an admin change: %+v", only)
	}
	if only := e.export(e.st.Pool(), ExportOptions{Kinds: []string{KindDecision}}); len(only) != 2 {
		t.Errorf("decisions: %d", len(only))
	}
}

func TestExportAndVerifyWithTheAuditorRole(t *testing.T) {
	e := newEnv(t, true)
	e.decisions(8, "d")
	e.adminChange("a-1", store.OutcomeApplied)
	e.chained(9)
	pool, err := pgxpool.New(context.Background(), storetest.AuditorURL(t, e.url))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if got := e.export(pool, ExportOptions{}); len(got) != 9 {
		t.Errorf("the auditor exported %d entries", len(got))
	}
	rep, err := Verify(context.Background(), pool, Options{PublicKeys: []ed25519.PublicKey{e.pub}})
	if err != nil || !rep.OK() {
		t.Fatalf("verification with the read-only role: %v %s", err, problems(rep))
	}
	if rep.Entries != 9 || !rep.SignaturesChecked || rep.Seals == 0 {
		t.Errorf("entries checked = %d, signatures %v, seals %d", rep.Entries, rep.SignaturesChecked, rep.Seals)
	}
	if _, err := Seals(context.Background(), pool); err != nil {
		t.Errorf("seals: %v", err)
	}
	// it finds what was tampered with, through the same role
	e.exec(`UPDATE outbox SET payload = jsonb_set(payload, '{actor}', '"someone-else"') WHERE event_id = 'a-1'`)
	rep, err = Verify(context.Background(), pool, Options{PublicKeys: []ed25519.PublicKey{e.pub}})
	if err != nil || rep.OK() {
		t.Errorf("tampering went unnoticed by the auditor role: %v %s", err, problems(rep))
	}
	// and the role cannot repair it, nor make it worse
	if _, err := pool.Exec(context.Background(), `UPDATE outbox SET payload = '{}'`); err == nil {
		t.Error("the auditor role could update the outbox")
	}
}

// Records made one second apart, so that the edges of a time window can be told.
func TestExportTimeWindowEdges(t *testing.T) {
	e := newEnv(t, false)
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var rows []store.OutboxRow
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("w-%d", i)
		rows = append(rows, store.OutboxRow{EventID: id, Kind: "decision", OccurredAt: base.Add(time.Duration(i) * time.Second), Payload: []byte(`{"n":` + fmt.Sprint(i) + `}`)})
	}
	if err := e.st.InsertOutbox(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	e.chained(5)
	ids := func(es []Entry) string {
		var out []string
		for _, x := range es {
			out = append(out, x.EventID)
		}
		return strings.Join(out, ",")
	}
	pool := e.st.Pool()
	t2 := base.Add(2 * time.Second)
	if got := ids(e.export(pool, ExportOptions{Since: t2})); got != "w-2,w-3,w-4" {
		t.Errorf("since is included: %s", got)
	}
	if got := ids(e.export(pool, ExportOptions{Until: t2})); got != "w-0,w-1" {
		t.Errorf("until is not included: %s", got)
	}
	if got := ids(e.export(pool, ExportOptions{Since: base.Add(time.Second), Until: base.Add(4 * time.Second)})); got != "w-1,w-2,w-3" {
		t.Errorf("a window: %s", got)
	}
	if got := ids(e.export(pool, ExportOptions{Since: t2, Until: t2})); got != "" {
		t.Errorf("an empty window: %s", got)
	}
}

// Times are written in UTC whatever the zone of the machine that exports.
func TestExportTimesAreUTC(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(1, "d")
	e.chained(1)
	saved := time.Local
	time.Local = time.FixedZone("elsewhere", 5*3600)
	defer func() { time.Local = saved }()
	got := e.export(e.st.Pool(), ExportOptions{})
	if len(got) != 1 || got[0].OccurredAt.Location() != time.UTC {
		t.Fatalf("entries = %+v", got)
	}
	b, _ := json.Marshal(got[0])
	if !strings.Contains(string(b), "Z\"") {
		t.Errorf("the time is not in UTC: %s", b)
	}
}

// The construction written in docs/AUDIT.md, implemented again here without
// the code of this package, gives the hashes of the export: what an auditor
// with a tool of their own would find.
func TestTheDocumentedConstructionGivesTheHashesOfTheExport(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(3, "d")
	e.adminChange("a-1", store.OutcomeApplied)
	e.chained(4)
	canonical := func(raw json.RawMessage) []byte {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil { // encoding/json sorts object keys and writes no spaces
			t.Fatal(err)
		}
		return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	}
	be64 := func(n int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(n)) }
	genesis := sha256.Sum256([]byte("tavian-audit-genesis-v1"))
	prev := genesis[:]
	for _, x := range e.export(e.st.Pool(), ExportOptions{}) {
		content := sha256.Sum256(canonical(x.Record))
		if hex.EncodeToString(content[:]) != x.ContentHash {
			t.Errorf("entry %d: content hash %x, exported %s", x.Position, content, x.ContentHash)
		}
		if hex.EncodeToString(prev) != x.PrevHash {
			t.Errorf("entry %d: previous hash %x, exported %s", x.Position, prev, x.PrevHash)
		}
		var in []byte
		in = append(in, "tavian-audit-entry-v1"...)
		in = append(in, 0)
		in = append(in, be64(x.Position)...)
		in = append(in, prev...)
		in = append(in, be64(int64(len(x.EventID)))...)
		in = append(in, x.EventID...)
		in = append(in, be64(x.OccurredAt.UnixMicro())...)
		in = append(in, content[:]...)
		entry := sha256.Sum256(in)
		if hex.EncodeToString(entry[:]) != x.EntryHash {
			t.Errorf("entry %d: entry hash %x, exported %s", x.Position, entry, x.EntryHash)
		}
		prev = entry[:]
	}
}
