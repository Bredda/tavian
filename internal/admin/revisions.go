package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/store"
)

// revisionID is the form of a revision id; "active" stands for the active one.
var revisionID = regexp.MustCompile(`^[0-9a-f]{12}$`)

// activeID says which revision is active: the one the database points to, or
// the running one while nothing was ever activated.
func (a *api) activeID(r *http.Request) (string, error) {
	act, ok, err := a.Store.ActiveRevision(r.Context())
	if err != nil {
		return "", err
	}
	if ok {
		return act.Revision, nil
	}
	return a.Snap.Load().Revision, nil
}

type revisionSummary struct {
	Revision      string    `json:"revision"`
	Profile       string    `json:"profile"`
	TavianVersion string    `json:"tavian_version"`
	FirstLoadedAt time.Time `json:"first_loaded_at"`
	Active        bool      `json:"active"`
}

func (a *api) revisions(w http.ResponseWriter, r *http.Request, _ call) {
	limit, before, ok := paging(w, r)
	if !ok {
		return
	}
	active, err := a.activeID(r)
	if err == nil {
		var list []store.StoredRevision
		var next int64
		if list, next, err = a.Store.ListRevisions(r.Context(), limit, before); err == nil {
			out := make([]revisionSummary, 0, len(list))
			for _, v := range list {
				out = append(out, revisionSummary{v.ID, v.Profile, v.Version, v.FirstLoadedAt.UTC(), v.ID == active})
			}
			body := map[string]any{"revisions": out, "active": active}
			if next > 0 {
				body["next"] = strconv.FormatInt(next, 10)
			}
			writeJSON(w, http.StatusOK, body)
			return
		}
	}
	a.Log.ErrorContext(r.Context(), "listing revisions failed", "error", err)
	writeError(w, http.StatusServiceUnavailable, "unavailable", "the revisions cannot be read")
}

// revisionContent is a revision with what it was made of.
type revisionContent struct {
	revisionSummary
	Config   string `json:"config"`
	Policies []File `json:"policies"`
}

// load reads a revision by id, "active" included. It answers the error itself.
func (a *api) load(w http.ResponseWriter, r *http.Request, id string) (revisionContent, bool) {
	if id == "active" {
		var err error
		if id, err = a.activeID(r); err != nil {
			a.Log.ErrorContext(r.Context(), "reading the active revision failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "the active revision cannot be read")
			return revisionContent{}, false
		}
	}
	if !revisionID.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_request", `a revision is 12 hexadecimal characters, or "active"`)
		return revisionContent{}, false
	}
	v, err := a.Store.GetRevision(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such revision: "+id)
		return revisionContent{}, false
	}
	if err != nil {
		a.Log.ErrorContext(r.Context(), "reading a revision failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the revision cannot be read")
		return revisionContent{}, false
	}
	active, err := a.activeID(r)
	if err != nil {
		a.Log.ErrorContext(r.Context(), "reading the active revision failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the active revision cannot be read")
		return revisionContent{}, false
	}
	var sources []policy.Source
	if len(v.Policies) > 0 {
		if err := json.Unmarshal(v.Policies, &sources); err != nil {
			a.Log.ErrorContext(r.Context(), "a stored revision has unreadable policies", "revision", id, "error", err)
			writeError(w, http.StatusInternalServerError, "corrupt_revision", "the policy files of this revision cannot be read")
			return revisionContent{}, false
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	files := make([]File, 0, len(sources))
	for _, p := range sources {
		files = append(files, File{Name: p.Name, YAML: string(p.Raw)})
	}
	return revisionContent{
		revisionSummary: revisionSummary{v.ID, v.Profile, v.Version, v.FirstLoadedAt.UTC(), v.ID == active},
		Config:          string(v.YAML), Policies: files,
	}, true
}

func (a *api) revision(w http.ResponseWriter, r *http.Request, _ call) {
	if v, ok := a.load(w, r, r.PathValue("id")); ok {
		writeJSON(w, http.StatusOK, v)
	}
}

// fileDiff is the difference of one file between two revisions.
type fileDiff struct {
	Name   string `json:"name"`
	Status string `json:"status"` // added, removed or modified
	Diff   string `json:"diff"`
}

func (a *api) diff(w http.ResponseWriter, r *http.Request, _ call) {
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if from == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "from is required (a revision id, or active)")
		return
	}
	if to == "" {
		to = "active"
	}
	x, ok := a.load(w, r, from)
	if !ok {
		return
	}
	y, ok := a.load(w, r, to)
	if !ok {
		return
	}
	files := []fileDiff{}
	add := func(name string, before, after *string) {
		switch {
		case before == nil:
			files = append(files, fileDiff{name, "added", unifiedDiff(name, "", *after, true, false)})
		case after == nil:
			files = append(files, fileDiff{name, "removed", unifiedDiff(name, *before, "", false, true)})
		case *before != *after:
			files = append(files, fileDiff{name, "modified", unifiedDiff(name, *before, *after, false, false)})
		}
	}
	add("tavian.yaml", &x.Config, &y.Config)
	byName := map[string][2]*string{}
	names := []string{}
	for i := range x.Policies {
		p := byName[x.Policies[i].Name]
		p[0] = &x.Policies[i].YAML
		byName[x.Policies[i].Name] = p
		names = append(names, x.Policies[i].Name)
	}
	for i := range y.Policies {
		p, seen := byName[y.Policies[i].Name]
		p[1] = &y.Policies[i].YAML
		byName[y.Policies[i].Name] = p
		if !seen {
			names = append(names, y.Policies[i].Name)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		add("policies/"+n, byName[n][0], byName[n][1])
	}
	writeJSON(w, http.StatusOK, map[string]any{"from": x.Revision, "to": y.Revision, "files": files})
}

// paging reads limit and before; it answers the error itself.
func paging(w http.ResponseWriter, r *http.Request) (limit int, before int64, ok bool) {
	limit = 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 500")
			return 0, 0, false
		}
		limit = n
	}
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid_request", "before must be a positive integer, as given by a previous page")
			return 0, 0, false
		}
		before = n
	}
	return limit, before, true
}
