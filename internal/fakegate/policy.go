package fakegate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// Policy is the delegation API of the fake gate: delegated roles and
// bindings by name, ETags, If-Match / If-None-Match, 409 policy_busy.
type Policy struct {
	Objects map[string]*client.DelegatedObject // "<kind>/<name>"
	version int

	Busy          int    // writes to refuse with 409 policy_busy
	BusyRefusals  int    // writes refused so far
	ForbiddenZone string // a rule on this zone is refused with 400 invalid_policy
	IfNoneMatch   int
	IfMatch       int
	ManagedBy     []string
}

// NewPolicy returns an empty delegation API.
func NewPolicy() *Policy { return &Policy{Objects: map[string]*client.DelegatedObject{}} }

func (p *Policy) refuseBusy(w http.ResponseWriter) bool {
	if p.Busy > 0 {
		p.Busy--
		p.BusyRefusals++
		Error(w, http.StatusConflict, "policy_busy", "concurrent activation")
		return true
	}
	return false
}

func (p *Policy) serve(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, client.DelegatedPath+"/")
	kindPlural, name, ok := strings.Cut(rest, "/")
	if !ok || (kindPlural != "roles" && kindPlural != "bindings") {
		Error(w, http.StatusNotFound, "not_found", rest)
		return
	}
	kind := strings.TrimSuffix(kindPlural, "s")
	key := kind + "/" + name
	cur := p.Objects[key]
	switch r.Method {
	case http.MethodGet:
		if cur == nil {
			Error(w, http.StatusNotFound, "not_found", key)
			return
		}
		w.Header().Set("ETag", cur.ETag)
		writeJSON(w, http.StatusOK, cur)
		return
	case http.MethodDelete:
		if p.refuseBusy(w) {
			return
		}
		if cur == nil {
			Error(w, http.StatusNotFound, "not_found", key)
			return
		}
		delete(p.Objects, key)
		writeJSON(w, http.StatusOK, client.DelegatedResult{Changed: true, RevisionID: "rev"})
		return
	case http.MethodPut:
	default:
		Error(w, http.StatusMethodNotAllowed, "method_not_allowed", r.Method)
		return
	}
	if p.refuseBusy(w) {
		return
	}
	if r.Header.Get("If-None-Match") == "*" {
		p.IfNoneMatch++
		if cur != nil {
			Error(w, http.StatusPreconditionFailed, "precondition", "exists")
			return
		}
	}
	if m := r.Header.Get("If-Match"); m != "" {
		if cur == nil || m != cur.ETag {
			Error(w, http.StatusPreconditionFailed, "precondition", "changed")
			return
		}
		p.IfMatch++
	}
	var body struct {
		client.Role
		client.Binding
		Delegation string `json:"delegation"`
		ManagedBy  string `json:"managed_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p.ManagedBy = append(p.ManagedBy, body.ManagedBy)
	delegation := body.Delegation
	if delegation == "" {
		delegation = "ci"
	}
	if cur != nil && cur.Owner.Delegation != delegation {
		Error(w, http.StatusConflict, "not_owner", "owned by "+cur.Owner.Delegation)
		return
	}
	obj := &client.DelegatedObject{Kind: kind, Name: name, Owner: client.DelegatedOwner{
		Delegation: delegation, ManagedBy: body.ManagedBy, CreatedBy: "fake:terraform", UpdatedBy: "fake:terraform"}}
	if kind == client.KindRole {
		role := body.Role
		for _, rule := range role.Rules {
			for _, z := range rule.Zones {
				if p.ForbiddenZone != "" && z == p.ForbiddenZone {
					writeJSON(w, http.StatusBadRequest, map[string]any{
						"reason": "invalid_policy", "message": "outside the delegation",
						"errors": []map[string]string{{"path": "rules[0].zones[0]", "message": "zone " + z + " is not delegated"}},
					})
					return
				}
			}
		}
		obj.Role = &role
	} else {
		b := body.Binding
		obj.Binding = &b
	}
	p.version++
	obj.ETag = fmt.Sprintf(`"%s-%d"`, kind, p.version)
	p.Objects[key] = obj
	w.Header().Set("ETag", obj.ETag)
	writeJSON(w, http.StatusOK, client.DelegatedResult{Object: obj, Changed: true, RevisionID: fmt.Sprintf("rev-%d", p.version)})
}
