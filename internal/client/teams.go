package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// TeamHeader selects, among the teams of the caller, the one a request of
// the gate API acts for.
const TeamHeader = "X-DNS-Gate-Team"

// ErrNoTeams is returned by Teams and Team when the gate does not serve the
// teams API (gates before first-class teams).
var ErrNoTeams = errors.New("the gate does not serve the teams API (GET /api/v1/teams)")

// unknownRoute reports the 404 a gate answers for a route it does not serve.
func unknownRoute(err error) bool {
	e, ok := AsAPIError(err)
	return ok && (e.Status == http.StatusNotFound && strings.Contains(e.Message, "unknown API endpoint") ||
		e.Status == http.StatusMethodNotAllowed)
}

// Teams lists the teams of the gate policy. ErrNoTeams on gates without teams.
func (c *Client) Teams(ctx context.Context) (*TeamList, error) {
	var tl TeamList
	if _, err := c.do(ctx, http.MethodGet, "/api/v1/teams", nil, nil, &tl); err != nil {
		if unknownRoute(err) {
			return nil, ErrNoTeams
		}
		return nil, err
	}
	return &tl, nil
}

// Team returns one team with what it owns in the zones the caller can read.
// A 404 is returned as an APIError (IsNotFound); ErrNoTeams on gates
// without teams.
func (c *Client) Team(ctx context.Context, name string) (*TeamDetail, error) {
	var td TeamDetail
	_, err := c.do(ctx, http.MethodGet, "/api/v1/teams/"+url.PathEscape(strings.ToLower(name)), nil, nil, &td)
	if err == nil {
		return &td, nil
	}
	if !IsNotFound(err) {
		return nil, err
	}
	if unknownRoute(err) {
		return nil, ErrNoTeams
	}
	if _, lerr := c.Teams(ctx); errors.Is(lerr, ErrNoTeams) {
		return nil, ErrNoTeams
	}
	return nil, err
}
