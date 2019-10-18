package tokens

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/hydra/oauth2"
	"github.com/ory/hydra/x"
	"github.com/ory/x/urlx"
	"github.com/pkg/errors"
)

type Handler struct {
	r InternalRegistry
	c Configuration
}

const (
	TokensPath = "/tokens"
)

func NewHandler(
	r InternalRegistry,
	c Configuration,
) *Handler {
	return &Handler{
		c: c,
		r: r,
	}
}

func (h *Handler) SetRoutes(admin *x.RouterAdmin) {
	admin.POST(TokensPath, h.PostSession)
}

// swagger:route POST /tokens admin createSession
//
// Create sessions for a subject for a specific OAuth 2.0 Client
//
// This endpoint creates a session for a subject for a specific OAuth 2.0 Client and creates an OAuth Access Token.
//
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       204: emptyResponse
//       400: genericError
//       404: genericError
//       500: genericError
func (h *Handler) PostSession(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var sr SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&sr); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	var ctx = r.Context()
	q := url.Values{}
	q.Set("client_id", sr.ClientID)
	// get from client!
	q.Set("redirect_uri", "http://localhost:5000/@callback")
	q.Set("scope", sr.Scope)
	q.Set("state", "foobar12345")
	q.Set("access_type", "offline")
	q.Set("response_type", "code")
	url, err := url.Parse("https://localhost:4444/oauth2/auth?" + q.Encode())
	if err != nil {
		x.LogError(err, h.r.Logger())
		return
	}

	// strings.NewReader()
	initiatizationOAuthRequest, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		x.LogError(err, h.r.Logger())
		return
	}

	authorizeRequest, err := h.r.OAuth2Provider().NewAuthorizeRequest(ctx, r)
	if err != nil {
		x.LogError(err, h.r.Logger())
		h.writeAuthorizeError(w, r, authorizeRequest, err)
		return
	}

	response, nil := oauth2.HandleOauth2Request(h.r, h.c, authorizeRequest, w, r)
	if err != nil {
		h.writeAuthorizeError(w, r, authorizeRequest, err)
		return
	}
	h.r.OAuth2Provider().WriteAuthorizeResponse(w, authorizeRequest, response)
}

func (h *Handler) writeAuthorizeError(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, err error) {
	if !ar.IsRedirectURIValid() {
		h.forwardError(w, r, err)
		return
	}

	h.r.OAuth2Provider().WriteAuthorizeError(w, ar, err)
}

func (h *Handler) forwardError(w http.ResponseWriter, r *http.Request, err error) {
	rfErr := fosite.ErrorToRFC6749Error(err)
	query := url.Values{"error": {rfErr.Name}, "error_description": {rfErr.Description}, "error_hint": {rfErr.Hint}}

	if h.c.ShareOAuth2Debug() {
		query.Add("error_debug", rfErr.Debug)
	}

	http.Redirect(w, r, urlx.CopyWithQuery(h.c.ErrorURL(), query).String(), http.StatusFound)
}
