package helpers

import (
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/hydra/consent"
	"github.com/ory/hydra/driver"
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/x"
	"github.com/pkg/errors"
)

func HandleOauth2Request(reg driver.RegistryBase, conf configuration.Provider,
	authorizeRequest fosite.AuthorizeRequester,
	w http.ResponseWriter, r *http.Request) (fosite.AuthorizeResponder, error) {
	var ctx = r.Context()

	session, err := reg.ConsentStrategy().HandleOAuth2AuthorizationRequest(w, r, authorizeRequest)
	if errors.Cause(err) == consent.ErrAbortOAuth2Request {
		// do nothing
		return nil, err
	} else if err != nil {
		x.LogError(err, reg.Logger())
		return nil, err
	}

	for _, scope := range session.GrantedScope {
		authorizeRequest.GrantScope(scope)
	}

	for _, audience := range session.GrantedAudience {
		authorizeRequest.GrantAudience(audience)
	}

	openIDKeyID, err := reg.OpenIDJWTStrategy().GetPublicKeyID(r.Context())
	if err != nil {
		x.LogError(err, reg.Logger())
		return nil, err
	}

	var accessTokenKeyID string
	if conf.AccessTokenStrategy() == "jwt" {
		accessTokenKeyID, err = reg.AccessTokenJWTStrategy().GetPublicKeyID(r.Context())
		if err != nil {
			x.LogError(err, reg.Logger())
			return nil, err
		}
	}

	authorizeRequest.SetID(session.Challenge)

	claims := &jwt.IDTokenClaims{
		Subject:                             session.ConsentRequest.SubjectIdentifier,
		Issuer:                              strings.TrimRight(conf.IssuerURL().String(), "/") + "/",
		IssuedAt:                            time.Now().UTC(),
		AuthTime:                            session.AuthenticatedAt,
		RequestedAt:                         session.RequestedAt,
		Extra:                               session.Session.IDToken,
		AuthenticationContextClassReference: session.ConsentRequest.ACR,

		// We do not need to pass the audience because it's included directly by ORY Fosite
		// Audience:    []string{authorizeRequest.GetClient().GetID()},

		// This is set by the fosite strategy
		// ExpiresAt:   time.Now().Add(h.IDTokenLifespan).UTC(),
	}
	claims.Add("sid", session.ConsentRequest.LoginSessionID)

	// done
	response, err := reg.OAuth2Provider().NewAuthorizeResponse(ctx, authorizeRequest, &Session{
		DefaultSession: &openid.DefaultSession{
			Claims: claims,
			Headers: &jwt.Headers{Extra: map[string]interface{}{
				// required for lookup on jwk endpoint
				"kid": openIDKeyID,
			}},
			Subject: session.ConsentRequest.Subject,
		},
		Extra:            session.Session.AccessToken,
		KID:              accessTokenKeyID,
		ClientID:         authorizeRequest.GetClient().GetID(),
		ConsentChallenge: session.Challenge,
	})
	if err != nil {
		x.LogError(err, reg.Logger())
		return nil, err
	}
	return response, nil
}
