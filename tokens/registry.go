package tokens

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	x.RegistryCookieStore
	x.RegistryLogger
	Registry

	OAuth2Storage() x.FositeStorer
	OpenIDJWTStrategy() jwk.JWTStrategy
	OpenIDConnectRequestValidator() *openid.OpenIDConnectRequestValidator
	ScopeStrategy() fosite.ScopeStrategy
}

type Registry interface {
	OAuth2Provider() fosite.OAuth2Provider
	AudienceStrategy() fosite.AudienceMatchingStrategy

	AccessTokenJWTStrategy() jwk.JWTStrategy
}

type Configuration interface {
	configuration.Provider
}
