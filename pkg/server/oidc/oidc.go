package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/twitchtv/twirp"
)

// Config defines runtime configuration for oidc middleware
type Config struct {
	Algorithms      []string
	ClientID        string `mapstructure:"client_id"`
	Issuer          string `validate:"required"`
	SkipExpiryCheck bool   `mapstructure:"skip_expiry_check"`
	SkipIssuerCheck bool   `mapstructure:"skip_issuer_check"`
}

// Middleware initializes a new oidc middleware handler
func (conf Config) Middleware() (mux.MiddlewareFunc, error) {
	p, err := oidc.NewProvider(context.Background(), conf.Issuer)
	if err != nil {
		return nil, fmt.Errorf("error initializing oidc provider: %v", err)
	}

	cfg := oidc.Config{
		ClientID:             conf.ClientID,
		SupportedSigningAlgs: conf.Algorithms,
		SkipClientIDCheck:    conf.ClientID == "",
		SkipExpiryCheck:      conf.SkipExpiryCheck,
		SkipIssuerCheck:      conf.SkipIssuerCheck,
	}

	v := p.Verifier(&cfg)

	return mux.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if h == "" {
				twirp.WriteError(w, twirp.NewError(twirp.Unauthenticated, "missing required header: Authorization"))
				return
			}

			if !strings.HasPrefix(h, "Bearer ") {
				twirp.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid header: Authorization"))
				return
			}

			_, err := v.Verify(r.Context(), strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
			if err != nil {
				twirp.WriteError(w, twirp.NewError(twirp.Unauthenticated, err.Error()))
			}
			next.ServeHTTP(w, r)
		})
	}), nil
}
