package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	providerV1 "github.com/cludden/terraform-registry/pkg/provider/v1"
	providerV1http "github.com/cludden/terraform-registry/pkg/provider/v1/http"
	"github.com/cludden/terraform-registry/pkg/server/logging"
	"github.com/cludden/terraform-registry/pkg/server/oidc"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Config defines runtime configuration for a valid server command
type Config struct {
	Log      logging.Config            `mapstructure:"log"`
	OIDC     *oidc.Config              `mapstructure:"oidc"`
	Provider *providerV1.ServiceConfig `mapstructure:"provider"`
}

// NewServer configures a terraform service provider server
func NewServer(conf Config) (http.Handler, error) {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(conf.Log.Level)
	if err != nil {
		level = logrus.DebugLevel
	}
	logrus.SetLevel(level)

	r := mux.NewRouter()

	services := map[string]string{}

	middlewares := []mux.MiddlewareFunc{}
	if level <= logrus.DebugLevel {
		logrus.Debugln("logging middleware enabled")
		r.Use(logging.Middleware())
	}

	if conf.OIDC != nil {
		m, err := conf.OIDC.Middleware()
		if err != nil {
			return nil, fmt.Errorf("error initializing oidc middleware: %v", err)
		}
		logrus.Debugln("oidc middleware enabled")
		middlewares = append(middlewares, m)
	}

	if conf.Provider != nil {
		pathPrefix := "/providers/v1"
		s := r.PathPrefix(pathPrefix).Subrouter()
		s.Use(middlewares...)
		if err := providerV1http.Register(s, *conf.Provider); err != nil {
			return nil, fmt.Errorf("error initializing provider.v1 registry: %v", err)
		}
		logrus.Debugln("providers.v1 service enabled")
		services["providers.v1"] = pathPrefix
	}

	discovery, err := json.Marshal(services)
	if err != nil {
		return nil, fmt.Errorf("error marshalling service discovery info: %v", err)
	}

	r.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write(discovery)
	})

	return r, nil
}
