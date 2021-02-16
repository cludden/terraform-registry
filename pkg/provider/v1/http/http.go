package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	v1 "github.com/cludden/terraform-registry/pkg/provider/v1"
	"github.com/gorilla/mux"
	"github.com/twitchtv/twirp"
)

// Handler exposes the provider.v1 http protocol
type Handler struct {
	service *v1.Service
}

// Register initializes a new provider.v1 service exposed via http
func Register(r *mux.Router, conf v1.ServiceConfig) error {
	svc, err := v1.NewService(conf)
	if err != nil {
		return err
	}

	h := Handler{
		service: svc,
	}

	r.HandleFunc("/gpg-public-keys/{id}", h.registerGPGPublicKey).Methods("PUT")
	r.HandleFunc("/{namespace}/{type}/{version}", h.publishVersion).Methods("PUT")
	r.HandleFunc("/{namespace}/{type}/versions", h.listAvailableVersions).Methods("GET")
	r.HandleFunc("/{namespace}/{type}/{version}/download/{os}/{arch}", h.findProviderPackage).Methods("GET")
	return nil
}

func (h *Handler) findProviderPackage(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)

	out, err := h.service.FindProviderPackage(r.Context(), v1.FindProviderPackageInput{
		Provider: v1.Provider{
			Namespace: params["namespace"],
			Type:      params["type"],
		},
		Platform: v1.Platform{
			Arch: params["arch"],
			OS:   params["os"],
		},
		Version: params["version"],
	})
	if err != nil {
		twirp.WriteError(w, err)
		return
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		twirp.WriteError(w, err)
	}
}

func (h *Handler) listAvailableVersions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	out, err := h.service.ListAvailableVersions(r.Context(), v1.ListAvailableVersionsInput{
		Provider: v1.Provider{
			Namespace: vars["namespace"],
			Type:      vars["type"],
		},
	})
	if err != nil {
		twirp.WriteError(w, err)
		return
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		twirp.WriteError(w, err)
	}
}

func (h *Handler) publishVersion(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)

	if r.Body == nil {
		twirp.WriteError(w, twirp.NewError(twirp.Malformed, "missing required payload"))
		return
	}

	var version v1.Version
	if err := json.NewDecoder(r.Body).Decode(&version); err != nil {
		http.Error(w, fmt.Sprintf("error parsing payload: %v", err), http.StatusBadRequest)
		return
	}
	if v, ok := params["version"]; ok || len(v) > 0 {
		version.Version = v
	}
	if strings.HasPrefix(version.Version, "v") {
		http.Error(w, fmt.Sprintf("validation failed: version %q should not start with v", version.Version), http.StatusUnprocessableEntity)
		return
	}

	out, err := h.service.PublishVersion(r.Context(), v1.PublishVersionInput{
		Provider: v1.Provider{
			Namespace: params["namespace"],
			Type:      params["type"],
		},
		Version: version,
	})
	if err != nil {
		twirp.WriteError(w, err)
		return
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		twirp.WriteError(w, fmt.Errorf("error marshalling response: %v", err))
	}
}

func (h *Handler) registerGPGPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		twirp.WriteError(w, twirp.NewError(twirp.Malformed, "missing required payload"))
		return
	}

	params := mux.Vars(r)

	var key v1.RegisterGPGPublicKeyInput
	if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
		http.Error(w, fmt.Sprintf("error parsing payload: %v", err), http.StatusBadRequest)
		return
	}
	if id, ok := params["id"]; ok && len(id) > 0 {
		key.KeyID = id
	}

	out, err := h.service.RegisterGPGPublicKey(r.Context(), key)
	if err != nil {
		twirp.WriteError(w, err)
		return
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		twirp.WriteError(w, fmt.Errorf("error marshalling response: %v", err))
	}
}
