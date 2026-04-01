package handler

import (
	"net/http"
	"strings"

	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/service"
)

type DiscoverHandler struct {
	cfg *config.Config
	svc *service.DeviceService
}

func NewDiscoverHandler(cfg *config.Config, svc *service.DeviceService) *DiscoverHandler {
	return &DiscoverHandler{cfg: cfg, svc: svc}
}

type discoverRequest struct {
	UserID             string `json:"sub"`
	ClientID           string `json:"client_id"`
	RedirectURI        string `json:"redirect_uri"`
	DeviceID           string `json:"device_id"`
	Name               string `json:"name"`
	UserAgent          string `json:"user_agent"`
	Platform           string `json:"platform"`
	PublicKey          string `json:"public_key"`
	KeyAlgorithm       string `json:"key_algorithm"`
	HardwareLevel      string `json:"hardware_level"`
	ProviderName       string `json:"provider_name"`
	Challenge          string `json:"challenge,omitempty"`
	ChallengeSignature string `json:"challenge_signature,omitempty"`
}

func (h *DiscoverHandler) baseResponse(clientID string) map[string]interface{} {
	authBaseURL := strings.TrimRight(h.cfg.KeycloakPublicURI, "/")
	authPath := "/realms/" + h.cfg.KeycloakRealm + "/protocol/openid-connect/auth"
	tokenPath := "/realms/" + h.cfg.KeycloakRealm + "/protocol/openid-connect/token"
	logoutPath := "/realms/" + h.cfg.KeycloakRealm + "/protocol/openid-connect/logout"

	return map[string]interface{}{
		"auth_url":      authBaseURL + authPath,
		"token_url":     authBaseURL + tokenPath,
		"logout_url":    authBaseURL + logoutPath,
		"client_id":     clientID,
	}
}

// GET /discover
func (h *DiscoverHandler) Discover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := h.baseResponse(h.cfg.KeycloakClientID)
	jsonResponse(w, resp, http.StatusOK)
}
