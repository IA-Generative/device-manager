package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/ctxkeys"
	"github.com/ia-generative/device-service/internal/model"
	"github.com/ia-generative/device-service/internal/repository"
	"github.com/ia-generative/device-service/internal/service"
)

type AttestationHandler struct {
	attestSvc *service.AttestationService
	deviceSvc *service.DeviceService
	riskSvc   *service.RiskService
	logger    *zap.Logger
}

func NewAttestationHandler(
	attestSvc *service.AttestationService,
	deviceSvc *service.DeviceService,
	riskSvc *service.RiskService,
	logger *zap.Logger,
) *AttestationHandler {
	return &AttestationHandler{
		attestSvc: attestSvc,
		deviceSvc: deviceSvc,
		riskSvc:   riskSvc,
		logger:    logger,
	}
}

// POST /devices/register/challenge
// Génère un challenge pré-enregistrement (le device n'existe pas encore)
// Le challenge est lié au userID du JWT, stocké dans Redis.
func (h *AttestationHandler) RegisterChallenge(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	challenge, err := h.attestSvc.GenerateRegisterChallenge(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to generate register challenge",
			zap.String("user_id", userID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := model.ChallengeResponse{
		Challenge: challenge,
		ExpiresIn: 120, // 2 minutes
	}
	jsonResponse(w, resp, http.StatusOK)
}

// POST /devices/{device_id}/challenge
// Génère un challenge pour le device (WebAuthn / signature ECDSA)
func (h *AttestationHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		jsonError(w, "device_id required", http.StatusBadRequest)
		return
	}

	challenge, err := h.attestSvc.GenerateChallenge(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to generate challenge",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := model.ChallengeResponse{
		Challenge: challenge,
		ExpiresIn: 120, // 2 minutes
	}
	jsonResponse(w, resp, http.StatusOK)
}

// POST /devices/verify
// Vérifie une signature sur un challenge (device-bound session proof)
func (h *AttestationHandler) Verify(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req model.VerifyChallengeRequest
	// parse JSON body if present, otherwise fallback to headers (for GET requests or clients that can't send JSON)
	if r.Method == http.MethodPost && r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	w.Header().Add("X-User-ID", userID)

	if req.Nonce == "" {
		req.Nonce = r.Context().Value(ctxkeys.DeviceNonce).(string)
	}
	if req.Timestamp == "" {
		req.Timestamp = r.Context().Value(ctxkeys.DeviceTimestamp).(string)
	}
	if req.Signature == "" {
		req.Signature = r.Context().Value(ctxkeys.DeviceSignature).(string)
	}
	if req.DeviceID == "" {
		req.DeviceID = r.Context().Value(ctxkeys.DeviceID).(string)
	}

	if req.DeviceID == "" {
		jsonError(w, "device_id is required", http.StatusBadRequest)
		return
	}

	var resp *model.VerifyResponse = &model.VerifyResponse{
		DeviceID: req.DeviceID,
		UserID:   userID,
		Verified: false, // par défaut à false, passe à true si vérification réussie
		Message:  "",
		Code:     401,
	}

	if req.Nonce == "" || req.Timestamp == "" || req.Signature == "" {
		sr, err := h.deviceSvc.Status(r.Context(), req.DeviceID)
		if err != nil {
			resp.Code = http.StatusUnauthorized

			if errors.Is(err, repository.ErrNotFound) {
				resp.Message = "device not found"
			} else {
				resp.Message = "signature verification failed: " + err.Error()
			}

			h.logger.Error("failed to get device status",
				zap.String("device_id", req.DeviceID),
				zap.Error(err))
		}
		if sr.Signed {
			resp.Code = http.StatusBadRequest
			resp.Message = "nonce, timestamp and signature are required for this device"
		}
		if sr.Status == model.StatusActive {
			resp.Verified = true
			resp.Message = "device is active but has no registered key, skipping signature verification"
			resp.Code = http.StatusOK
		} else {
			resp.Message = "device is not active"
			resp.Code = http.StatusUnauthorized
		}
	} else {
		vrsr, err := h.attestSvc.VerifyRequestSignature(
			r.Context(),
			req.DeviceID,
			req.Nonce,
			req.Timestamp,
			req.Signature,
			userID,
		)

		if err != nil {
			h.logger.Warn("signature verification failed",
				zap.String("device_id", req.DeviceID),
				zap.Error(err))
			resp.Message = "signature verification failed: " + err.Error()
			resp.Code = http.StatusUnauthorized
		}
		if vrsr.Verified {
			resp.Message = "signature verified, device is active"
			resp.Code = http.StatusOK
			resp.Verified = true
		} else {
			resp.Message = vrsr.Message
			resp.Code = http.StatusUnauthorized
		}
	}

	// Recalculate trust score after successful verification
	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), req.DeviceID)
	if err != nil {
		resp.Message += "; failed to compute trust score: " + err.Error()
		resp.Code = http.StatusInternalServerError
		h.logger.Warn("trust score computation failed after verify",
			zap.String("device_id", req.DeviceID),
			zap.Error(err))
	}

	if trustResp != nil {
		resp.TrustScore = &trustResp.TrustScore
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-User-ID", userID)
	w.Header().Set("X-Device-ID", req.DeviceID)
	w.Header().Set("X-Verified", strconv.FormatBool(resp.Verified))
	if resp.TrustScore != nil {
		w.Header().Set("X-Trust-Score", strconv.Itoa(*resp.TrustScore))
	}

	w.WriteHeader(resp.Code)
	json.NewEncoder(w).Encode(map[string]any{
		"message": resp.Message,
		"verified": resp.Verified,
		"trust_score": *resp.TrustScore,
		"device_id": resp.DeviceID,
		"user_id": resp.UserID,
	})
}

// POST /devices/{device_id}/reattest
// Re-attestation : le device prouve qu'il possède toujours la clé
// et optionnellement fournit une nouvelle preuve matérielle (TPM quote)
func (h *AttestationHandler) Reattest(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req model.ReattestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.DeviceID = deviceID

	// 1. Verify the signature (proves possession of the private key)
	if _, err := h.attestSvc.VerifyRequestSignature(
		r.Context(),
		req.DeviceID,
		req.Nonce,
		req.Timestamp,
		req.Signature,
		userID,
	); err != nil {
		h.logger.Warn("reattest signature failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "signature verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// 2. Record successful re-attestation
	if err := h.attestSvc.RecordReattestation(r.Context(), deviceID); err != nil {
		h.logger.Error("failed to record reattestation",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 3. Recompute trust score
	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID)
	if err != nil {
		h.logger.Warn("trust score computation failed after reattest",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	resp := map[string]interface{}{
		"reattested": true,
		"device_id":  deviceID,
	}
	if trustResp != nil {
		resp["trust_score"] = trustResp.TrustScore
	}

	h.logger.Info("device re-attested",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID))

	jsonResponse(w, resp, http.StatusOK)
}

// GET /devices/{device_id}/trust
// Retourne le trust score actuel du device
func (h *AttestationHandler) TrustScore(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		h.logger.Error("trust score computation failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, trustResp, http.StatusOK)
}
