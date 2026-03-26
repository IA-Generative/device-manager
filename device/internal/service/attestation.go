package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/attestation"
	"github.com/ia-generative/device-service/internal/model"
)

const (
	challengeTTL    = 2 * time.Minute
	signatureWindow = 30 * time.Second
	nonceTTL        = 60 * time.Second
)

type AttestationService struct {
	deviceSvc *DeviceService
	logger    *zap.Logger
}

func NewAttestationService(
	deviceSvc *DeviceService,
	logger *zap.Logger,
) *AttestationService {
	return &AttestationService{
		deviceSvc: deviceSvc,
		logger:    logger,
	}
}

// GetDevice expose l'accès au device pour le handler (vérification de politique)
func (s *AttestationService) GetDevice(ctx context.Context, deviceID string) (*model.Device, error) {
	return s.deviceSvc.repo.GetByDeviceID(ctx, deviceID)
}

// GenerateChallenge génère un challenge à signer par le device
func (s *AttestationService) GenerateChallenge(ctx context.Context, deviceID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := hex.EncodeToString(b)

	if err := s.deviceSvc.repo.SetChallenge(ctx, deviceID, challenge, time.Now().Add(challengeTTL)); err != nil {
		return "", err
	}

	return challenge, nil
}

// GenerateRegisterChallenge génère un challenge pré-enregistrement.
// Stocké dans Redis (pas en DB car le device n'existe pas encore).
// Le challenge est lié au userID extrait du JWT.
func (s *AttestationService) GenerateRegisterChallenge(ctx context.Context, userID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := hex.EncodeToString(b)

	if err := s.deviceSvc.cache.SetRegisterChallenge(ctx, userID, challenge, challengeTTL); err != nil {
		return "", err
	}

	s.logger.Debug("register challenge generated",
		zap.String("user_id", userID),
		zap.Duration("ttl", challengeTTL))

	return challenge, nil
}

// VerifyRegisterSignature vérifie la signature du challenge pré-enregistrement.
// Le client signe le challenge brut avec sa clé ECDSA et envoie tout
// au moment du POST /devices/register.
func (s *AttestationService) VerifyRegisterSignature(
	ctx context.Context,
	userID, publicKeyPEM, challenge, signatureB64 string,
) error {
	// 1. Le challenge correspond-il à celui stocké dans Redis ?
	stored, err := s.deviceSvc.cache.GetRegisterChallenge(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get register challenge: %w", err)
	}
	if stored == "" || stored != challenge {
		return errors.New("invalid or expired register challenge")
	}

	// 2. Vérifier la signature ECDSA sur le challenge
	provider := &attestation.SoftwareProvider{}
	if err := provider.VerifySignature(ctx, publicKeyPEM, challenge, signatureB64); err != nil {
		s.logger.Warn("register challenge signature verification failed",
			zap.String("user_id", userID),
			zap.Error(err))
		return fmt.Errorf("challenge signature invalid: %w", err)
	}

	return nil
}

// VerifyRequestSignature vérifie la signature sur chaque appel API
func (s *AttestationService) VerifyRequestSignature(
	ctx context.Context,
	deviceID, nonce, timestamp, signatureB64, userID string,
) (*model.VerifySignatureResponse, error) {
	// 0. Récupérer le device et sa clé publique
	device, err := s.deviceSvc.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if device.UserID != userID {
		return nil, errors.New("device does not belong to this user")
	}
	// 1. Anti-replay : nonce déjà vu ?
	seen, _ := s.deviceSvc.cache.GetNonce(ctx, nonce)
	if seen {
		return nil, attestation.ErrReplayAttack
	}

	// 2. Fenêtre de timestamp
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(ts) > signatureWindow {
		return nil, attestation.ErrTimestampOutOfWindow
	}

	if device.PublicKey == nil {
		return nil, errors.New("device has no registered key")
	}

	// 3. Vérifier la signature (toujours software, car hardware_level supprimé)
	payload := nonce + "|" + timestamp
	provider := &attestation.SoftwareProvider{}
	if err := provider.VerifySignature(ctx, *device.PublicKey, payload, signatureB64); err != nil {
		s.logger.Warn("request signature verification failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		return nil, err
	}

	// 4. Consommer le nonce
	_ = s.deviceSvc.cache.SetNonce(ctx, nonce, nonceTTL)

	// 5. Mettre à jour last_seen
	_ = s.deviceSvc.repo.UpdateLastSeen(ctx, deviceID)
	resp := &model.VerifySignatureResponse{
		DeviceID: device.ID,
		UserID:   device.UserID,
		Verified: false,
		Message: "",
	}
	
	if device.Status == model.StatusActive {
		resp.Verified = true
	} else {
		resp.Message = "device is not active"
	}
	return resp, nil
}

// ─── Hardware Level Policy ──────────────────────────────────────────────────

// UpgradeKey permet à un device de changer sa clé publique (preuve de possession de l'ancienne clé requise).
func (s *AttestationService) UpgradeKey(
	ctx context.Context,
	deviceID, userID string,
	newPublicKey, newKeyAlgorithm, newProviderName string,
	oldNonce, oldTimestamp, oldSignature string,
) error {
	// 1. Récupérer le device
	device, err := s.deviceSvc.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device.UserID != userID {
		return errors.New("device does not belong to this user")
	}
	if device.Status != "active" {
		return errors.New("device is not active")
	}

	// 2. Vérifier la preuve de possession de l'ancienne clé
	if device.PublicKey != nil && *device.PublicKey != "" {
		if _, err := s.VerifyRequestSignature(ctx, deviceID, oldNonce, oldTimestamp, oldSignature, userID); err != nil {
			return fmt.Errorf("old key proof of possession failed: %w", err)
		}
	}

	// 3. Mettre à jour la clé
	if err := s.deviceSvc.repo.UpgradeKey(ctx, deviceID, newPublicKey, newKeyAlgorithm, newProviderName); err != nil {
		return err
	}

	_ = s.deviceSvc.cache.InvalidateDevice(ctx, deviceID)

	s.logger.Info("device key upgraded",
		zap.String("device_id", deviceID))

	return nil
}

// RecordReattestation enregistre une re-attestation réussie
func (s *AttestationService) RecordReattestation(ctx context.Context, deviceID string) error {
	if err := s.deviceSvc.repo.RecordReattestation(ctx, deviceID); err != nil {
		s.logger.Error("failed to record reattestation",
			zap.String("device_id", deviceID),
			zap.Error(err))
		return err
	}

	// Invalider le cache
	_ = s.deviceSvc.cache.InvalidateDevice(ctx, deviceID)

	s.logger.Info("reattestation recorded",
		zap.String("device_id", deviceID))
	return nil
}
