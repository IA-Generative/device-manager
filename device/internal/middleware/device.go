package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/ia-generative/device-service/internal/ctxkeys"
	"go.uber.org/zap"
)

func DeviceAuthExtract(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extraire les headers d'authentification du device
			// first copy headers, then lowers them for case-insensitive matching
			headers := make(map[string]string)
			for k, v := range r.Header {
				headers[strings.ToLower(k)] = v[0]
			}
			deviceID := headers["x-device-id"]
			nonce := headers["x-device-nonce"]
			timestamp := headers["x-device-timestamp"]
			signature := headers["x-device-signature"]

			// Inject in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxkeys.DeviceID, deviceID)
			ctx = context.WithValue(ctx, ctxkeys.DeviceNonce, nonce)
			ctx = context.WithValue(ctx, ctxkeys.DeviceTimestamp, timestamp)
			ctx = context.WithValue(ctx, ctxkeys.DeviceSignature, signature)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
