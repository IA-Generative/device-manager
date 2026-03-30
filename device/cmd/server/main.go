package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/cache"
	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/db"
	"github.com/ia-generative/device-service/internal/handler"
	authmw "github.com/ia-generative/device-service/internal/middleware"
	"github.com/ia-generative/device-service/internal/repository"
	"github.com/ia-generative/device-service/internal/service"
)

func main() {
	cfg := config.Load()

	// Logger
	logger, err := buildLogger(cfg.Env)
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// Postgres
	pg, err := db.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer pg.Close()

	// Redis
	rdb, err := cache.NewRedis(cfg.RedisURL)
	if err != nil {
		logger.Fatal("failed to connect to redis", zap.Error(err))
	}
	defer rdb.Close()

	// Layers
	repo := repository.NewDeviceRepository(pg)
	emailSvc := service.NewEmailService(
		cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPFrom,
		service.SMTPAuthType(cfg.SMTPAuthType),
		cfg.SMTPUsername, cfg.SMTPPassword,
		service.SMTPEncryption(cfg.SMTPEncryption),
	)
	deviceSvc := service.NewDeviceServiceWithConfig(repo, rdb, emailSvc, logger, cfg)
	attestSvc := service.NewAttestationService(deviceSvc, logger)
	riskSvc := service.NewRiskService(deviceSvc, cfg, logger)

	probeHandler := handler.NewProbeHandler(pg, rdb, logger)
	discoverHandler := handler.NewDiscoverHandler(cfg, deviceSvc)
	deviceHandler := handler.NewDeviceHandler(deviceSvc, attestSvc, riskSvc, cfg, logger)
	attestHandler := handler.NewAttestationHandler(attestSvc, deviceSvc, riskSvc, logger)

	// Router
	r := chi.NewRouter()
	r.Use(authmw.CORS(authmw.CORSOptions{
		AllowedOrigins:   cfg.CORSAllowedOrigins,
		AllowedMethods:   cfg.CORSAllowedMethods,
		AllowedHeaders:   cfg.CORSAllowedHeaders,
		ExposedHeaders:   cfg.CORSExposedHeaders,
		AllowCredentials: cfg.CORSAllowCredentials,
		MaxAgeSeconds:    cfg.CORSMaxAgeSeconds,
	}))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Kubernetes probes (pas d'auth)
	r.Get("/healthz", probeHandler.Liveness)
	r.Get("/readyz", probeHandler.Readiness)
	r.Get("/api/discover", discoverHandler.Discover)	

	// Device endpoints (JWT requis)
	r.Group(func(r chi.Router) {
		r.Use(authmw.JWTAuth(cfg.JWKSEndpoint, logger))
		r.Use(authmw.DeviceAuthExtract(logger))

		r.Get("/api/devices/{device_id}/status", deviceHandler.Status)
		r.Post("/api/devices/register", deviceHandler.Register)
		r.Post("/api/devices/register/challenge", attestHandler.RegisterChallenge)
		r.Get("/api/devices/{device_id}", deviceHandler.Get)
		r.Get("/api/me/devices", deviceHandler.ListMine)
		r.Get("/api/me/devices/pending", deviceHandler.ListPending)
		r.Get("/api/me/events", deviceHandler.Events)
		r.Get("/api/users/{user_id}/devices", deviceHandler.ListByUser)
		r.Post("/api/devices/{device_id}/revoke", deviceHandler.Revoke)
		r.Post("/api/devices/{device_id}/approve", deviceHandler.Approve)
		r.Post("/api/devices/{device_id}/reject", deviceHandler.Reject)
		r.Post("/api/me/devices/{device_id}/verify-email", deviceHandler.VerifyEmail)
		r.Post("/api/me/devices/{device_id}/renew-code", deviceHandler.RenewCode)

		// Attestation endpoints
		r.Post("/api/devices/{device_id}/challenge", attestHandler.Challenge)
		r.Post("/api/devices/verify", attestHandler.Verify)
		r.Get("/api/devices/verify", attestHandler.Verify)
		r.Post("/api/devices/{device_id}/reattest", attestHandler.Reattest)
		r.Get("/api/devices/{device_id}/trust", attestHandler.TrustScore)
	})

	// If the frontend was embedded into the pod/image, prepare a cached
	// copy at startup. This copies the static files into a cache directory,
	// generates /env.js and injects the script tag into index.html so the SPA
	// can read runtime variables without per-request modifications.
	if cfg.UiEnabled {
		frontendPath := "/static"
		idx, err := prepareIdxHtml(frontendPath, logger)
		if err == nil {
			r.Handle("/*", spaHandler(frontendPath, idx))
		}
	}

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("device service starting", zap.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	<-quit
	logger.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("forced shutdown", zap.Error(err))
	}

	logger.Info("server stopped")
}

func buildLogger(env string) (*zap.Logger, error) {
	if env == "production" {
		return zap.NewProduction()
	}
	return zap.NewDevelopment()
}

// prepareIdxHtml copies the frontend files from srcDir into dstDir, writes
// an /env.js file with runtime variables, and injects a script tag into
// index.html so the SPA loads the runtime config. It creates dstDir if needed.
func prepareIdxHtml(srcDir string, logger *zap.Logger) (string, error) {
	idxPath := filepath.Join(srcDir, "index.html")

	// Generate env.js in dstDir
	apiURL := os.Getenv("VITE_API_URL")
	if apiURL == "" {
		apiURL = "/api"
	}
	exampleURL := os.Getenv("VITE_EXAMPLE_API_URL")
	envJS := "window.__ENV = {"
	envJS += "  VITE_API_URL: '" + apiURL + "',"
	envJS += "  VITE_EXAMPLE_API_URL: '" + exampleURL + "'"
	envJS += "};"

	// Inject script tag into index.html in dstDir
	data, err := os.ReadFile(idxPath)
	if err != nil {
		logger.Fatal("index.html not found in frontend dist", zap.String("path", idxPath))
		return "", errors.New("Unable to find index.html")
	}
	content := string(data)
	script := "<script>"+envJS+"</script>"
	lower := strings.ToLower(content)
	pos := strings.Index(lower, "</head>")
	if pos != -1 {
		// Insert before closing head
		content = content[:pos] + script + content[pos:]
	} else {
		// Prepend if no head tag
		content = script + content
	}
	return content, nil
}

// spaHandler returns an http.Handler that serves files from dir and falls back
// to index.html for not-found paths (SPA behavior).
func spaHandler(dir string, idxHtml string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prefer to serve files that exist; otherwise serve index.html
		p := filepath.Join(dir, path.Clean(r.URL.Path))
		// If path is directory or root, serve index
		fi, err := os.Stat(p)
		if err == nil && !fi.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		// Serve index.html modified
		w.Write([]byte(idxHtml))
	})
}
