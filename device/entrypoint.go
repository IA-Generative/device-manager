package main

import (
	"log"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	migratePath := "/usr/local/bin/migrate"
	migrateArgs := []string{"-path", "/migrations", "-database", os.Getenv("DATABASE_URL"), "up"}

	cmd := exec.Command(migratePath, migrateArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		log.Fatalf("migrate failed: %v", err)
	}

	// Replace current process with /device-service
	execErr := syscall.Exec("/device-service", []string{"/device-service"}, os.Environ())
	log.Fatalf("exec device-service failed: %v", execErr)
}
