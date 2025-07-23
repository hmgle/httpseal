package mount

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/httpseal/httpseal/pkg/logger"
)

// OverlayManager handles OverlayFS mounting operations
type OverlayManager struct {
	logger    logger.Logger
	workDir   string
	upperDir  string
	mergedDir string
}

// NewOverlayManager creates a new overlay manager
func NewOverlayManager(baseDir string, log logger.Logger) (*OverlayManager, error) {
	workDir := filepath.Join(baseDir, "work")
	upperDir := filepath.Join(baseDir, "upper")
	mergedDir := filepath.Join(baseDir, "merged")

	// Create necessary directories
	for _, dir := range []string{workDir, upperDir, mergedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &OverlayManager{
		logger:    log,
		workDir:   workDir,
		upperDir:  upperDir,
		mergedDir: mergedDir,
	}, nil
}

// MountOverlay creates an overlay mount
func (om *OverlayManager) MountOverlay(lowerDir string) error {
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		lowerDir, om.upperDir, om.workDir)

	err := syscall.Mount("overlay", om.mergedDir, "overlay", 0, opts)
	if err != nil {
		return fmt.Errorf("failed to mount overlay: %w", err)
	}

	om.logger.Debug("Mounted overlay: %s -> %s", lowerDir, om.mergedDir)
	return nil
}

// Unmount unmounts the overlay
func (om *OverlayManager) Unmount() error {
	if err := syscall.Unmount(om.mergedDir, 0); err != nil {
		return fmt.Errorf("failed to unmount overlay: %w", err)
	}
	om.logger.Debug("Unmounted overlay: %s", om.mergedDir)
	return nil
}

// GetMergedDir returns the merged directory path
func (om *OverlayManager) GetMergedDir() string {
	return om.mergedDir
}

// GetUpperDir returns the upper directory path
func (om *OverlayManager) GetUpperDir() string {
	return om.upperDir
}

// Cleanup removes overlay directories
func (om *OverlayManager) Cleanup() error {
	baseDir := filepath.Dir(om.workDir)
	return os.RemoveAll(baseDir)
}

// PrepareFiles prepares files for overlay mounting
func (om *OverlayManager) PrepareFiles(files map[string]string) error {
	for destPath, content := range files {
		// Create destination directory in upper layer
		upperPath := filepath.Join(om.upperDir, destPath)
		if err := os.MkdirAll(filepath.Dir(upperPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", upperPath, err)
		}

		// Write file content
		if err := os.WriteFile(upperPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %w", upperPath, err)
		}

		om.logger.Debug("Prepared file for overlay: %s", upperPath)
	}
	return nil
}