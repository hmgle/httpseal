package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	bodySpoolFilePrefix   = "body-"
	bodySpoolMemoryLimit  = 64 * 1024
	bodySpoolCleanupAfter = 24 * time.Hour
)

var (
	bodySpoolDir            = filepath.Join(os.TempDir(), "httpseal-body")
	bodySpoolPrepareMu      sync.Mutex
	bodySpoolCleanupDone    bool
	bodySpoolCleanupNowFunc = time.Now
)

type bodyCapture struct {
	path      string
	memory    []byte
	size      int64
	captured  []byte
	truncated bool
}

type limitedCaptureBuffer struct {
	limit int64
	buf   bytes.Buffer
	total int64
}

type spillBuffer struct {
	threshold int64
	buf       bytes.Buffer
	path      string
	file      *os.File
}

func newLimitedCaptureBuffer(limit int64) *limitedCaptureBuffer {
	return &limitedCaptureBuffer{limit: limit}
}

func (b *limitedCaptureBuffer) Write(p []byte) (int, error) {
	b.total += int64(len(p))
	if b.limit == 0 {
		_, _ = b.buf.Write(p)
		return len(p), nil
	}

	remaining := b.limit - int64(b.buf.Len())
	if remaining > 0 {
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}

	return len(p), nil
}

func (b *limitedCaptureBuffer) Bytes() []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *limitedCaptureBuffer) Truncated() bool {
	if b == nil || b.limit == 0 {
		return false
	}
	return b.total > int64(b.buf.Len())
}

func (b *spillBuffer) Write(p []byte) (int, error) {
	if b.file == nil && int64(b.buf.Len()+len(p)) <= b.threshold {
		_, _ = b.buf.Write(p)
		return len(p), nil
	}

	if b.file == nil {
		if err := prepareBodySpoolDir(); err != nil {
			return 0, err
		}
		file, err := os.CreateTemp(bodySpoolDir, bodySpoolFilePrefix+"*")
		if err != nil {
			return 0, fmt.Errorf("create body spool file: %w", err)
		}
		if _, err := file.Write(b.buf.Bytes()); err != nil {
			name := file.Name()
			file.Close()
			_ = os.Remove(name)
			return 0, fmt.Errorf("seed body spool file: %w", err)
		}
		b.path = file.Name()
		b.file = file
		b.buf.Reset()
	}

	if _, err := b.file.Write(p); err != nil {
		return 0, fmt.Errorf("write body spool file: %w", err)
	}
	return len(p), nil
}

func (b *spillBuffer) finish() ([]byte, string, error) {
	if b.file == nil {
		return append([]byte(nil), b.buf.Bytes()...), "", nil
	}
	if err := b.file.Close(); err != nil {
		name := b.path
		_ = os.Remove(name)
		return nil, "", fmt.Errorf("close body spool file: %w", err)
	}
	return nil, b.path, nil
}

func spoolBody(body io.ReadCloser, captureLimit int64) (*bodyCapture, error) {
	if body == nil || body == http.NoBody {
		return &bodyCapture{}, nil
	}
	defer body.Close()

	capture := newLimitedCaptureBuffer(captureLimit)
	store := &spillBuffer{threshold: bodySpoolMemoryLimit}
	size, copyErr := io.Copy(store, io.TeeReader(body, capture))
	if copyErr != nil {
		if store.path != "" {
			_ = os.Remove(store.path)
		}
		return nil, fmt.Errorf("copy body into capture store: %w", copyErr)
	}

	if size == 0 {
		if store.path != "" {
			_ = os.Remove(store.path)
		}
		return &bodyCapture{}, nil
	}

	memory, path, err := store.finish()
	if err != nil {
		return nil, err
	}

	return &bodyCapture{
		path:      path,
		memory:    memory,
		size:      size,
		captured:  capture.Bytes(),
		truncated: capture.Truncated(),
	}, nil
}

func (b *bodyCapture) Reader() io.ReadCloser {
	if b == nil || b.size == 0 {
		return nil
	}
	if b.path != "" {
		file, err := os.Open(b.path)
		if err != nil {
			return io.NopCloser(strings.NewReader(""))
		}
		return file
	}
	return io.NopCloser(bytes.NewReader(b.memory))
}

func (b *bodyCapture) ReadAll() ([]byte, error) {
	if b == nil || b.size == 0 {
		return nil, nil
	}
	if b.path != "" {
		data, err := os.ReadFile(b.path)
		if err != nil {
			return nil, fmt.Errorf("read spooled body: %w", err)
		}
		return data, nil
	}
	return append([]byte(nil), b.memory...), nil
}

func (b *bodyCapture) Cleanup() error {
	if b == nil {
		return nil
	}
	if b.path == "" {
		return nil
	}

	path := b.path
	b.path = ""
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func prepareBodySpoolDir() error {
	bodySpoolPrepareMu.Lock()
	defer bodySpoolPrepareMu.Unlock()

	if err := os.MkdirAll(bodySpoolDir, 0o700); err != nil {
		return fmt.Errorf("create body spool directory %s: %w", bodySpoolDir, err)
	}
	if bodySpoolCleanupDone {
		return nil
	}
	if err := cleanupStaleBodySpoolFiles(bodySpoolDir, bodySpoolCleanupNowFunc()); err != nil {
		return err
	}
	bodySpoolCleanupDone = true
	return nil
}

func cleanupStaleBodySpoolFiles(dir string, now time.Time) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read body spool directory %s: %w", dir, err)
	}

	cutoff := now.Add(-bodySpoolCleanupAfter)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), bodySpoolFilePrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat body spool file %s: %w", entry.Name(), err)
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale body spool file %s: %w", entry.Name(), err)
		}
	}
	return nil
}
