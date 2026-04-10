package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
)

type bodyCapture struct {
	file      *os.File
	path      string
	size      int64
	captured  []byte
	truncated bool
}

type limitedCaptureBuffer struct {
	limit int64
	buf   bytes.Buffer
	total int64
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

func spoolBody(body io.ReadCloser, captureLimit int64) (*bodyCapture, error) {
	if body == nil || body == http.NoBody {
		return &bodyCapture{}, nil
	}
	defer body.Close()

	tmpFile, err := os.CreateTemp("", "httpseal-body-*")
	if err != nil {
		return nil, fmt.Errorf("create body spool file: %w", err)
	}

	capture := newLimitedCaptureBuffer(captureLimit)
	size, copyErr := io.Copy(tmpFile, io.TeeReader(body, capture))
	if copyErr != nil {
		name := tmpFile.Name()
		tmpFile.Close()
		_ = os.Remove(name)
		return nil, fmt.Errorf("copy body into spool file: %w", copyErr)
	}

	if size == 0 {
		name := tmpFile.Name()
		tmpFile.Close()
		_ = os.Remove(name)
		return &bodyCapture{}, nil
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		name := tmpFile.Name()
		tmpFile.Close()
		_ = os.Remove(name)
		return nil, fmt.Errorf("rewind body spool file: %w", err)
	}

	return &bodyCapture{
		file:      tmpFile,
		path:      tmpFile.Name(),
		size:      size,
		captured:  capture.Bytes(),
		truncated: capture.Truncated(),
	}, nil
}

func (b *bodyCapture) Reader() io.ReadCloser {
	if b == nil || b.file == nil {
		return nil
	}
	return b.file
}

func (b *bodyCapture) Cleanup() error {
	if b == nil {
		return nil
	}

	var lastErr error
	if b.file != nil {
		if err := b.file.Close(); err != nil {
			lastErr = err
		}
		b.file = nil
	}
	if b.path != "" {
		if err := os.Remove(b.path); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
		b.path = ""
	}

	return lastErr
}
