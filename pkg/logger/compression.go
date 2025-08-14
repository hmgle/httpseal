package logger

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// CompressionType represents the type of compression used
type CompressionType int

const (
	CompressionNone CompressionType = iota
	CompressionGzip
	CompressionDeflate
	CompressionBrotli
	CompressionUnknown
)

// String returns the string representation of compression type
func (c CompressionType) String() string {
	switch c {
	case CompressionNone:
		return "none"
	case CompressionGzip:
		return "gzip"
	case CompressionDeflate:
		return "deflate"
	case CompressionBrotli:
		return "br"
	case CompressionUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// DetectCompressionType detects compression type from Content-Encoding header
func DetectCompressionType(contentEncoding string) CompressionType {
	if contentEncoding == "" {
		return CompressionNone
	}

	// Normalize to lowercase and handle multiple encodings
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))

	// Handle multiple encodings (e.g., "gzip, deflate")
	encodings := strings.Split(encoding, ",")
	for _, enc := range encodings {
		enc = strings.TrimSpace(enc)
		switch enc {
		case "gzip", "x-gzip":
			return CompressionGzip
		case "deflate":
			return CompressionDeflate
		case "br", "brotli":
			return CompressionBrotli
		}
	}

	return CompressionUnknown
}

// DecompressResponse decompresses response body based on Content-Encoding
func DecompressResponse(body []byte, contentEncoding string) ([]byte, error) {
	compressionType := DetectCompressionType(contentEncoding)

	switch compressionType {
	case CompressionNone:
		return body, nil
	case CompressionGzip:
		return decompressGzip(body)
	case CompressionDeflate:
		return decompressDeflate(body)
	case CompressionBrotli:
		return decompressBrotli(body)
	case CompressionUnknown:
		return nil, fmt.Errorf("unknown compression type: %s", contentEncoding)
	default:
		return body, nil
	}
}

// decompressGzip decompresses gzip-compressed data
func decompressGzip(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	result, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip data: %w", err)
	}

	return result, nil
}

// decompressDeflate decompresses deflate-compressed data
func decompressDeflate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()

	result, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress deflate data: %w", err)
	}

	return result, nil
}

// decompressBrotli decompresses brotli-compressed data
// Note: This is a placeholder. For full brotli support, we would need
// to import a brotli library like "github.com/andybalholm/brotli"
func decompressBrotli(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	// For now, return an error indicating brotli is not supported
	// This can be implemented later with proper brotli library
	return nil, fmt.Errorf("brotli decompression not yet implemented - requires external library")
}

// IsTextLikeContent checks if the decompressed content appears to be text
func IsTextLikeContent(data []byte, contentType string) bool {
	if len(data) == 0 {
		return true
	}

	// Check content type first
	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "text/") ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/xml") ||
		strings.Contains(contentType, "application/javascript") ||
		strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return true
	}

	// Simple heuristic: check if most bytes are printable
	printableCount := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printableCount++
		}
	}

	// If more than 80% of bytes are printable, consider it text-like
	return float64(printableCount)/float64(len(data)) > 0.8
}