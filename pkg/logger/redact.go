package logger

import (
	"net/url"
	"regexp"
	"strings"
)

const redactedValue = "[REDACTED]"

var (
	bearerTokenPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+\/=-]+\b`)
	jsonSecretPattern  = regexp.MustCompile(`(?i)("?(?:access_token|refresh_token|id_token|api[_-]?key|apikey|password|passwd|secret|token|session(?:_id)?|client_secret)"?\s*[:=]\s*"?)([^"&,\\\s]+)("?)`)
)

func RedactTrafficRecord(record *TrafficRecord, disabled bool) {
	if disabled || record == nil {
		return
	}

	record.Request.Headers = redactHeaders(record.Request.Headers)
	record.Response.Headers = redactHeaders(record.Response.Headers)
	record.Request.URL = redactURLString(record.Request.URL)
	record.Request.Body = redactBody(record.Request.Body, firstHeaderValue(record.Request.Headers, "Content-Type"))
	record.Response.Body = redactBody(record.Response.Body, record.Response.ContentType)
}

func redactHeaders(headers map[string][]string) map[string][]string {
	for name, values := range headers {
		if !isSensitiveFieldName(name) {
			continue
		}
		redacted := make([]string, len(values))
		for i := range redacted {
			redacted[i] = redactedValue
		}
		headers[name] = redacted
	}
	return headers
}

func redactURLString(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.RawQuery == "" {
		return raw
	}

	query := parsed.Query()
	for name := range query {
		if isSensitiveFieldName(name) {
			values := query[name]
			for i := range values {
				values[i] = redactedValue
			}
			query[name] = values
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func redactBody(body string, contentType string) string {
	if body == "" {
		return body
	}

	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(body); err == nil {
			for name := range values {
				if isSensitiveFieldName(name) {
					entries := values[name]
					for i := range entries {
						entries[i] = redactedValue
					}
					values[name] = entries
				}
			}
			body = values.Encode()
		}
	}

	body = bearerTokenPattern.ReplaceAllString(body, "Bearer "+redactedValue)
	body = jsonSecretPattern.ReplaceAllString(body, `${1}`+redactedValue+`${3}`)
	return body
}

func isSensitiveFieldName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie",
		"x-api-key", "x-auth-token", "x-csrf-token", "x-amz-security-token":
		return true
	}

	if strings.Contains(name, "token") || strings.Contains(name, "secret") ||
		strings.Contains(name, "password") || strings.Contains(name, "passwd") ||
		strings.Contains(name, "api-key") || strings.Contains(name, "apikey") ||
		strings.Contains(name, "session") {
		return true
	}

	return false
}
