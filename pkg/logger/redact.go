package logger

import (
	"net/url"
	"regexp"
	"strings"
)

const redactedValue = "[REDACTED]"

var (
	bearerTokenPattern  = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+\/=-]+\b`)
	jsonSecretPattern   = regexp.MustCompile(`(?i)("?(?:access_token|refresh_token|id_token|api[_-]?key|apikey|password|passwd|secret|token|session(?:_id)?|client_secret)"?\s*[:=]\s*"?)([^"&,\\\s]+)("?)`)
	sensitiveFieldNames = map[string]struct{}{
		"authorization":        {},
		"proxy-authorization":  {},
		"cookie":               {},
		"set-cookie":           {},
		"x-api-key":            {},
		"x-auth-token":         {},
		"x-csrf-token":         {},
		"x-amz-security-token": {},
		"access-token":         {},
		"refresh-token":        {},
		"id-token":             {},
		"api-key":              {},
		"apikey":               {},
		"password":             {},
		"passwd":               {},
		"secret":               {},
		"token":                {},
		"session":              {},
		"session-id":           {},
		"sessionid":            {},
		"client-secret":        {},
	}
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

	parsed.RawQuery = redactDelimitedValues(parsed.RawQuery, "&")
	return parsed.String()
}

func redactBody(body string, contentType string) string {
	if body == "" {
		return body
	}

	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		return redactDelimitedValues(body, "&")
	}

	body = bearerTokenPattern.ReplaceAllString(body, "Bearer "+redactedValue)
	body = jsonSecretPattern.ReplaceAllString(body, `${1}`+redactedValue+`${3}`)
	return body
}

func isSensitiveFieldName(name string) bool {
	name = normalizeFieldName(name)
	if _, ok := sensitiveFieldNames[name]; ok {
		return true
	}

	for _, suffix := range []string{"-token", "-secret", "-password", "-passwd", "-api-key", "-apikey", "-session-id", "-sessionid"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
}

func normalizeFieldName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var builder strings.Builder
	builder.Grow(len(name))
	lastDash := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func redactDelimitedValues(raw string, sep string) string {
	if raw == "" {
		return raw
	}

	parts := strings.Split(raw, sep)
	changed := false
	for i, part := range parts {
		keyPart, valuePart, hasValue := strings.Cut(part, "=")
		keyName, err := url.QueryUnescape(keyPart)
		if err != nil || !isSensitiveFieldName(keyName) || !hasValue {
			continue
		}
		parts[i] = keyPart + "=" + url.QueryEscape(redactedValue)
		if valuePart != url.QueryEscape(redactedValue) {
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return strings.Join(parts, sep)
}
