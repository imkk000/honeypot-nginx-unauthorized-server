package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

func ipExtractor(req *http.Request) string {
	if ip := req.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	return echo.ExtractIPDirect()(req)
}

func errorHandler(c *echo.Context, err error) {
	resp, _ := echo.UnwrapResponse(c.Response())
	if resp != nil && resp.Committed {
		return
	}

	if errors.Is(err, echo.ErrUnauthorized) {
		c.Response().Header().Del(echo.HeaderWWWAuthenticate)
		c.Blob(http.StatusUnauthorized, echo.MIMETextHTML, page401)
		return
	}

	c.NoContent(http.StatusInternalServerError)
}

func middlewareRequestID(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		id := uuid.Must(uuid.NewV7()).String()
		c.Request().Header.Set(echo.HeaderXRequestID, id)
		return next(c)
	}
}

func middlewareNotFound(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		path := c.Request().URL.Path
		for _, prefix := range skip {
			if strings.HasPrefix(path, prefix) {
				return c.NoContent(http.StatusNotFound)
			}
		}
		return next(c)
	}
}

func middlewareRequestLogger() echo.MiddlewareFunc {
	logHeaderGroup := func(headers http.Header) slog.Attr {
		result := make([]slog.Attr, 0, len(headers))
		for key := range headers {
			overrideHeader, ok := keepHeaders[key]
			if !ok {
				continue
			}
			value, ok := validateHeader(headers.Get(key))
			if ok && overrideHeader != nil {
				value = overrideHeader(value)
			}
			result = append(result, slog.String(key, value))
		}
		if len(result) == 0 {
			return slog.Attr{}
		}
		return slog.GroupAttrs("headers", result...)
	}
	logAuthGroup := func(c *echo.Context) slog.Attr {
		authCtx := c.Get("authctx")
		if authCtx == nil {
			return slog.Attr{}
		}
		v, ok := authCtx.(AuthContext)
		if !ok || !v.IsAttempted() {
			return slog.Attr{}
		}
		return slog.GroupAttrs("auth",
			slog.String("user", v.Username),
			slog.String("pass", v.Password),
		)
	}

	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogLatency:   true,
		LogRemoteIP:  true,
		LogHost:      true,
		LogMethod:    true,
		LogURI:       true,
		LogRequestID: true,
		LogStatus:    true,
		HandleError:  true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			country := c.Request().Header.Get("Cf-IPCountry")
			cfRay := c.Request().Header.Get("Cf-Ray")
			logger := c.Logger()
			if v.Error == nil {
				logger.LogAttrs(context.Background(), slog.LevelInfo, "request",
					slog.String("request_id", v.RequestID),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Duration("latency", v.Latency),
					slog.String("remote_ip", v.RemoteIP),
					slog.String("cf_country", country),
					slog.String("cf_ray", cfRay),
					logAuthGroup(c),
					logHeaderGroup(c.Request().Header),
				)
				return nil
			}

			logger.LogAttrs(context.Background(), slog.LevelError, "request_error",
				slog.String("request_id", v.RequestID),
				slog.String("method", v.Method),
				slog.String("uri", v.URI),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("remote_ip", v.RemoteIP),
				slog.String("cf_country", country),
				slog.String("cf_ray", cfRay),
				logAuthGroup(c),
				logHeaderGroup(c.Request().Header),

				slog.String("error", v.Error.Error()),
			)
			return nil
		},
	})
}

func middlewareBasicAuth() echo.MiddlewareFunc {
	cfg := middleware.BasicAuthConfig{
		Realm: realm,
		Validator: func(c *echo.Context, user, password string) (bool, error) {
			c.Set("authctx", AuthContext{
				Username: user,
				Password: password,
			})
			return false, nil
		},
	}

	return middleware.BasicAuthWithConfig(cfg)
}

func middlewareSetServerHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		c.Response().Header()[echo.HeaderWWWAuthenticate] = []string{`Basic realm="` + realm + `"`}
		c.Response().Header().Set(echo.HeaderServer, "nginx/1.29.6")
		c.Response().Header().Set(echo.HeaderConnection, "keep-alive")
		return next(c)
	}
}

const (
	realm = "phpMyAdmin"
)

var page401 = []byte(strings.ReplaceAll(`<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.29.6</center>
</body>
</html>
`, "\n", "\r\n"))

var skip = []string{
	"/favicon.ico",
	"/.well-known",
	"/robots.txt",
	"/sitemap.xml",
}

var (
	keepHeaders = map[string]func(string) string{
		"Content-Type": func(v string) string {
			if idx := strings.Index(v, ";"); idx != -1 {
				return v[:idx]
			}
			return v
		},
		"Accept-Language": func(v string) string {
			if idx := strings.Index(v, ","); idx != -1 {
				return v[:idx]
			}
			return v
		},
		"Cookie": func(v string) string {
			parts := strings.Split(v, ";")
			if len(parts) > 20 {
				return "[TOO_MANY]"
			}
			var names []string
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				if idx := strings.Index(part, "="); idx != -1 {
					name := strings.TrimSpace(part[:idx])
					if name != "" {
						names = append(names, name)
					}
				}
			}
			if len(names) == 0 {
				return "[MALFORMED]"
			}
			return strings.Join(names, ";")
		},
		"User-Agent":      nil,
		"Authorization":   nil,
		"X-Forwarded-For": nil,
	}
	validateHeader = func(v string) (string, bool) {
		if len(v) == 0 {
			return "[EMPTY]", false
		}
		if len(v) > 1024 {
			return "[TOO_LONG]", false
		}
		return v, true
	}
)

type AuthContext struct {
	Username string
	Password string
}

func (a AuthContext) IsAttempted() bool {
	return a.Username != "" || a.Password != ""
}
