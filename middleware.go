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
	if ip := req.Header.Get("CF-Connecting-IP"); ip != "" {
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
		c.Set("request_id", id)
		c.Request().Header.Set(echo.HeaderXRequestID, id)
		return next(c)
	}
}

func middlewareNoFavicon(next echo.HandlerFunc) echo.HandlerFunc {
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
			if strings.HasPrefix(key, "CF-") {
				continue
			}
			value := headers.Get(key)

			result = append(result, slog.String(key, value))
		}
		return slog.GroupAttrs("headers", result...)
	}

	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogLatency:       true,
		LogRemoteIP:      true,
		LogHost:          true,
		LogMethod:        true,
		LogURI:           true,
		LogRequestID:     true,
		LogStatus:        true,
		LogContentLength: true,
		LogResponseSize:  true,
		HandleError:      true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			country := c.Request().Header.Get("CF-IPCountry")
			logger := c.Logger()
			if v.Error == nil {
				logger.LogAttrs(context.Background(), slog.LevelInfo, "request",
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Duration("latency", v.Latency),
					slog.String("host", v.Host),
					slog.String("bytes_in", v.ContentLength),
					slog.Int64("bytes_out", v.ResponseSize),
					slog.String("country", country),
					slog.String("remote_ip", v.RemoteIP),
					slog.String("request_id", v.RequestID),
					logHeaderGroup(c.Request().Header),
				)
				return nil
			}

			logger.LogAttrs(context.Background(), slog.LevelError, "request_error",
				slog.String("method", v.Method),
				slog.String("uri", v.URI),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("host", v.Host),
				slog.String("bytes_in", v.ContentLength),
				slog.Int64("bytes_out", v.ResponseSize),
				slog.String("country", country),
				slog.String("remote_ip", v.RemoteIP),
				slog.String("request_id", v.RequestID),
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
			if user != "" || password != "" {
				c.Logger().Info("login", "user", user, "pass", password, "request_id", c.Get("request_id"))
			}
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
