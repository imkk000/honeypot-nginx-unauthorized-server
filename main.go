package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

func main() {
	var addr string
	var certFile, keyFile string
	var logPath string

	flag.StringVar(&addr, "addr", "127.0.0.1:9000", "set address")
	flag.StringVar(&certFile, "cert", "", "set cert file")
	flag.StringVar(&keyFile, "key", "", "set key file")
	flag.StringVar(&logPath, "log", "app.log", "set log path name")
	flag.Parse()

	fs, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		slog.Error("open log file", "err", err)
		os.Exit(2)
		return
	}
	defer fs.Close()

	multi := io.MultiWriter(os.Stdout, fs)
	logger := slog.New(slog.NewJSONHandler(multi, nil))

	e := echo.New()
	e.Logger = logger

	e.HTTPErrorHandler = errorHandler
	e.IPExtractor = ipExtractor
	e.Use(
		middleware.Recover(),
		middlewareSetServerHeader,
		middlewareNotFound,
		middlewareRequestID,
		middlewareRequestLogger(),
		middlewareBasicAuth(),
	)

	sc := echo.StartConfig{
		Address:    addr,
		HideBanner: true,
		HidePort:   true,
	}
	if err := sc.StartTLS(context.Background(), e, certFile, keyFile); err != nil {
		e.Logger.Error("start server", "err", err)
		os.Exit(2)
	}
}
