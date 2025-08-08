package logging

import (
	"fmt"
	"os"
	"strings"
)

type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

var currentLevel = LevelError // default to error

// InitFromEnv initializes log level from env var OBFUSKIT_LOG_LEVEL (error|warn|info|debug)
func InitFromEnv() {
	if v := os.Getenv("OBFUSKIT_LOG_LEVEL"); v != "" {
		SetLevel(v)
	}
}

// SetLevel sets the current logging level from string
func SetLevel(level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error", "err":
		currentLevel = LevelError
	case "warn", "warning":
		currentLevel = LevelWarn
	case "info":
		currentLevel = LevelInfo
	case "debug":
		currentLevel = LevelDebug
	default:
		currentLevel = LevelError
	}
}

func shouldLog(level Level) bool { return level <= currentLevel }

func Errorf(format string, a ...interface{}) {
	if shouldLog(LevelError) {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}
func Errorln(a ...interface{}) {
	if shouldLog(LevelError) {
		fmt.Fprintln(os.Stderr, a...)
	}
}

func Warnf(format string, a ...interface{}) {
	if shouldLog(LevelWarn) {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}
func Warnln(a ...interface{}) {
	if shouldLog(LevelWarn) {
		fmt.Fprintln(os.Stderr, a...)
	}
}

func Infof(format string, a ...interface{}) {
	if shouldLog(LevelInfo) {
		fmt.Printf(format, a...)
	}
}
func Infoln(a ...interface{}) {
	if shouldLog(LevelInfo) {
		fmt.Println(a...)
	}
}

func Debugf(format string, a ...interface{}) {
	if shouldLog(LevelDebug) {
		fmt.Printf(format, a...)
	}
}
func Debugln(a ...interface{}) {
	if shouldLog(LevelDebug) {
		fmt.Println(a...)
	}
}
