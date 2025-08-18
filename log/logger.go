package log

import (
	"fmt"
	"io"
	"time"
)

type (
	Logger interface {
		D(message string, args ...interface{})
		I(message string, args ...interface{})
		E(message string, args ...interface{})
	}

	Level byte

	nopLogger func()

	stdLogger struct {
		out   io.Writer
		lower Level
	}
)

const (
	DebugLog Level = iota
	InfoLog
	ErrorLog
)

func (level Level) String() string {
	switch level {
	case DebugLog:
		return "DEBUG"
	case InfoLog:
		return "INFO"
	case ErrorLog:
		return "ERROR"
	default:
		return "N/A"
	}
}

var NopLogger Logger = nopLogger(func() {})

func (nop nopLogger) D(format string, args ...interface{}) {}
func (nop nopLogger) I(format string, args ...interface{}) {}
func (nop nopLogger) E(format string, args ...interface{}) {}

func NewLogger(lowerLevel Level, out io.Writer) Logger {
	return &stdLogger{lower: lowerLevel, out: out}
}

func (l *stdLogger) log(level Level, message string, args ...interface{}) {
	if level < l.lower {
		return
	}

	fmt.Fprintf(l.out, "%s [%-5s] %s\n",
		time.Now().Format("2006-01-02 15:04:00.000"),
		level,
		fmt.Sprintf(message, args...),
	)
}

func (l *stdLogger) D(message string, args ...interface{}) { l.log(DebugLog, message, args...) }
func (l *stdLogger) I(message string, args ...interface{}) { l.log(InfoLog, message, args...) }
func (l *stdLogger) E(message string, args ...interface{}) { l.log(ErrorLog, message, args...) }
