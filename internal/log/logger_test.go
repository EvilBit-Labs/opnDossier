package log

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/charmbracelet/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		testMsg  string
		expected bool // whether the message should appear in output
	}{
		{
			name: "debug level shows debug messages",
			config: Config{
				Level:           "debug",
				Format:          "text",
				ReportCaller:    false,
				ReportTimestamp: false,
			},
			testMsg:  "debug message",
			expected: true,
		},
		{
			name: "info level filters debug messages",
			config: Config{
				Level:           "info",
				Format:          "text",
				ReportCaller:    false,
				ReportTimestamp: false,
			},
			testMsg:  "debug message",
			expected: false,
		},
		{
			name: "warn level filters info messages",
			config: Config{
				Level:           "warn",
				Format:          "text",
				ReportCaller:    false,
				ReportTimestamp: false,
			},
			testMsg:  "info message",
			expected: false,
		},
		{
			name: "error level filters warn messages",
			config: Config{
				Level:           "error",
				Format:          "text",
				ReportCaller:    false,
				ReportTimestamp: false,
			},
			testMsg:  "warn message",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tt.config.Output = &buf

			logger := New(tt.config)
			require.NotNil(t, logger)

			// Test each log level method
			switch tt.config.Level {
			case "debug":
				logger.Debug(tt.testMsg)
			case "info":
				logger.Debug(tt.testMsg) // Should be filtered for info level
			case "warn":
				logger.Info(tt.testMsg) // Should be filtered for warn level
			case "error":
				logger.Warn(tt.testMsg) // Should be filtered for error level
			}

			output := buf.String()
			if tt.expected {
				assert.Contains(t, output, tt.testMsg)
			} else {
				assert.NotContains(t, output, tt.testMsg)
			}
		})
	}
}

func TestLoggerFormats(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		expected string // substring to look for in output
	}{
		{
			name:     "text format",
			format:   "text",
			expected: "INFO", // Text format typically shows level names
		},
		{
			name:     "json format",
			format:   "json",
			expected: `"level":"info"`, // JSON format should contain level field
		},
		{
			name:     "empty format defaults to text",
			format:   "",
			expected: "INFO",
		},
		{
			name:     "invalid format defaults to text",
			format:   "invalid",
			expected: "INFO",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			config := Config{
				Level:           "info",
				Format:          tt.format,
				Output:          &buf,
				ReportCaller:    false,
				ReportTimestamp: false,
			}

			logger := New(config)
			logger.Info("test message")

			output := buf.String()
			assert.Contains(t, output, tt.expected)

			// For JSON format, verify it's valid JSON
			if tt.format == "json" {
				lines := strings.Split(strings.TrimSpace(output), "\n")
				for _, line := range lines {
					if line == "" {
						continue
					}
					var jsonData map[string]interface{}
					err := json.Unmarshal([]byte(line), &jsonData)
					assert.NoError(t, err, "Output should be valid JSON")
					assert.Equal(t, "info", jsonData["level"])
					assert.Equal(t, "test message", jsonData["msg"])
				}
			}
		})
	}
}

func TestLoggerLevels(t *testing.T) {
	tests := []struct {
		level    string
		expected log.Level
	}{
		{"debug", log.DebugLevel},
		{"info", log.InfoLevel},
		{"warn", log.WarnLevel},
		{"warning", log.WarnLevel},
		{"error", log.ErrorLevel},
		{"invalid", log.InfoLevel}, // Should default to info
		{"", log.InfoLevel},        // Should default to info
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			level := parseLevel(tt.level)
			assert.Equal(t, tt.expected, level)
		})
	}
}

func TestLoggerWithContext(t *testing.T) {
	var buf bytes.Buffer
	config := Config{
		Level:           "info",
		Format:          "text",
		Output:          &buf,
		ReportCaller:    false,
		ReportTimestamp: false,
	}

	logger := New(config)
	type contextKey string
	ctx := context.WithValue(context.Background(), contextKey("test"), "value")

	contextLogger := logger.WithContext(ctx)
	require.NotNil(t, contextLogger)

	contextLogger.Info("test message")
	output := buf.String()
	assert.Contains(t, output, "test message")
}

func TestLoggerWithFields(t *testing.T) {
	var buf bytes.Buffer
	config := Config{
		Level:           "info",
		Format:          "json",
		Output:          &buf,
		ReportCaller:    false,
		ReportTimestamp: false,
	}

	logger := New(config)
	fieldLogger := logger.WithFields("key1", "value1", "key2", "value2")

	fieldLogger.Info("test message")

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "key2")
	assert.Contains(t, output, "value2")
}

func TestLoggerSub(t *testing.T) {
	var buf bytes.Buffer
	config := Config{
		Level:           "info",
		Format:          "json",
		Output:          &buf,
		ReportCaller:    false,
		ReportTimestamp: false,
	}

	logger := New(config)
	subLogger := logger.Sub("parser")

	subLogger.Info("test message")

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "subsystem")
	assert.Contains(t, output, "parser")
}

func TestLoggerWithPrefix(t *testing.T) {
	var buf bytes.Buffer
	config := Config{
		Level:           "info",
		Format:          "text",
		Output:          &buf,
		ReportCaller:    false,
		ReportTimestamp: false,
	}

	logger := New(config)
	prefixLogger := logger.WithPrefix("[TEST]")

	prefixLogger.Info("test message")

	output := buf.String()
	assert.Contains(t, output, "[TEST]")
	assert.Contains(t, output, "test message")
}

func TestLevelFiltering(t *testing.T) {
	// Test that higher log levels filter out lower level messages
	var buf bytes.Buffer
	config := Config{
		Level:           "error",
		Format:          "text",
		Output:          &buf,
		ReportCaller:    false,
		ReportTimestamp: false,
	}

	logger := New(config)

	// These should be filtered out
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")

	// This should appear
	logger.Error("error message")

	output := buf.String()
	assert.NotContains(t, output, "debug message")
	assert.NotContains(t, output, "info message")
	assert.NotContains(t, output, "warn message")
	assert.Contains(t, output, "error message")
}

func BenchmarkLogger(b *testing.B) {
	var buf bytes.Buffer
	config := Config{
		Level:           "info",
		Format:          "text",
		Output:          &buf,
		ReportCaller:    false,
		ReportTimestamp: false,
	}

	logger := New(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i)
	}
}
