package Common

import (
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

var (
	status = &ScanStatus{lastSuccess: time.Now(), lastError: time.Now()}
	Num    int64
	End    int64
)

type ScanStatus struct {
	mu          sync.RWMutex
	total       int64
	completed   int64
	lastSuccess time.Time
	lastError   time.Time
}

type LogEntry struct {
	Level   string
	Time    time.Time
	Content string
}

const (
	LogLevelAll     = "ALL"
	LogLevelDebug   = "DEBUG"
	LogLevelInfo    = "INFO"
	LogLevelSuccess = "SUCCESS"
	LoglevelError   = "ERROR"
)

// InitLogger 初始化日志系统
func InitLogger() {
	// 禁用标准日志输出
	log.SetOutput(io.Discard)
}

func formatLogMessage(entry *LogEntry) string {
	return fmt.Sprintf("[%s] [%s] %s", entry.Time.Format("2006-01-02 15:04:05"), entry.Level, entry.Content)
}

func printLog(entry *LogEntry) {
	//todo 输出
	OutputMutex.Lock()
	defer OutputMutex.Unlock()
	logMsg := formatLogMessage(entry)
	fmt.Println(logMsg)
}

func LogSuccess(content string, args ...any) {

	entry := &LogEntry{
		Level:   LogLevelSuccess,
		Time:    time.Now(),
		Content: _ifelse(len(args) > 0, fmt.Sprintf(content, args...), content),
	}
	printLog(entry)

}

func LogError(content string, args ...any) {
	entry := &LogEntry{
		Level:   LoglevelError,
		Time:    time.Now(),
		Content: _ifelse(len(args) > 0, fmt.Sprintf(content, args...), content),
	}
	printLog(entry)
}

func LogDebug(content string, args ...any) {
	entry := &LogEntry{
		Level:   LogLevelDebug,
		Time:    time.Now(),
		Content: _ifelse(len(args) > 0, fmt.Sprintf(content, args...), content),
	}
	printLog(entry)
}

func LogInfo(content string, args ...any) {
	entry := &LogEntry{
		Level:   LogLevelInfo,
		Time:    time.Now(),
		Content: _ifelse(len(args) > 0, fmt.Sprintf(content, args...), content),
	}
	printLog(entry)
}

func _ifelse(condition bool, trueValue string, falseValue string) string {
	if condition {
		return trueValue
	}
	return falseValue
}
