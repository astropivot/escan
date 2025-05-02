package Common

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
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

var logColors = map[string]color.Attribute{
	LogLevelError:   color.FgRed,    // 错误日志显示红色
	LogLevelInfo:    color.FgYellow, // 信息日志显示黄色
	LogLevelSuccess: color.FgGreen,  // 成功日志显示绿色
	LogLevelDebug:   color.FgBlue,   // 调试日志显示蓝色
}

const (
	LogLevelAll     = "ALL"
	LogLevelDebug   = "DEBUG"
	LogLevelInfo    = "INFO"
	LogLevelSuccess = "SUCCESS"
	LogLevelError   = "ERROR"
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
	// 根据当前设置的日志级别过滤日志
	shouldPrint := false
	switch LogLevel {
	case LogLevelDebug:
		// DEBUG级别显示所有日志
		shouldPrint = true
	case LogLevelError:
		// ERROR级别显示 ERROR、SUCCESS、INFO
		shouldPrint = entry.Level == LogLevelError ||
			entry.Level == LogLevelSuccess ||
			entry.Level == LogLevelInfo
	case LogLevelSuccess:
		// SUCCESS级别显示 SUCCESS、INFO
		shouldPrint = entry.Level == LogLevelSuccess ||
			entry.Level == LogLevelInfo
	case LogLevelInfo:
		// INFO级别只显示 INFO
		shouldPrint = entry.Level == LogLevelInfo
	case LogLevelAll:
		// ALL显示所有日志
		shouldPrint = true
	default:
		// 默认只显示 INFO
		shouldPrint = entry.Level == LogLevelInfo
	}

	if !shouldPrint {
		return
	}

	OutputMutex.Lock()
	defer OutputMutex.Unlock()
	logMsg := formatLogMessage(entry)

	// 使用彩色输出
	if colorAttr, ok := logColors[entry.Level]; ok {
		color.New(colorAttr).Println(logMsg)
	} else {
		fmt.Println(logMsg)
	}

}

func LogSuccess(content string, args ...any) {
	printLog(ifesle(content, LogLevelSuccess, args...))
}

func LogError(content string, args ...any) {
	printLog(ifesle(content, LogLevelError, args...))
}

func LogDebug(content string, args ...any) {
	printLog(ifesle(content, LogLevelDebug, args...))
}

func LogInfo(content string, args ...any) {

	printLog(ifesle(content, LogLevelInfo, args...))
}

func ifesle(content string, Level string, args ...any) *LogEntry {
	if len(args) > 0 {
		return &LogEntry{
			Level:   Level,
			Time:    time.Now(),
			Content: fmt.Sprintf(content, args...),
		}
	} else {
		return &LogEntry{
			Level:   Level,
			Time:    time.Now(),
			Content: content,
		}
	}
}

func CheckErrs(err error) error {
	if err == nil {
		return nil
	}

	// 已知需要重试的错误列表
	errs := []string{
		"closed by the remote host", "too many connections",
		"EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}

	// 检查错误是否匹配
	errLower := strings.ToLower(err.Error())
	for _, key := range errs {
		if strings.Contains(errLower, strings.ToLower(key)) {
			time.Sleep(3 * time.Second)
			return err
		}
	}

	return nil
}
