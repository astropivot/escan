package Common

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 全局输出管理器
var ResultOutput *OutputManager

// OutputManager 输出管理器结构体
type OutputManager struct {
	mu            sync.Mutex
	outputPath    string
	outputFormat  string
	file          *os.File
	csvWriter     *csv.Writer
	jsonEncoder   *json.Encoder
	isInitialized bool
}

// ResultType 定义结果类型
type ResultType string

const (
	HOST    ResultType = "HOST"    // 主机存活
	PORT    ResultType = "PORT"    // 端口开放
	SERVICE ResultType = "SERVICE" // 服务识别
	VULN    ResultType = "VULN"    // 漏洞发现
)

// ScanResult 扫描结果结构
type ScanResult struct {
	Time    time.Time              `json:"time"`    // 发现时间
	Type    ResultType             `json:"type"`    // 结果类型
	Target  string                 `json:"target"`  // 目标(IP/域名/URL)
	Status  string                 `json:"status"`  // 状态描述
	Details map[string]interface{} `json:"details"` // 详细信息
}

func InitOutput() error {
	LogDebug("InitOutput_start")
	switch OutputFormat {
	case "json", "txt", "csv":
		//有效格式

	default:
		LogError("Invalid OutputFormat: %s", OutputFormat)
		return fmt.Errorf("Invalid OutputFormat: %s", OutputFormat)
	}
	if OutputFilePath == "" {
		LogError("OutputFilePath is empty")
		return fmt.Errorf("OutputFilePath is empty")
	}
	dir := filepath.Dir(OutputFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		LogError("MkdirAll failed: %s", err.Error())
		return fmt.Errorf("MkdirAll failed: %s", err.Error())
	}
	manager := &OutputManager{
		outputPath:   OutputFilePath,
		outputFormat: OutputFormat,
	}

	if err := manager.initialize(); err != nil {
		LogError("OutputManager initialize failed: %s", err.Error())
		return fmt.Errorf("OutputManager initialize failed: %s", err.Error())
	}
	ResultOutput = manager
	LogDebug("InitOutput_end")

	return nil

}

func (manager *OutputManager) initialize() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.isInitialized {
		return nil
	}
	LogDebug("output_openning_file: " + manager.outputPath)
	file, err := os.OpenFile(manager.outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		LogError("output_openning_file_failed: " + err.Error())
		return fmt.Errorf("output_openning_file_failed: " + err.Error())
	}
	manager.file = file
	switch manager.outputFormat {
	case "csv":
		manager.csvWriter = csv.NewWriter(file)
		headers := []string{"Time", "Type", "Target", "Status", "Details"}
		if err := manager.csvWriter.Write(headers); err != nil {
			LogError("output_csv_write_header_failed: " + err.Error())
			file.Close()
			return fmt.Errorf("output_csv_write_header_failed: " + err.Error())
		}
		manager.csvWriter.Flush()
	case "txt":
		//TODO: txt output
	case "json":
		LogDebug("output_json_encoder_init")
		manager.jsonEncoder = json.NewEncoder(file)
		manager.jsonEncoder.SetIndent("", "  ")
	default:
		LogError("Invalid OutputFormat: " + manager.outputFormat)
		file.Close()
	}
	manager.isInitialized = true
	LogDebug("output_init_complete")
	return nil
}

func SaveResult(result *ScanResult) error {
	if ResultOutput == nil {
		LogDebug("ResultOutput_not_init")
		return fmt.Errorf("ResultOutput_not_init")
	}
	// LogDebug("output_save_result:type=%s,target=%s", result.Type, result.Target)
	return ResultOutput.saveResult(result)
	//TODO: save result to file or database
}
func (manager *OutputManager) saveResult(result *ScanResult) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.isInitialized {
		LogDebug("output_not_init")
		return fmt.Errorf("output_not_init")
	}
	var err error
	switch manager.outputFormat {
	case "csv":
		err = manager.writeCsv(result)
	case "txt":
		err = manager.writeTxt(result)
	case "json":
		err = manager.writeJson(result)
	default:
		err = fmt.Errorf("Invalid OutputFormat: %s", manager.outputFormat)
		return fmt.Errorf("Invalid OutputFormat: %s", manager.outputFormat)
	}
	if err != nil {
		LogDebug("output_save_result_failed: %s", err.Error())
	} else {
		// LogDebug("output_save_result_success:type=%s,target=%s", result.Type, result.Target)
	}
	return err
}

func (manager *OutputManager) writeTxt(result *ScanResult) error {
	var details string
	if len(result.Details) > 0 {
		pairs := make([]string, 0, len(result.Details))
		for k, v := range result.Details {
			pairs = append(pairs, fmt.Sprintf("%s=%v", k, v))
		}
		details = strings.Join(pairs, ", ")
	}
	txt := fmt.Sprintf("[%s] [%s] 目标:%s 状态:%s 详情:%s\n", result.Time.Format("2006-01-02 15:04:05"), result.Type, result.Target, result.Status, details)
	_, err := manager.file.WriteString(txt)
	return err
}

func (om *OutputManager) writeJson(result *ScanResult) error {
	return om.jsonEncoder.Encode(result)
}

func (om *OutputManager) writeCsv(result *ScanResult) error {
	details, err := json.Marshal(result.Details)
	if err != nil {
		details = []byte("{}")
	}

	record := []string{
		result.Time.Format("2006-01-02 15:04:05"),
		string(result.Type),
		result.Target,
		result.Status,
		string(details),
	}

	if err := om.csvWriter.Write(record); err != nil {
		return err
	}
	om.csvWriter.Flush()
	return om.csvWriter.Error()
}

func CloseOutput() error {
	if ResultOutput == nil {
		return nil
	}
	LogDebug("CloseOutput_start")
	ResultOutput.mu.Lock()
	defer ResultOutput.mu.Unlock()
	if !ResultOutput.isInitialized {
		LogDebug("output_no_need_close")
		return nil
	}

	if ResultOutput.csvWriter != nil {
		LogDebug("output_flush_csv")
		ResultOutput.csvWriter.Flush()
	}

	if err := ResultOutput.file.Close(); err != nil {
		LogDebug("output_close_failed%:s", err)
		return fmt.Errorf("output_close_failed:%s", err)
	}

	ResultOutput.isInitialized = false
	LogDebug("output_closed")
	return nil
}
