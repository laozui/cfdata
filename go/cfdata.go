package main

import (
	"bufio"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ----------------------- 嵌入静态文件 -----------------------

//go:embed index.html
var staticFiles embed.FS

// ----------------------- 数据类型定义 -----------------------

// DataCenterInfo 数据中心信息
type DataCenterInfo struct {
	DataCenter string
	Region     string
	City       string
	IPCount    int
	MinLatency int // 毫秒
}

// ScanResult 扫描结果
type ScanResult struct {
	IP          string
	DataCenter  string
	Region      string
	City        string
	LatencyStr  string
	TCPDuration time.Duration
}

// TestResult 测试结果
type TestResult struct {
	IP         string
	MinLatency time.Duration
	MaxLatency time.Duration
	AvgLatency time.Duration
	LossRate   float64
	Speed      string
}

// location 位置信息
type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

type scanController struct {
	mu     sync.Mutex
	cond   *sync.Cond
	paused bool
}

func newScanController() *scanController {
	c := &scanController{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *scanController) Pause() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return false
	}
	c.paused = true
	return true
}

func (c *scanController) Resume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused {
		return false
	}
	c.paused = false
	c.cond.Broadcast()
	return true
}

func (c *scanController) Reset() {
	c.mu.Lock()
	c.paused = false
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *scanController) IsPaused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paused
}

// ----------------------- 全局变量 -----------------------

var (
	// 扫描结果存储
	scanResults []ScanResult
	scanMutex   sync.Mutex

	// 位置信息映射
	locationMap map[string]location
	locationMu  sync.RWMutex

	// WebSocket 升级器
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	// WebSocket 写入锁
	wsMutex sync.Mutex

	// 随机数生成器
	randomMu        sync.Mutex
	randomGenerator = rand.New(rand.NewSource(time.Now().UnixNano()))

	// 扫描控制
	scanCtrl = newScanController()

	// 全局任务锁
	taskMutex     sync.Mutex
	isTaskRunning bool

	// 运行参数
	httpPort              int
	dataDir               string
	speedTestURL          string
	detailedTestMutex     sync.Mutex
	isDetailedTestRunning bool

	// CLI 批处理模式参数
	batchMode    bool
	batchLimit   int
	batchOut     string
	batchThreads int
	batchTimeout int

	// 移动端扫描参数（原子量，避免任务与导出接口并发读写）
	scanTimeoutAtomic atomic.Int64 // 单次 TCP 握手超时(ms)
	sampleLimitAtomic atomic.Int64 // 每次扫描随机采样的子网数，0 = 全部
	looseAtomic       atomic.Bool  // 宽松模式：TCP 连通但无 CF 特征也收录

	// 启动参数（仅 flag 解析阶段使用）
	flagScanTimeout int
	flagSampleLimit int
	flagLoose       bool

	// 详细测试结果（供 /api/ips 导出，网页表格只保留有限行）
	testResults   []TestResult
	testResultsMu sync.Mutex

	// 探测阶段统计（供 /api/diag 定位「扫不到 IP」）
	probeStats struct {
		tcpOK  int64
		httpOK int64
		cfRay  int64
		cfHead int64
		tlsOK  int64
		noCF   int64
	}
)

func scanTimeout() time.Duration {
	v := scanTimeoutAtomic.Load()
	if v < 200 {
		v = 200
	}
	return time.Duration(v) * time.Millisecond
}

func sampleLimit() int {
	return int(sampleLimitAtomic.Load())
}

// downloadClient 带超时的下载客户端。
// Android 上 CGO_ENABLED=0 时系统根证书可能不可达，App 启动进程时会设置
// SSL_CERT_FILE 指向内置的 Mozilla CA bundle，Go 的 crypto/x509 会自动读取。
var downloadClient = &http.Client{Timeout: 20 * time.Second}

func dataPath(name string) string {
	if dataDir != "" {
		return filepath.Join(dataDir, name)
	}
	if _, err := os.Stat(name); err == nil {
		return name
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		p := filepath.Join(exeDir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name
}

func tryStartDetailedTest() bool {
	detailedTestMutex.Lock()
	defer detailedTestMutex.Unlock()
	if isDetailedTestRunning {
		return false
	}
	isDetailedTestRunning = true
	return true
}

func finishDetailedTest() {
	detailedTestMutex.Lock()
	isDetailedTestRunning = false
	detailedTestMutex.Unlock()
}

// ----------------------- 主函数 -----------------------

func main() {
	flag.BoolVar(&batchMode, "batch", false, "静默批处理扫描模式，不启动网页服务")
	flag.IntVar(&batchLimit, "limit", 100, "批处理模式输出的最优 IP 数量")
	flag.StringVar(&batchOut, "out", "cf_ip_pool.txt", "批处理模式输出文件路径")
	flag.IntVar(&batchThreads, "threads", 128, "批处理模式并发扫描线程数")
	flag.IntVar(&batchTimeout, "timeout", 1000, "TCP 握手超时时间(ms)")
	flag.IntVar(&httpPort, "port", 8080, "网页服务监听端口")
	flag.StringVar(&dataDir, "data-dir", "", "资源文件目录，留空则使用当前目录")
	flag.IntVar(&flagScanTimeout, "scan-timeout", 1500, "移动端扫描单次 TCP 握手超时(ms)")
	flag.IntVar(&flagSampleLimit, "sample", 1200, "移动端扫描随机采样的子网数量，0=全部")
	flag.BoolVar(&flagLoose, "loose", false, "宽松模式：TCP 连通但无 CF 特征也收录")
	flag.Parse()

	dataDir = strings.Trim(strings.TrimSpace(dataDir), "\"")
	scanTimeoutAtomic.Store(int64(flagScanTimeout))
	sampleLimitAtomic.Store(int64(flagSampleLimit))
	looseAtomic.Store(flagLoose)

	if batchMode {
		if err := runBatchScan(); err != nil {
			fmt.Printf("批处理扫描失败: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := runServer(); err != nil {
		fmt.Printf("启动失败: %v\n", err)
	}
}

func runBatchScan() error {
	dataDir = strings.Trim(dataDir, "\"")
	dataDir = strings.TrimRight(dataDir, "\\/")
	batchOut = strings.Trim(batchOut, "\"")

	fmt.Printf("[cfdata] 启动 CLI 静默扫描模式: 目标采集前 %d 个最优 IP，输出到: %s\n", batchLimit, batchOut)
	initLocations()

	filename := dataPath("ips-v4.txt")
	apiURL := "https://www.baipiao.eu.org/cloudflare/ips-v4"
	var content string
	var err error

	if _, err = os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("[cfdata] 本地 %s 不存在，正在联网下载...\n", filename)
		content, err = getURLContent(apiURL)
		if err != nil {
			return fmt.Errorf("下载 IPv4 列表失败: %w", err)
		}
		_ = saveToFile(filename, content)
	} else {
		content, err = getFileContent(filename)
		if err != nil {
			return fmt.Errorf("读取本地 IPv4 列表失败: %w", err)
		}
	}

	ipList := parseIPList(content)
	if len(ipList) == 0 {
		return fmt.Errorf("IPv4 列表为空")
	}
	ipList = getRandomIPv4s(ipList)

	fmt.Printf("[cfdata] 正在并发扫描 %d 个 Cloudflare 子网样本 IP (并发数: %d, 超时: %dms)...\n", len(ipList), batchThreads, batchTimeout)

	var validResults []ScanResult
	var resMu sync.Mutex
	var wg sync.WaitGroup
	threadPool := make(chan struct{}, batchThreads)
	timeoutDuration := time.Duration(batchTimeout) * time.Millisecond

	startTime := time.Now()
	for _, ip := range ipList {
		threadPool <- struct{}{}
		wg.Add(1)
		go func(targetIP string) {
			defer func() {
				<-threadPool
				wg.Done()
			}()

			dialer := &net.Dialer{Timeout: timeoutDuration}
			t0 := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(targetIP, "80"))
			if err != nil {
				return
			}
			defer conn.Close()
			tcpDuration := time.Since(t0)

			req, err := http.NewRequest("GET", "http://"+net.JoinHostPort(targetIP, "80"), nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true

			_ = conn.SetDeadline(time.Now().Add(timeoutDuration + 500*time.Millisecond))
			if err := req.Write(conn); err != nil {
				return
			}

			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			cfRay := strings.TrimSpace(resp.Header.Get("CF-RAY"))
			if cfRay == "" {
				return
			}
			parts := strings.Split(cfRay, "-")
			dataCenter := ""
			if len(parts) >= 2 {
				dataCenter = strings.TrimSpace(parts[len(parts)-1])
			}

			locationMu.RLock()
			loc := locationMap[dataCenter]
			locationMu.RUnlock()

			r := ScanResult{
				IP:          targetIP,
				DataCenter:  dataCenter,
				Region:      loc.Region,
				City:        loc.City,
				LatencyStr:  fmt.Sprintf("%d ms", tcpDuration.Milliseconds()),
				TCPDuration: tcpDuration,
			}

			resMu.Lock()
			validResults = append(validResults, r)
			resMu.Unlock()
		}(ip)
	}
	wg.Wait()

	totalTime := time.Since(startTime)
	fmt.Printf("[cfdata] 扫描完毕，耗时: %.2fs，共发现 %d 个响应良好的可用 IP\n", totalTime.Seconds(), len(validResults))

	if len(validResults) == 0 {
		return fmt.Errorf("未能扫描到任何有效 IP")
	}

	// 按 TCP 延迟从小到大排序
	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].TCPDuration < validResults[j].TCPDuration
	})

	limit := batchLimit
	if limit <= 0 || limit > len(validResults) {
		limit = len(validResults)
	}
	topList := validResults[:limit]

	// 写入文件
	var lines []string
	for _, res := range topList {
		lines = append(lines, res.IP)
	}
	outData := strings.Join(lines, "\n") + "\n"

	// 如果输出文件的父目录不存在，先创建
	if dir := filepath.Dir(batchOut); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	if err := os.WriteFile(batchOut, []byte(outData), 0644); err != nil {
		return fmt.Errorf("写入输出文件失败: %w", err)
	}

	fmt.Printf("[cfdata] 成功将前 %d 个最优 IP 写入: %s (最低延迟: %s, 第%d延迟: %s)\n",
		len(topList), batchOut, topList[0].LatencyStr, len(topList), topList[len(topList)-1].LatencyStr)
	return nil
}

func runServer() error {
	initLocations()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("index.html")
		if err != nil {
			http.Error(w, "无法加载页面", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	http.HandleFunc("/ws", handleWebSocket)
	http.HandleFunc("/api/ips", handleIPsAPI)
	http.HandleFunc("/api/diag", handleDiagAPI)

	addr := fmt.Sprintf(":%d", httpPort)
	fmt.Printf("网页服务已启动: http://localhost:%d\n", httpPort)
	if dataDir != "" {
		fmt.Printf("资源目录: %s\n", dataDir)
	}

	return http.ListenAndServe(addr, nil)
}

// ----------------------- WebSocket 处理 -----------------------

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket 升级失败:", err)
		return
	}
	defer ws.Close()

	for {
		// 读取客户端消息
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}

		var request struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(msg, &request); err != nil {
			continue
		}

		// 根据消息类型分发任务
		switch request.Type {
		case "start_task":
			var params struct {
				IPType   int    `json:"ipType"`
				Threads  int    `json:"threads"`
				Port     int    `json:"port"`
				Delay    int    `json:"delay"`
				SpeedURL string `json:"speedUrl"`
				Timeout  int    `json:"timeout"`
				Sample   int    `json:"sample"`
				Loose    bool   `json:"loose"`
			}
			json.Unmarshal(request.Data, &params)
			if params.SpeedURL == "" {
				sendWSMessage(ws, "error", "缺少测速 URL，请在网页中填写后再开始扫描")
				continue
			}
			speedTestURL = params.SpeedURL
			if params.Timeout > 0 {
				scanTimeoutAtomic.Store(int64(params.Timeout))
			}
			if params.Sample > 0 {
				sampleLimitAtomic.Store(int64(params.Sample))
			}
			looseAtomic.Store(params.Loose)
			go runUnifiedTask(ws, params.IPType, params.Threads)

		case "pause_task":
			if scanCtrl.Pause() {
				sendCurrentScanSummary(ws, true)
			} else {
				sendWSMessage(ws, "log", "扫描已处于暂停状态")
			}

		case "resume_task":
			if scanCtrl.Resume() {
				sendWSMessage(ws, "log", "继续扫描中...")
			} else {
				sendWSMessage(ws, "log", "当前没有处于暂停状态的扫描任务")
			}

		case "compact_ipv4":
			go compactIPv4Library(ws)

		case "reset_resources":
			go resetResources(ws)

		case "start_test":
			var params struct {
				DC    string `json:"dc"`
				Port  int    `json:"port"`
				Delay int    `json:"delay"`
			}
			json.Unmarshal(request.Data, &params)
			go runDetailedTest(ws, params.DC, params.Port, params.Delay)

		case "start_speed_test":
			var params struct {
				IP       string `json:"ip"`
				Port     int    `json:"port"`
				SpeedURL string `json:"speedUrl"`
			}
			json.Unmarshal(request.Data, &params)
			if params.SpeedURL == "" {
				sendWSMessage(ws, "speed_test_result", map[string]string{
					"ip":    params.IP,
					"speed": "缺少测速 URL",
				})
				sendWSMessage(ws, "log", "测速失败: 未提供测速 URL")
				continue
			}
			speedTestURL = params.SpeedURL
			go runSpeedTest(ws, params.IP, params.Port)
		}
	}
}

func sendWSMessage(ws *websocket.Conn, msgType string, data any) {
	wsMutex.Lock()
	defer wsMutex.Unlock()
	msg := map[string]any{
		"type": msgType,
		"data": data,
	}
	ws.WriteJSON(msg)
}

// ----------------------- 核心逻辑 -----------------------

func initLocations() {
	initLocationsWithWS(nil)
}

func initLocationsWithWS(ws *websocket.Conn) {
	filename := dataPath("locations.json")
	url := "https://www.baipiao.eu.org/cloudflare/locations"
	var locations []location
	var body []byte
	var err error

	if _, err = os.Stat(filename); os.IsNotExist(err) {
		msg := fmt.Sprintf("本地 %s 不存在，正在下载 locations 数据...", filename)
		fmt.Println(msg)
		if ws != nil {
			sendWSMessage(ws, "log", msg)
		}
		resp, err := downloadClient.Get(url)
		if err != nil {
			fmt.Println("获取位置信息失败:", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("获取位置信息失败: HTTP %d\n", resp.StatusCode)
			return
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("读取响应内容失败:", err)
			return
		}
		if err := saveToFile(filename, string(body)); err != nil {
			fmt.Println("保存位置信息文件失败:", err)
		} else {
			msg = fmt.Sprintf("locations 数据下载完成，已保存到 %s", filename)
			fmt.Println(msg)
			if ws != nil {
				sendWSMessage(ws, "log", msg)
			}
		}
	} else {
		msg := fmt.Sprintf("读取本地 %s 文件...", filename)
		fmt.Println(msg)
		if ws != nil {
			sendWSMessage(ws, "log", msg)
		}
		body, err = os.ReadFile(filename)
		if err != nil {
			fmt.Println("读取本地位置文件失败:", err)
			return
		}
	}

	if err := json.Unmarshal(body, &locations); err != nil {
		fmt.Println("解析位置信息JSON失败:", err)
		return
	}

	loadedMap := make(map[string]location)
	for _, loc := range locations {
		loadedMap[loc.Iata] = loc
	}

	locationMu.Lock()
	locationMap = loadedMap
	locationMu.Unlock()

	msg := fmt.Sprintf("已加载 %d 个数据中心位置信息", len(loadedMap))
	fmt.Println(msg)
	if ws != nil {
		sendWSMessage(ws, "log", msg)
	}
}

func buildDCListFromScanResults() []DataCenterInfo {
	scanMutex.Lock()
	defer scanMutex.Unlock()

	sort.Slice(scanResults, func(i, j int) bool {
		return scanResults[i].TCPDuration < scanResults[j].TCPDuration
	})

	dcMap := make(map[string]*DataCenterInfo)
	for _, res := range scanResults {
		if _, ok := dcMap[res.DataCenter]; !ok {
			dcMap[res.DataCenter] = &DataCenterInfo{
				DataCenter: res.DataCenter,
				Region:     res.Region,
				City:       res.City,
				IPCount:    0,
				MinLatency: 999999,
			}
		}
		info := dcMap[res.DataCenter]
		info.IPCount++
		lat, _ := strconv.Atoi(strings.TrimSuffix(res.LatencyStr, " ms"))
		if lat < info.MinLatency {
			info.MinLatency = lat
		}
	}

	var dcList []DataCenterInfo
	for _, info := range dcMap {
		dcList = append(dcList, *info)
	}
	sort.Slice(dcList, func(i, j int) bool {
		return dcList[i].MinLatency < dcList[j].MinLatency
	})

	return dcList
}

func sendCurrentScanSummary(ws *websocket.Conn, paused bool) {
	scanMutex.Lock()
	resultsCount := len(scanResults)
	scanMutex.Unlock()

	if paused {
		sendWSMessage(ws, "scan_paused", map[string]bool{"paused": true})
	}

	if resultsCount == 0 {
		if paused {
			sendWSMessage(ws, "error", "已暂停扫描，但当前还没有扫描到有效 IP")
		}
		return
	}

	dcList := buildDCListFromScanResults()
	if paused {
		sendWSMessage(ws, "log", "扫描已暂停，已整理当前已扫描到的 IP")
	}
	sendWSMessage(ws, "scan_complete_wait_dc", dcList)
}

func compactIPv4Library(ws *websocket.Conn) {
	taskMutex.Lock()
	if isTaskRunning {
		taskMutex.Unlock()
		sendWSMessage(ws, "error", "已有任务正在运行，请等待完成后再试")
		return
	}
	isTaskRunning = true
	taskMutex.Unlock()
	defer func() {
		taskMutex.Lock()
		isTaskRunning = false
		taskMutex.Unlock()
	}()

	filename := dataPath("ips-v4.txt")
	apiURL := "https://www.baipiao.eu.org/cloudflare/ips-v4"
	var content string
	var err error

	if _, err = os.Stat(filename); os.IsNotExist(err) {
		sendWSMessage(ws, "log", fmt.Sprintf("本地 %s 不存在，正在下载...", filename))
		content, err = getURLContent(apiURL)
		if err != nil {
			sendWSMessage(ws, "error", "下载 IPv4 列表失败: "+err.Error())
			return
		}
	} else {
		sendWSMessage(ws, "log", fmt.Sprintf("读取本地 %s 文件...", filename))
		content, err = getFileContent(filename)
		if err != nil {
			sendWSMessage(ws, "error", "读取本地 IPv4 列表失败: "+err.Error())
			return
		}
	}

	ipList := parseIPList(content)
	if len(ipList) == 0 {
		sendWSMessage(ws, "error", "IPv4 地址库为空，无法精简")
		return
	}

	subnetStates := initSubnetStates(ipList)
	validSubnets := make(map[string]bool)
	emptyRounds := 0
	pass := 1
	maxThreads := 100

	for {
		toScan := getSubnetsToScan(subnetStates)
		if len(toScan) == 0 {
			break
		}

		ipsToTest := generateOneIPPerSubnet(toScan)
		totalToScan := len(ipsToTest)
		sendWSMessage(ws, "log", fmt.Sprintf("IPv4 精简第 %d 轮开始，本轮待测 %d 个子网", pass, totalToScan))
		sendWSMessage(ws, "compact_ipv4_progress", map[string]any{
			"pass":    pass,
			"current": 0,
			"total":   totalToScan,
			"found":   len(validSubnets),
			"status":  fmt.Sprintf("精简第 %d 轮", pass),
		})
		validIPs := scanLiteIPv4s(ws, ipsToTest, maxThreads, pass, len(validSubnets))

		if len(validIPs) == 0 {
			emptyRounds++
			sendWSMessage(ws, "log", fmt.Sprintf("第 %d 轮未发现有效 IPv4 子网", pass))
			if emptyRounds >= 2 {
				sendWSMessage(ws, "log", "连续 2 轮未发现有效 IPv4 子网，停止精简")
				break
			}
		} else {
			emptyRounds = 0
			sendWSMessage(ws, "log", fmt.Sprintf("第 %d 轮发现 %d 个有效 IPv4 子网", pass, len(validIPs)))
		}

		for _, ip := range validIPs {
			subnet := extractSubnet(ip)
			if subnet == "" {
				continue
			}
			subnetStates[subnet].found = true
			validSubnets[subnet] = true
		}
		sendWSMessage(ws, "log", fmt.Sprintf("第 %d 轮结束，累计保留 %d 个 IPv4 子网", pass, len(validSubnets)))
		pass++
	}

	sendWSMessage(ws, "compact_ipv4_progress", map[string]any{
		"pass":    pass - 1,
		"current": len(validSubnets),
		"total":   len(validSubnets),
		"found":   len(validSubnets),
		"status":  "精简完成",
	})

	if len(validSubnets) == 0 {
		sendWSMessage(ws, "error", "未发现可保留的有效 IPv4 子网")
		return
	}

	var subnets []string
	for subnet := range validSubnets {
		subnets = append(subnets, subnet)
	}
	sort.Slice(subnets, func(i, j int) bool {
		ip1 := strings.TrimSuffix(subnets[i], "/24")
		ip2 := strings.TrimSuffix(subnets[j], "/24")
		parts1 := strings.Split(ip1, ".")
		parts2 := strings.Split(ip2, ".")
		for k := range 4 {
			n1, _ := strconv.Atoi(parts1[k])
			n2, _ := strconv.Atoi(parts2[k])
			if n1 != n2 {
				return n1 < n2
			}
		}
		return false
	})

	compactContent := strings.Join(subnets, "\n") + "\n"
	if err := saveToFile(filename, compactContent); err != nil {
		sendWSMessage(ws, "error", "写入精简后的 IPv4 地址库失败: "+err.Error())
		return
	}

	sendWSMessage(ws, "compact_ipv4_done", map[string]any{
		"count": len(subnets),
		"file":  filename,
	})
	sendWSMessage(ws, "log", fmt.Sprintf("IPv4 地址库精简完成，已保留 %d 个 /24 子网并覆盖原文件", len(subnets)))
}

func resetResources(ws *websocket.Conn) {
	taskMutex.Lock()
	if isTaskRunning {
		taskMutex.Unlock()
		sendWSMessage(ws, "error", "已有任务正在运行，请等待完成后再试")
		return
	}
	isTaskRunning = true
	taskMutex.Unlock()
	defer func() {
		taskMutex.Lock()
		isTaskRunning = false
		taskMutex.Unlock()
	}()

	files := []string{
		dataPath("locations.json"),
		dataPath("ips-v4.txt"),
		dataPath("ips-v6.txt"),
	}

	deleted := make([]string, 0, len(files))
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			if !os.IsNotExist(err) {
				sendWSMessage(ws, "error", fmt.Sprintf("删除资源文件失败: %s: %v", file, err))
				return
			}
			continue
		}
		deleted = append(deleted, filepath.Base(file))
	}

	locationMu.Lock()
	locationMap = nil
	locationMu.Unlock()
	sendWSMessage(ws, "reset_resources_done", map[string]any{
		"deleted": deleted,
	})
	sendWSMessage(ws, "log", "资源目录已重置，后续运行会重新联网下载 locations、IPv4、IPv6 数据")
}

func runUnifiedTask(ws *websocket.Conn, ipType int, scanMaxThreads int) {
	taskMutex.Lock()
	if isTaskRunning {
		taskMutex.Unlock()
		sendWSMessage(ws, "error", "已有任务正在运行，请等待完成后再试")
		return
	}
	isTaskRunning = true
	taskMutex.Unlock()

	defer func() {
		scanCtrl.Reset()
		taskMutex.Lock()
		isTaskRunning = false
		taskMutex.Unlock()
	}()

	scanCtrl.Reset()
	sendWSMessage(ws, "log", "开始扫描任务...")

	// 确定文件名和URL
	var filename, apiURL string
	if ipType == 6 {
		filename = dataPath("ips-v6.txt")
		apiURL = "https://www.baipiao.eu.org/cloudflare/ips-v6"
	} else {
		filename = dataPath("ips-v4.txt")
		apiURL = "https://www.baipiao.eu.org/cloudflare/ips-v4"
	}

	var content string
	var err error

	// 检查本地文件是否存在
	if _, err = os.Stat(filename); os.IsNotExist(err) {
		sendWSMessage(ws, "log", fmt.Sprintf("本地 %s 不存在，正在下载...", filename))
		content, err = getURLContent(apiURL)
		if err != nil {
			sendWSMessage(ws, "error", "下载 IP 列表失败: "+err.Error())
			return
		}
		// 保存到本地
		if err := saveToFile(filename, content); err != nil {
			sendWSMessage(ws, "log", "警告: 保存IP文件失败: "+err.Error())
		}
	} else {
		sendWSMessage(ws, "log", fmt.Sprintf("读取本地 %s 文件...", filename))
		content, err = getFileContent(filename)
		if err != nil {
			sendWSMessage(ws, "error", "读取本地 IP 列表失败: "+err.Error())
			return
		}
	}

	ipList := parseIPList(content)
	ipList = limitIPList(ipList, sampleLimit())
	if ipType == 6 {
		ipList = getRandomIPv6s(ipList)
	} else {
		ipList = getRandomIPv4s(ipList)
	}

	// 每轮清空探测统计，便于 /api/diag 判断卡在哪一环
	atomic.StoreInt64(&probeStats.tcpOK, 0)
	atomic.StoreInt64(&probeStats.httpOK, 0)
	atomic.StoreInt64(&probeStats.cfRay, 0)
	atomic.StoreInt64(&probeStats.cfHead, 0)
	atomic.StoreInt64(&probeStats.tlsOK, 0)
	atomic.StoreInt64(&probeStats.noCF, 0)

	scanMutex.Lock()
	scanResults = []ScanResult{}
	scanMutex.Unlock()
	testResultsMu.Lock()
	testResults = nil
	testResultsMu.Unlock()

	initLocationsWithWS(ws)

	sendWSMessage(ws, "log", fmt.Sprintf("正在扫描 %d 个 IP 地址...", len(ipList)))

	var wg sync.WaitGroup
	wg.Add(len(ipList))
	thread := make(chan struct{}, scanMaxThreads)
	var count int
	total := len(ipList)

	for _, ip := range ipList {
		scanCtrl.mu.Lock()
		for scanCtrl.paused {
			scanCtrl.cond.Wait()
		}
		scanCtrl.mu.Unlock()

		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				scanMutex.Lock()
				count++
				currentCount := count
				scanMutex.Unlock()
				if currentCount%10 == 0 || currentCount == total {
					sendWSMessage(ws, "scan_progress", map[string]int{
						"current": currentCount,
						"total":   total,
					})
				}
			}()

			res, ok := probeCF(ip)
			if !ok {
				return
			}
			scanMutex.Lock()
			scanResults = append(scanResults, res)
			scanMutex.Unlock()
			sendWSMessage(ws, "scan_result", res)
		}(ip)
	}
	wg.Wait()

	if scanCtrl.IsPaused() {
		return
	}

	// ---------------- Bug Fix: 检查是否有结果 ----------------
	scanMutex.Lock()
	resultsCount := len(scanResults)
	scanMutex.Unlock()

	if resultsCount == 0 {
		sendWSMessage(ws, "error", "扫描完成，但未发现任何有效IP。请检查网络状态或尝试更换IP类型/增加延迟阈值。")
		return
	}
	// ------------------------------------------------------

	sendWSMessage(ws, "log", "扫描完成，请选择数据中心进行详细测试")
	sendCurrentScanSummary(ws, false)
}

func runDetailedTest(ws *websocket.Conn, selectedDC string, port int, delay int) {
	if !tryStartDetailedTest() {
		sendWSMessage(ws, "test_busy", map[string]string{
			"message": "当前已有数据测试任务，请等待完成后再试",
		})
		return
	}
	defer finishDetailedTest()

	var testIPList []string
	scanMutex.Lock()
	for _, res := range scanResults {
		if selectedDC == "" || res.DataCenter == selectedDC {
			testIPList = append(testIPList, res.IP)
		}
	}
	scanMutex.Unlock()

	if len(testIPList) == 0 {
		sendWSMessage(ws, "error", "没有找到可测试的 IP 地址")
		return
	}

	sendWSMessage(ws, "log", fmt.Sprintf("开始对 %s 的 %d 个 IP 进行详细测试...", selectedDC, len(testIPList)))

	var results []TestResult
	var resMutex sync.Mutex

	var wg sync.WaitGroup
	wg.Add(len(testIPList))
	thread := make(chan struct{}, 50)
	var count int
	total := len(testIPList)

	for _, ip := range testIPList {
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				scanMutex.Lock()
				count++
				currentCount := count
				scanMutex.Unlock()
				if currentCount%5 == 0 || currentCount == total {
					sendWSMessage(ws, "test_progress", map[string]int{
						"current": currentCount,
						"total":   total,
					})
				}
			}()

			dialer := &net.Dialer{Timeout: time.Duration(delay) * time.Millisecond}
			successCount := 0
			totalLatency := time.Duration(0)
			minLatency := time.Duration(math.MaxInt64)
			maxLatency := time.Duration(0)

			for range 10 {
				start := time.Now()
				conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
				if err != nil {
					continue
				}
				latency := time.Since(start)
				if latency > time.Duration(delay)*time.Millisecond {
					conn.Close()
					continue
				}
				successCount++
				totalLatency += latency
				if latency < minLatency {
					minLatency = latency
				}
				if latency > maxLatency {
					maxLatency = latency
				}
				conn.Close()
			}

			if successCount > 0 {
				avgLatency := totalLatency / time.Duration(successCount)
				lossRate := float64(10-successCount) / 10.0
				res := TestResult{
					IP:         ip,
					MinLatency: minLatency,
					MaxLatency: maxLatency,
					AvgLatency: avgLatency,
					LossRate:   lossRate,
				}
				sendWSMessage(ws, "test_result", res)

				resMutex.Lock()
				results = append(results, res)
				resMutex.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].LossRate != results[j].LossRate {
			return results[i].LossRate < results[j].LossRate
		}

		minI := time.Duration(math.Round(float64(results[i].MinLatency) / float64(time.Millisecond)))
		minJ := time.Duration(math.Round(float64(results[j].MinLatency) / float64(time.Millisecond)))
		if minI != minJ {
			return minI < minJ
		}

		if results[i].MaxLatency != results[j].MaxLatency {
			return results[i].MaxLatency < results[j].MaxLatency
		}

		return results[i].AvgLatency < results[j].AvgLatency
	})

	testResultsMu.Lock()
	testResults = append([]TestResult(nil), results...)
	testResultsMu.Unlock()

	sendWSMessage(ws, "test_complete", results)
}

func runSpeedTest(ws *websocket.Conn, ip string, port int) {
	sendWSMessage(ws, "log", fmt.Sprintf("开始对 IP %s 端口 %d 进行测速...", ip, port))
	if speedTestURL == "" {
		sendWSMessage(ws, "speed_test_result", map[string]string{
			"ip":    ip,
			"speed": "缺少测速 URL",
		})
		sendWSMessage(ws, "log", "测速失败: 未提供测速 URL")
		return
	}

	scheme := "http"
	if port == 443 || port == 2053 || port == 2083 || port == 2087 || port == 2096 || port == 8443 {
		scheme = "https"
	}

	testURL := speedTestURL
	if !strings.HasPrefix(testURL, "http://") && !strings.HasPrefix(testURL, "https://") {
		testURL = scheme + "://" + testURL
	}

	parsedURL, err := url.Parse(testURL)
	if err != nil {
		sendWSMessage(ws, "speed_test_result", map[string]string{
			"ip":    ip,
			"speed": "URL解析错误",
		})
		return
	}
	hostname := parsedURL.Hostname()

	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return net.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 15 * time.Second,
	}

	fullURL := fmt.Sprintf("%s://%s%s", scheme, hostname, parsedURL.RequestURI())
	req, _ := http.NewRequest("GET", fullURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		sendWSMessage(ws, "speed_test_result", map[string]string{
			"ip":    ip,
			"speed": "连接错误",
		})
		sendWSMessage(ws, "log", "测速失败: "+err.Error())
		return
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	var totalBytes int64
	var maxSpeed float64
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	lastBytes := int64(0)
	lastTime := start
	done := false
	for !done {
		select {
		case <-timeout:
			done = true
		case <-ticker.C:
			now := time.Now()
			duration := now.Sub(lastTime).Seconds()
			if duration > 0 {
				bytesDiff := totalBytes - lastBytes
				currentSpeed := float64(bytesDiff) / duration / 1024 / 1024
				if currentSpeed > maxSpeed {
					maxSpeed = currentSpeed
				}
			}
			lastBytes = totalBytes
			lastTime = now
		default:
			n, err := resp.Body.Read(buf)
			if n > 0 {
				totalBytes += int64(n)
			}
			if err != nil {
				done = true
			}
		}
	}

	speedStr := fmt.Sprintf("%.2f MB/s", maxSpeed)
	sendWSMessage(ws, "speed_test_result", map[string]string{
		"ip":    ip,
		"speed": speedStr,
	})
	sendWSMessage(ws, "log", fmt.Sprintf("IP %s 测速完成: %s", ip, speedStr))
}

func getURLContent(targetURL string) (string, error) {
	resp, err := downloadClient.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// getFileContent 读取本地文件内容
func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// saveToFile 保存内容到文件
func saveToFile(filename, content string) error {
	dir := filepath.Dir(filename)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(filename, []byte(content), 0644)
}

func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ipList = append(ipList, line)
		}
	}
	return ipList
}

func nextRandomIntn(n int) int {
	randomMu.Lock()
	defer randomMu.Unlock()
	return randomGenerator.Intn(n)
}

type subnetState struct {
	subnet  string
	usedIPs map[int]bool
	found   bool
}

func initSubnetStates(ipList []string) map[string]*subnetState {
	states := make(map[string]*subnetState)
	for _, subnet := range ipList {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		states[subnet] = &subnetState{
			subnet:  subnet,
			usedIPs: make(map[int]bool),
		}
	}
	return states
}

func getSubnetsToScan(states map[string]*subnetState) []*subnetState {
	var toScan []*subnetState
	for _, state := range states {
		if !state.found {
			toScan = append(toScan, state)
		}
	}
	return toScan
}

func generateOneIPPerSubnet(states []*subnetState) []string {
	var ips []string
	for _, state := range states {
		lastOctet := nextRandomIntn(256)
		for state.usedIPs[lastOctet] && len(state.usedIPs) < 256 {
			lastOctet = (lastOctet + 1) % 256
		}
		state.usedIPs[lastOctet] = true

		baseIP := strings.TrimSuffix(state.subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) != 4 {
			continue
		}
		octets[3] = fmt.Sprintf("%d", lastOctet)
		ips = append(ips, strings.Join(octets, "."))
	}
	return ips
}

func scanLiteIPv4s(ws *websocket.Conn, ipList []string, maxThreads int, currentPass int, foundCount int) []string {
	var wg sync.WaitGroup
	wg.Add(len(ipList))
	resultChan := make(chan string, len(ipList))
	thread := make(chan struct{}, maxThreads)
	var count int
	var mu sync.Mutex
	total := len(ipList)

	for _, ip := range ipList {
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				mu.Lock()
				count++
				current := count
				mu.Unlock()
				if current == 1 || current%10 == 0 || current == total {
					sendWSMessage(ws, "compact_ipv4_progress", map[string]any{
						"pass":    currentPass,
						"current": current,
						"total":   total,
						"found":   foundCount,
						"status":  fmt.Sprintf("精简第 %d 轮", currentPass),
					})
				}
			}()

			dialer := &net.Dialer{Timeout: 1 * time.Second}
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "80"))
			if err != nil {
				return
			}
			conn.Close()
			sendWSMessage(ws, "log", fmt.Sprintf("第 %d 轮发现有效 IP: %s", currentPass, ip))
			resultChan <- ip
		}(ip)
	}

	wg.Wait()
	close(resultChan)

	var validIPs []string
	for ip := range resultChan {
		validIPs = append(validIPs, ip)
	}
	return validIPs
}

func extractSubnet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return ""
}

func getRandomIPv4s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) >= 4 {
			octets[3] = fmt.Sprintf("%d", nextRandomIntn(256))
			randomIPs = append(randomIPs, strings.Join(octets, "."))
		}
	}
	return randomIPs
}

func getRandomIPv6s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/48")
		sections := strings.Split(baseIP, ":")
		if len(sections) >= 3 {
			sections = sections[:3]
			for i := 3; i < 8; i++ {
				sections = append(sections, fmt.Sprintf("%x", nextRandomIntn(65536)))
			}
			randomIPs = append(randomIPs, strings.Join(sections, ":"))
		}
	}
	return randomIPs
}

// ----------------------- 移动端适配：探测 / 采样 / 导出 -----------------------

// limitIPList 随机抽样子网，避免移动端一次发起 6500+ 连接把 radio/NAT 打满。
func limitIPList(list []string, limit int) []string {
	if limit <= 0 || len(list) <= limit {
		return list
	}
	out := append([]string(nil), list...)
	for i := 0; i < limit; i++ {
		j := i + nextRandomIntn(len(out)-i)
		out[i], out[j] = out[j], out[i]
	}
	return out[:limit]
}

func fillLocation(res *ScanResult, dc string) {
	locationMu.RLock()
	loc := locationMap[dc]
	locationMu.RUnlock()
	res.DataCenter = dc
	res.Region = loc.Region
	res.City = loc.City
}

// tlsLooksLikeCF 用 TLS 握手 + 证书签发者判断是否为 Cloudflare 边缘。
// 明文 80 端口在移动网络常被运营商注入/劫持，这条加密通道可兜底。
func tlsLooksLikeCF(ip string, timeout time.Duration) bool {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout + 1500*time.Millisecond))
	c := tls.Client(conn, &tls.Config{
		ServerName:         "speed.cloudflare.com",
		InsecureSkipVerify: true, // 只判断证书签发者，不做域名/链校验
		MinVersion:         tls.VersionTLS12,
	})
	if err := c.Handshake(); err != nil {
		return false
	}
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false
	}
	issuer := strings.ToLower(certs[0].Issuer.String())
	return strings.Contains(issuer, "cloudflare")
}

// probeCF 探测单个 IP，返回 (结果, 是否收录)。
// 判定优先级：CF-RAY > Server: cloudflare / Cf-Cache-Status > TLS 证书 > 宽松模式。
func probeCF(ip string) (ScanResult, bool) {
	res := ScanResult{IP: ip}
	timeout := scanTimeout()

	d := &net.Dialer{Timeout: timeout}
	t0 := time.Now()
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, "80"))
	if err != nil {
		atomic.AddInt64(&probeStats.noCF, 1)
		return res, false
	}
	defer conn.Close()
	res.TCPDuration = time.Since(t0)
	res.LatencyStr = fmt.Sprintf("%d ms", res.TCPDuration.Milliseconds())
	atomic.AddInt64(&probeStats.tcpOK, 1)

	req, err := http.NewRequest("GET", "http://"+net.JoinHostPort(ip, "80"), nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Close = true
		_ = conn.SetDeadline(time.Now().Add(timeout + 1500*time.Millisecond))
		if err = req.Write(conn); err == nil {
			resp, rerr := http.ReadResponse(bufio.NewReader(conn), req)
			if rerr == nil {
				_ = resp.Body.Close()
				atomic.AddInt64(&probeStats.httpOK, 1)
				cfRay := strings.TrimSpace(resp.Header.Get("CF-RAY"))
				if cfRay != "" {
					parts := strings.Split(cfRay, "-")
					dc := strings.TrimSpace(parts[len(parts)-1])
					if dc != "" {
						fillLocation(&res, dc)
						atomic.AddInt64(&probeStats.cfRay, 1)
						return res, true
					}
				}
				server := strings.ToLower(resp.Header.Get("Server"))
				if strings.Contains(server, "cloudflare") || resp.Header.Get("Cf-Cache-Status") != "" {
					fillLocation(&res, "CF")
					atomic.AddInt64(&probeStats.cfHead, 1)
					return res, true
				}
				// 有 HTTP 响应但无 CF 特征：多半是运营商拦截页，走 TLS 兜底
				if tlsLooksLikeCF(ip, timeout) {
					fillLocation(&res, "TLS")
					atomic.AddInt64(&probeStats.tlsOK, 1)
					return res, true
				}
			}
		}
	}

	if looseAtomic.Load() {
		fillLocation(&res, "UNVERIFIED")
		return res, true
	}
	atomic.AddInt64(&probeStats.noCF, 1)
	return res, false
}

// ----------------------- /api/ips：全量 IP 导出 -----------------------

func handleIPsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	q := r.URL.Query()
	source := q.Get("source")
	if source == "" {
		source = "all"
	}
	format := strings.ToLower(q.Get("format"))
	dc := strings.TrimSpace(q.Get("dc"))

	scanMutex.Lock()
	scanCopy := append([]ScanResult(nil), scanResults...)
	scanMutex.Unlock()
	testResultsMu.Lock()
	testCopy := append([]TestResult(nil), testResults...)
	testResultsMu.Unlock()

	dcOf := make(map[string]string, len(scanCopy))
	for _, s := range scanCopy {
		dcOf[s.IP] = s.DataCenter
	}

	seen := make(map[string]bool)
	var ips []string
	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		if dc != "" && dcOf[ip] != dc {
			return
		}
		seen[ip] = true
		ips = append(ips, ip)
	}

	if source == "test" || source == "all" {
		for _, t := range testCopy { // 已按丢包率 / 延迟排序
			add(t.IP)
		}
	}
	if source == "scan" || source == "all" {
		sort.SliceStable(scanCopy, func(i, j int) bool {
			return scanCopy[i].TCPDuration < scanCopy[j].TCPDuration
		})
		for _, s := range scanCopy {
			add(s.IP)
		}
	}

	if format == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":  len(ips),
			"source": source,
			"dc":     dc,
			"ips":    ips,
		})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	stamp := time.Now().Format("20060102_1504")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cf_ips_%s.txt"`, stamp))
	if len(ips) == 0 {
		return
	}
	_, _ = w.Write([]byte(strings.Join(ips, "\n") + "\n"))
}

// ----------------------- /api/diag：网络与扫描自检 -----------------------

func handleDiagAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	scanMutex.Lock()
	scanCount := len(scanResults)
	scanMutex.Unlock()
	testResultsMu.Lock()
	testCount := len(testResults)
	testResultsMu.Unlock()

	resources := map[string]any{}
	for _, name := range []string{"ips-v4.txt", "ips-v6.txt", "locations.json"} {
		info := map[string]any{"exists": false, "lines": 0}
		if data, err := os.ReadFile(dataPath(name)); err == nil {
			info["exists"] = true
			info["bytes"] = len(data)
			info["lines"] = len(strings.Split(strings.TrimSpace(string(data)), "\n"))
		}
		resources[name] = info
	}

	// ?probe=1 时做一次小样本主动探测，用于真机定位「扫不到 IP」
	probe := map[string]any{"ran": false}
	if r.URL.Query().Get("probe") == "1" {
		content, err := os.ReadFile(dataPath("ips-v4.txt"))
		if err == nil {
			list := limitIPList(parseIPList(string(content)), 24)
			ips := getRandomIPv4s(list)
			beforeTCP := atomic.LoadInt64(&probeStats.tcpOK)
			beforeHTTP := atomic.LoadInt64(&probeStats.httpOK)
			beforeRay := atomic.LoadInt64(&probeStats.cfRay)
			beforeTLS := atomic.LoadInt64(&probeStats.tlsOK)
			var wg sync.WaitGroup
			sem := make(chan struct{}, 12)
			var okCount int64
			for _, ip := range ips {
				sem <- struct{}{}
				wg.Add(1)
				go func(target string) {
					defer func() { <-sem; wg.Done() }()
					if _, ok := probeCF(target); ok {
						atomic.AddInt64(&okCount, 1)
					}
				}(ip)
			}
			wg.Wait()
			probe = map[string]any{
				"ran":       true,
				"sample":    len(ips),
				"valid":     okCount,
				"tcp_ok":    atomic.LoadInt64(&probeStats.tcpOK) - beforeTCP,
				"http_ok":   atomic.LoadInt64(&probeStats.httpOK) - beforeHTTP,
				"cf_ray":    atomic.LoadInt64(&probeStats.cfRay) - beforeRay,
				"tls_other": atomic.LoadInt64(&probeStats.tlsOK) - beforeTLS,
			}
		} else {
			probe = map[string]any{"ran": false, "error": err.Error()}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"resources":    resources,
		"scan_results": scanCount,
		"test_results": testCount,
		"probe_stats": map[string]int64{
			"tcp_ok":  atomic.LoadInt64(&probeStats.tcpOK),
			"http_ok": atomic.LoadInt64(&probeStats.httpOK),
			"cf_ray":  atomic.LoadInt64(&probeStats.cfRay),
			"cf_head": atomic.LoadInt64(&probeStats.cfHead),
			"tls_ok":  atomic.LoadInt64(&probeStats.tlsOK),
			"no_cf":   atomic.LoadInt64(&probeStats.noCF),
		},
		"params": map[string]any{
			"timeout_ms": scanTimeoutAtomic.Load(),
			"sample":     sampleLimit(),
			"loose":      looseAtomic.Load(),
		},
		"probe":      probe,
		"goroutines": runtime.NumGoroutine(),
	})
}
