package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

var (
	logPath       = flag.String("log-path", "/var/log/osquery", "Path to osquery log directory")
	nodeName      = flag.String("node-name", "", "Node name (auto-detected if empty)")
	namespace     = flag.String("namespace", "osquery-system", "Namespace for QueryResult CRs")
	batchSize     = flag.Int("batch-size", 100, "Number of results to batch before creating events")
	flushInterval = flag.Duration("flush-interval", 10*time.Second, "How often to flush results to K8s events")
)

// OsqueryResult represents a single osquery result log entry
type OsqueryResult struct {
	Name           string              `json:"name"`
	HostIdentifier string              `json:"hostIdentifier"`
	CalendarTime   string              `json:"calendarTime"`
	UnixTime       int64               `json:"unixTime"`
	Epoch          int64               `json:"epoch"`
	Counter        int64               `json:"counter"`
	Decorations    map[string]string   `json:"decorations"`
	Columns        map[string]string   `json:"columns,omitempty"`
	DiffResults    *DiffResults        `json:"diffResults,omitempty"`
	Snapshot       []map[string]string `json:"snapshot,omitempty"`
	Action         string              `json:"action,omitempty"`
}

type DiffResults struct {
	Added   []map[string]string `json:"added,omitempty"`
	Removed []map[string]string `json:"removed,omitempty"`
}

// Sink interface for different result destinations
type Sink interface {
	Send(ctx context.Context, results []OsqueryResult) error
	Close() error
}

// KubernetesSink ships results as K8s Events and QueryResult CRs
type KubernetesSink struct {
	clientset *kubernetes.Clientset
	nodeName  string
	namespace string
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *nodeName == "" {
		*nodeName = getNodeName()
	}

	klog.Infof("Starting k8s-event-bridge on node %s", *nodeName)
	klog.Infof("Log path: %s", *logPath)

	sink, err := NewKubernetesSink(*nodeName, *namespace)
	if err != nil {
		klog.Fatalf("Failed to create Kubernetes sink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	processor := NewResultProcessor(*logPath, sink)

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		klog.Info("Received shutdown signal")
		cancel()
	}()

	if err := processor.Start(ctx); err != nil && err != context.Canceled {
		klog.Fatalf("Processor error: %v", err)
	}

	klog.Info("k8s-event-bridge stopped")
}

func NewKubernetesSink(nodeName, namespace string) (*KubernetesSink, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return &KubernetesSink{
		clientset: clientset,
		nodeName:  nodeName,
		namespace: namespace,
	}, nil
}

func (s *KubernetesSink) Send(ctx context.Context, results []OsqueryResult) error {
	for _, result := range results {
		if !s.shouldCreateEvent(result) {
			continue
		}

		event := &corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("osquery-%s-%d", result.Name, result.UnixTime),
				Namespace: s.namespace,
			},
			InvolvedObject: corev1.ObjectReference{
				Kind:      "Node",
				Name:      s.nodeName,
				Namespace: s.namespace,
			},
			Reason:  "OsqueryResult-" + result.Name,
			Message: formatResultMessage(result),
			Type:    "Normal",
			Source: corev1.EventSource{
				Component: "k8s-event-bridge",
				Host:      s.nodeName,
			},
			FirstTimestamp: metav1.Time{Time: time.Unix(result.UnixTime, 0)},
			LastTimestamp:  metav1.Time{Time: time.Unix(result.UnixTime, 0)},
			Count:          1,
		}

		_, err := s.clientset.CoreV1().Events(s.namespace).Create(ctx, event, metav1.CreateOptions{})
		if err != nil {
			klog.Errorf("Failed to create event: %v", err)
		}
	}

	return nil
}

func (s *KubernetesSink) shouldCreateEvent(result OsqueryResult) bool {
	if result.Action == "" {
		if result.DiffResults == nil {
			return false
		}
		if len(result.DiffResults.Added) == 0 && len(result.DiffResults.Removed) == 0 {
			return false
		}
	}

	rowCount := len(result.Columns)
	if result.Snapshot != nil {
		rowCount = len(result.Snapshot)
	} else if result.DiffResults != nil {
		rowCount = len(result.DiffResults.Added) + len(result.DiffResults.Removed)
	}
	if rowCount == 0 && result.Action != "removed" {
		return false
	}

	return true
}

func (s *KubernetesSink) Close() error {
	return nil
}

func formatResultMessage(result OsqueryResult) string {
	var rows []map[string]string

	switch {
	case result.Snapshot != nil:
		rows = result.Snapshot
	case result.DiffResults != nil:
		rows = append(rows, result.DiffResults.Added...)
		rows = append(rows, result.DiffResults.Removed...)
	case result.Columns != nil:
		rows = []map[string]string{result.Columns}
	}

	if len(rows) == 0 {
		return "Query '" + result.Name + "' returned no results"
	}

	msg := fmt.Sprintf("Query '%s' returned %d rows", result.Name, len(rows))
	if len(rows) > 0 {
		sample, _ := json.Marshal(rows[0])
		if len(sample) > 200 {
			sample = append(sample[:200], []byte("...")...)
		}
		msg += ". Sample: " + string(sample)
	}

	return msg
}

// ResultProcessor handles reading and shipping osquery results
type ResultProcessor struct {
	logPath string
	sink    Sink
	results chan OsqueryResult
	done    chan struct{}
}

func NewResultProcessor(logPath string, sink Sink) *ResultProcessor {
	return &ResultProcessor{
		logPath: logPath,
		sink:    sink,
		results: make(chan OsqueryResult, 1000),
		done:    make(chan struct{}),
	}
}

func (p *ResultProcessor) Start(ctx context.Context) error {
	go p.shipResults(ctx)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	if err := watcher.Add(p.logPath); err != nil {
		return fmt.Errorf("failed to watch path: %w", err)
	}

	resultFile := filepath.Join(p.logPath, "osqueryd.results.log")
	if _, err := os.Stat(resultFile); err == nil {
		go p.tailFile(ctx, resultFile)
	}

	for {
		select {
		case <-ctx.Done():
			close(p.done)
			return ctx.Err()

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			_ = event

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			klog.Errorf("Watcher error: %v", err)
		}
	}
}

func (p *ResultProcessor) tailFile(ctx context.Context, path string) {
	file, err := os.Open(path) //nolint:gosec // G304: path comes from internal filepath.Join, not user input
	if err != nil {
		klog.Errorf("Failed to open file %s: %v", path, err)
		return
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Seek(0, 2); err != nil {
		klog.Errorf("Failed to seek file %s: %v", path, err)
		return
	}

	klog.Infof("Tailing file %s", path)
	reader := bufio.NewReader(file)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			line = line[:len(line)-1]
			if line == "" {
				continue
			}

			var result OsqueryResult
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				klog.Errorf("Failed to parse result: %v", err)
				continue
			}

			klog.V(2).Infof("Read result: %s", result.Name)

			select {
			case p.results <- result:
			default:
				klog.Warning("Result channel full, dropping result")
			}
		}
	}
}

func (p *ResultProcessor) shipResults(ctx context.Context) {
	batch := make([]OsqueryResult, 0, *batchSize)
	ticker := time.NewTicker(*flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}

		var lastErr error
		for attempt := range 3 {
			if err := p.sink.Send(ctx, batch); err != nil {
				lastErr = err
				backoff := time.Duration(1<<attempt) * time.Second // 1s, 2s, 4s
				klog.Warningf("Failed to ship results (attempt %d/3): %v, retrying in %v", attempt+1, err, backoff)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
					continue
				}
			}
			lastErr = nil
			break
		}

		if lastErr != nil {
			klog.Errorf("Failed to ship results after 3 attempts: %v", lastErr)
		}

		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return

		case <-p.done:
			flush()
			return

		case result := <-p.results:
			batch = append(batch, result)
			if len(batch) >= *batchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

func getNodeName() string {
	if name := os.Getenv("NODE_NAME"); name != "" {
		return name
	}
	if name, err := os.Hostname(); err == nil {
		return name
	}
	return "unknown"
}
