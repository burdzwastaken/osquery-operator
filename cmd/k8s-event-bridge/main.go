package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	osqueryv1alpha1 "github.com/burdzwastaken/osquery-operator/api/v1alpha1"
)

var (
	logPath            = flag.String("log-path", "/var/log/osquery", "Path to osquery log directory")
	nodeName           = flag.String("node-name", "", "Node name (auto-detected if empty)")
	namespace          = flag.String("namespace", "osquery-system", "Namespace for QueryResult CRs")
	batchSize          = flag.Int("batch-size", 100, "Number of results to batch before creating events")
	flushInterval      = flag.Duration("flush-interval", 10*time.Second, "How often to flush results to K8s events")
	createEvents       = flag.Bool("create-events", true, "Create Kubernetes Events for query results")
	createQueryResults = flag.Bool("create-query-results", false, "Create QueryResult CRs for query results")

	invalidLabelChars = regexp.MustCompile(`[^a-z0-9-]`)
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
	clientset          *kubernetes.Clientset
	crClient           client.Client
	nodeName           string
	namespace          string
	createEvents       bool
	createQueryResults bool
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *nodeName == "" {
		*nodeName = getNodeName()
	}

	klog.Infof("Starting k8s-event-bridge on node %s", *nodeName)
	klog.Infof("Log path: %s", *logPath)
	klog.Infof("Create Events: %v, Create QueryResults: %v", *createEvents, *createQueryResults)

	sink, err := NewKubernetesSink(*nodeName, *namespace, *createEvents, *createQueryResults)
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

func NewKubernetesSink(nodeName, namespace string, createEvents, createQueryResults bool) (*KubernetesSink, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	sink := &KubernetesSink{
		clientset:          clientset,
		nodeName:           nodeName,
		namespace:          namespace,
		createEvents:       createEvents,
		createQueryResults: createQueryResults,
	}

	if createQueryResults {
		scheme := runtime.NewScheme()
		if err := osqueryv1alpha1.AddToScheme(scheme); err != nil {
			return nil, fmt.Errorf("failed to add osquery scheme: %w", err)
		}

		crClient, err := client.New(config, client.Options{Scheme: scheme})
		if err != nil {
			return nil, fmt.Errorf("failed to create CR client: %w", err)
		}
		sink.crClient = crClient
	}

	return sink, nil
}

func (s *KubernetesSink) Send(ctx context.Context, results []OsqueryResult) error {
	var errs []error

	for _, result := range results {
		if s.createEvents && s.shouldCreateEvent(result) {
			if err := s.createEvent(ctx, result); err != nil {
				errs = append(errs, err)
			}
		}

		if s.createQueryResults {
			if err := s.createQueryResult(ctx, result); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func (s *KubernetesSink) createEvent(ctx context.Context, result OsqueryResult) error {
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "osquery-" + result.Name + "-" + strconv.FormatInt(result.UnixTime, 10),
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

	if _, err := s.clientset.CoreV1().Events(s.namespace).Create(ctx, event, metav1.CreateOptions{}); err != nil {
		klog.Errorf("Failed to create event: %v", err)
		return err
	}

	return nil
}

func (s *KubernetesSink) createQueryResult(ctx context.Context, result OsqueryResult) error {
	rows := s.extractRows(result)
	action := s.determineAction(result)
	packName, queryName := parseQueryName(result.Name)

	crName := fmt.Sprintf("%s-%s-%d-%d", s.nodeName, sanitizeName(result.Name), result.UnixTime, result.Counter)
	if len(crName) > 63 {
		crName = crName[:63]
	}

	qr := &osqueryv1alpha1.QueryResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crName,
			Namespace: s.namespace,
			Labels: map[string]string{
				"osquery.burdz.net/node":  s.nodeName,
				"osquery.burdz.net/query": sanitizeName(queryName),
			},
		},
		Spec: osqueryv1alpha1.QueryResultSpec{
			QueryName:   queryName,
			PackName:    packName,
			NodeName:    s.nodeName,
			Timestamp:   metav1.Time{Time: time.Unix(result.UnixTime, 0)},
			Action:      action,
			Rows:        rows,
			Decorations: result.Decorations,
		},
	}

	if packName != "" {
		qr.Labels["osquery.burdz.net/pack"] = sanitizeName(packName)
	}

	if err := s.crClient.Create(ctx, qr); err != nil {
		klog.Errorf("Failed to create QueryResult CR: %v", err)
		return err
	}

	klog.V(2).Infof("Created QueryResult CR %s for query %s", crName, result.Name)
	return nil
}

func (s *KubernetesSink) extractRows(result OsqueryResult) []map[string]string {
	switch {
	case result.Snapshot != nil:
		return result.Snapshot
	case result.DiffResults != nil:
		rows := make([]map[string]string, 0, len(result.DiffResults.Added)+len(result.DiffResults.Removed))
		rows = append(rows, result.DiffResults.Added...)
		rows = append(rows, result.DiffResults.Removed...)
		return rows
	case result.Columns != nil:
		return []map[string]string{result.Columns}
	default:
		return nil
	}
}

func (s *KubernetesSink) determineAction(result OsqueryResult) string {
	if result.Snapshot != nil {
		return "snapshot"
	}
	if result.Action != "" {
		return result.Action
	}
	if result.DiffResults != nil {
		if len(result.DiffResults.Added) > 0 {
			return "added"
		}
		if len(result.DiffResults.Removed) > 0 {
			return "removed"
		}
	}
	return "snapshot"
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

// parseQueryName extracts pack name and query name from osquery's naming convention.
// osquery uses format: "pack_<packname>_<queryname>" for pack queries.
func parseQueryName(name string) (packName, queryName string) {
	if strings.HasPrefix(name, "pack_") {
		parts := strings.SplitN(name, "_", 3)
		if len(parts) >= 3 {
			return parts[1], parts[2]
		}
	}
	return "", name
}

func sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = invalidLabelChars.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-")
	if len(name) > 63 { // Kubernetes label value limit
		name = name[:63]
		name = strings.TrimRight(name, "-")
	}
	return name
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
