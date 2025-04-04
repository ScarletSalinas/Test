package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type scanResults struct {
	mu       sync.Mutex
	target   string
	Ports    []int
	Count    int
	Duration time.Duration
}

func (r *scanResults) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	sort.Ints(r.Ports)
	if len(r.Ports) == 0 {
		return fmt.Sprintf("\nScan Results\n-----------\nTarget: %s\nNo open ports found\nDuration: %s\n",
			r.target, r.Duration.Round(time.Millisecond))
	}

	return fmt.Sprintf(
		"\nScan Results\n"+
			"------------------\n"+
			"Target: %s\n"+
			"Open ports: %v\n"+
			"Total open: %d\n"+
			"Duration: %s\n",
		r.target, r.Ports, r.Count, r.Duration.Round(time.Millisecond))
}

func parseTargets(input string) []string {
	targets := []string{}
	if input != "" {
		raw := strings.Split(input, ",")
		for _, t := range raw {
			if t = strings.TrimSpace(t); t != "" {
				targets = append(targets, t)
			}
		}
	}
	if len(targets) == 0 {
		targets = append(targets, "scanme.nmap.org")
	}
	return targets
}

func parsePorts(input string) ([]int, error) {
	if input == "" {
		return nil, nil
	}

	var ports []int
	for _, portStr := range strings.Split(input, ",") {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port number %q", portStr)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return ""
		}
		return ""
	}
	return strings.TrimSpace(string(buffer[:n]))
}

func worker(ctx context.Context, wg *sync.WaitGroup, tasks chan string, dialer net.Dialer,
	results map[string]*scanResults, completedTasks *int32) {
	defer wg.Done()
	maxRetries := 3

	for {
		select {
		case addr, ok := <-tasks:
			if !ok {
				return
			}

			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid address %q: %v\n", addr, err)
				atomic.AddInt32(completedTasks, 1)
				continue
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid port number %q: %v\n", portStr, err)
				atomic.AddInt32(completedTasks, 1)
				continue
			}

			var success bool
			for i := 0; i < maxRetries; i++ {
				conn, err := dialer.Dial("tcp", addr)
				if err == nil {
					banner := grabBanner(conn, dialer.Timeout/2)
					conn.Close()

					if banner != "" {
						fmt.Printf("Banner for %s:%d: %s\n", host, port, banner)
					}

					results[host].mu.Lock()
					results[host].Ports = append(results[host].Ports, port)
					results[host].Count++
					results[host].target = host
					results[host].mu.Unlock()

					fmt.Printf("%s - port %d is open\n", host, port)
					success = true
					break
				}

				backoff := time.Duration(1<<i) * time.Second
				fmt.Printf("Attempt %d to %s failed. Waiting %v...\n", i+1, addr, backoff)
				time.Sleep(backoff)
			}

			if !success {
				fmt.Printf("Failed to connect to %v after %d attempts\n", addr, maxRetries)
			}
			atomic.AddInt32(completedTasks, 1)

		case <-ctx.Done():
			return
		}
	}
}

func main() {
	target := flag.String("target", "", "Single host to scan (overrides -targets)")
	targets := flag.String("targets", "scanme.nmap.org", "Comma-separated host list")
	startPort := flag.Int("start", 1, "First port in range")
	endPort := flag.Int("end", 1024, "Last port in range")
	timeout := flag.Duration("timeout", 5*time.Second, "connection timeout per port")
	workers := flag.Int("workers", 100, "Number of workers")
	portsList := flag.String("ports", "", "Comma-separated list of ports to scan (overrides -start and -end)")

	flag.Parse()

	// Parse ports list if provided
	var portsToScan []int
	if *portsList != "" {
		var err error
		portsToScan, err = parsePorts(*portsList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
			return
		}
	} else {
		// Validate port range
		if *startPort < 1 || *endPort > 65535 || *startPort > *endPort {
			fmt.Fprintf(os.Stderr, "Invalid port range. Must be between 1-65535 and start <= end\n")
			return
		}
		
		// Generate ports from range
		for port := *startPort; port <= *endPort; port++ {
			portsToScan = append(portsToScan, port)
		}
	}

	// Determine targets
	var targetList []string
	if *target != "" {
		targetList = []string{*target}
	} else {
		targetList = parseTargets(*targets)
	}

	// Initialize results with start time
	results := make(map[string]*scanResults)
	startTimes := make(map[string]time.Time)
	for _, t := range targetList {
		results[t] = &scanResults{target: t}
		startTimes[t] = time.Now()
	}

	// Calculate total number of tasks
	totalTasks := len(targetList) * len(portsToScan)
	var completedTasks int32

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Progress indicator
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				completed := atomic.LoadInt32(&completedTasks)
				progress := float64(completed) / float64(totalTasks) * 100
				fmt.Fprintf(os.Stderr, "\rProgress: %.2f%% (%d/%d)", progress, completed, totalTasks)
			case <-ctx.Done():
				fmt.Fprintf(os.Stderr, "\n")
				return
			}
		}
	}()

	dialer := net.Dialer{Timeout: *timeout}
	tasks := make(chan string, *workers)
	var wg sync.WaitGroup

	// Launch workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, tasks, dialer, results, &completedTasks)
	}

	// Submit tasks in separate goroutine
	go func() {
		defer close(tasks)
		for _, currentTarget := range targetList {
			for _, port := range portsToScan {
				select {
				case tasks <- net.JoinHostPort(currentTarget, strconv.Itoa(port)):
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Wait for completion
	wg.Wait()
	cancel()

	// Print final results
	fmt.Println("\n=== SCAN COMPLETE ===")
	for target, res := range results {
		res.Duration = time.Since(startTimes[target])
		fmt.Println(res.String())
	}
}