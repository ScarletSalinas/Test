// Purpose: this program demonstrates a concurrent TCP port scanner that checks for open ports on a target host
// Target host for scanning: scanme.nmap.org
// with retry logic and exponential backoff for failed attempts

package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scan Summary
type scanResults struct {
	mu       sync.Mutex
	target   string    // Stores scanned host
	Ports    []int     // Stores port nums
	Count    int       // Total port count
	Duration time.Duration // Stores scan time
}

// Func to print scan summary results
func (r *scanResults) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	sort.Ints(r.Ports)
	if len(r.Ports) == 0 {
		return "No ports found"
	}

	return fmt.Sprintf(
		"\nScan Results\n"+
			"-----------\n"+
			"Target: %s\n"+
			"Open ports: %v\n"+
			"Total open: %d\n"+
			"Duration: %s\n",
		r.target, r.Ports, r.Count, r.Duration.Round(time.Millisecond))
}

// Func to separate comma list into individual target strings
func parseTargets(input string) []string {
	targets := []string{} // Initialize empty slice

	// Process input
	if input != "" {
		raw := strings.Split(input, ",") // Split by comma
		for _, t := range raw {          // Clean each split
			if t = strings.TrimSpace(t); t != "" {
				targets = append(targets, t)
			}
		}
	}

	// Apply default target if no other valid found
	if len(targets) == 0 {
		targets = append(targets, "scanme.nmap.org")
	}
	return targets
}

// Worker func handles port scanning
func worker(wg *sync.WaitGroup, tasks chan string, dialer net.Dialer, results map[string]*scanResults, maxRetries int) {
	defer wg.Done() // Signal done when worker func exits

	// Process each address from tasks channel
	for addr := range tasks {
		// Error handling for invalid address + port number
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			fmt.Printf("Invalid address %q: %v\n", addr, err)
			continue
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			fmt.Printf("Invalid port number %q: %v\n", portStr, err)
			continue
		}

		var success bool
		for i := 0; i < maxRetries; i++ { // Retry loop
			conn, err := dialer.Dial("tcp", addr) // Attempt tcp connection

			if err == nil { // Connection successful
				conn.Close() // Close connection
				fmt.Printf("Connection to %s was successful\n", addr)
				success = true

				results[host].mu.Lock()
				results[host].Ports = append(results[host].Ports, port)
				results[host].Count++
				results[host].mu.Unlock()

				fmt.Printf("%s - port %d is open\n", host, port)
				break // Exit retry loop
			}

			// Calculate exponential backoff
			backoff := time.Duration(1<<i) * time.Second
			fmt.Printf("Attempt %d to %s failed. Waiting %v...\n", i+1, addr, backoff)

			time.Sleep(backoff) // Wait before retrying
		}

		// Report if all attempts failed
		if !success {
			fmt.Printf("Failed to connect to %s:%d after %d attempts\n", host, port, maxRetries)
		}
	}
}

func main() {
	// command-line flags
	target := flag.String("target", "", "Single host to scan (overrides -targets)")
	targets := flag.String("targets", "scanme.nmap.org", "Comma-separated host list")
	startPort := flag.Int("start", 1, "First port in range")
	endPort := flag.Int("end", 1024, "Last port in range")
	timeout := flag.Duration("timeout", 5*time.Second, "connection timeout per port")
	workers := flag.Int("workers", 100, "Number of workers")
	maxRetries := flag.Int("retries", 3, "Max retry attempts")
	flag.Parse()

	// Validate port range
	if *startPort < 1 || *endPort > 65535 || *startPort > *endPort {
		fmt.Println("Invalid port range")
		return
	}

	// Determine targets
	var targetList []string
	if *target != "" {
		targetList = []string{*target}
	} else {
		targetList = parseTargets(*targets)
	}

	// Initialize results with start times
	results := make(map[string]*scanResults)
	startTimes := make(map[string]time.Time)
	for _, t := range targetList {
		t = strings.TrimSpace(t)
		results[t] = &scanResults{target: t}
		startTimes[t] = time.Now() // Record start time for each target
	}

	// Network dialer with timeout
	dialer := net.Dialer{Timeout: *timeout}

	// Buffered channel for port scanning tasks (capacity: workers)
	tasks := make(chan string, *workers)
	var wg sync.WaitGroup

	// Launch worker goroutines
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, dialer, results, *maxRetries)
	}

	// Generate scanning tasks for each target
	for currentTarget := range results {
		fmt.Printf("\nScanning %s (ports %d-%d)\n", currentTarget, *startPort, *endPort)
		for p := *startPort; p <= *endPort; p++ {
			tasks <- net.JoinHostPort(currentTarget, strconv.Itoa(p))
		}
	}
	close(tasks)

	// Wait for all workers to complete
	wg.Wait()

	// Calculate durations and print results
	for target, result := range results {
		result.Duration = time.Since(startTimes[target])
		fmt.Println(result)
	}
}
