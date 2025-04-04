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
	mu sync.Mutex
	target string	// Stores scanned host
	Ports []int	// Stores port nums
	Count int	// Total port count
	Duration time.Duration // Stores scan time
}

// Func to separate comma list into individual target strings
func parseTargets(input string) []string {
	targets := []string{}	// Initialize empty slice

	// Process input
	if input != "" {
		raw := strings.Split(input, ",")	// Split by comma
		for _, t:= range raw {	// Clean each split
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

// Func to print scan summary results
func (r *scanResults) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	sort.Ints(r.Ports)
	return fmt.Sprintf(
		"\nScan Summary\n"+
		"-----------------\n"+
		"Target: %s\n"+
		"Open ports %v\n"+
		"Total open: %d\n"+
		"Duration: %s\n",
		r.target, r.Ports, r.Count, r.Duration.Round(time.Millisecond))
}

// Worker func handles port scanning
func worker(wg *sync.WaitGroup, tasks chan string, dialer net.Dialer, results *scanResults) {
	defer wg.Done()	// Signal done when worker func exits
	maxRetries := 3	// Max retry attempts

	// Process each address from tasks channel
    for addr := range tasks {

		// Error handling for ivalid address + port number
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
		for i := range maxRetries {  	// Retry loop   
			conn, err := dialer.Dial("tcp", addr)	//Attempt tcp connection 

			if err == nil {	// Conection successful
				conn.Close()	// Close connection
				fmt.Printf("Connection to %s was successful\n", addr)
				success = true
				results.mu.Lock()
                results.Ports = append(results.Ports, port)
                results.Count++

                results.mu.Unlock()
				fmt.Printf("%s - port %d is open\n", host, port)
				break	// Exit retry loop
			
			}

			if success { 
				results.mu.Lock()
				results.Ports = append(results.Ports, port)
				results.Count++
				results.mu.Unlock()
			}

			// Calculate expon. backoff
			backoff := time.Duration(1<<i) * time.Second
			fmt.Printf("Attempt %d to %s failed. Waiting %v...\n", i+1,  addr, backoff)

			time.Sleep(backoff)	// Wait before retrying
	    }

		// Report if all attempts failed
		if !success {
			fmt.Printf("Failed to connect to %s after %d attempts\n", addr, maxRetries)
		}
	}
}

func main() {

	// command-line flags
	target  := flag.String("target", "", "Single host to scan (overrides -targets)")
	targets := flag.String("targets", "scanme.nmap.org", "Comma-separated host list")
	startPort := flag.Int("start", 1, "First port in range")
	endPort := flag.Int("end", 1024, "Last port in range")
	timeout := flag.Duration("timeout", 5*time.Second, "connection timeout per port")
	workers := flag.Int("workers", 100, "Number of workers")

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
	
	dialer := net.Dialer{Timeout: *timeout}	// Network dialer with timeout
	var wg sync.WaitGroup
	results := &scanResults{target: *target}
	startTime := time.Now()
	tasks := make(chan string, *workers)	// Buffered channel for port scanning tasks (capacity: 100)


	// Launch worker goroutines
    for i := 1; i <= *workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, dialer, results)
	}

	
	for _, target := range targetList {
		target = strings.TrimSpace(target)
		fmt.Printf("\nScanning %s (ports %d-%d)\n", target, *startPort, *endPort)
		// Generate tasks for THIS target
		for p := *startPort; p <= *endPort; p++ {
			tasks <- net.JoinHostPort(target, strconv.Itoa(p))
		}
	}

	// Close task channel
	close(tasks)

	// Wait for all workers to complete
	wg.Wait()

	// Calculate scan time
	results.mu.Lock()
	results.Duration = time.Since(startTime)
	results.mu.Unlock()

	// Print Summary
	fmt.Printf("\n%s\n", results)

	// Program exits when all scanning is done
}
