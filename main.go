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
	"sync"
	"time"
)

type scanResults struct {
	mu sync.Mutex
	target string	// Stores scanned host
	Ports []int	// Stores port nums
	Count int	// Total port count
	Duration time.Duration // Stores scan time
}

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
		for i := range maxRetries {     
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
	target := flag.String("target","scanme.nmap.org", "Hostname or IP address to scan")
	startPort := flag.Int("start", 1, "First port in range")
	endPort := flag.Int("end", 1024, "Last port in range")
	timeout := flag.Duration("timeout", 5*time.Second, "connection timeout in seconds")
	workers := flag.Int("workers", 100, "Number of workers")

	flag.Parse()

	results := &scanResults{target: *target}
	var wg sync.WaitGroup
	startTime := time.Now()
	tasks := make(chan string, *workers)	// Buffered channel for port scanning tasks (capacity: 100)

	// Network dialer with timeout
	dialer := net.Dialer {
		Timeout: *timeout,
	}

	// Launch worker goroutines
    for i := 1; i <= *workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, dialer, results)
	}

	// Generate scanning tasks for each port
	for p := *startPort; p <= *endPort; p++ {
		port := strconv.Itoa(p)	// Convert port num to str
        address := net.JoinHostPort(*target, port)
		tasks <- address	// Send addr. to workers via channel
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
