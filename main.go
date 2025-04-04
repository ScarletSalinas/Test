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

	// Apply default target if no other valid one found
	if len(targets) == 0 {
		targets = append(targets, "scanme.nmap.org")
	}
	return targets
}


// Worker func handles port scanning
func worker(wg *sync.WaitGroup, tasks chan string, dialer net.Dialer, results map[string] *scanResults) {
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

		port, err := strconv.Atoi(portStr) // Convert port string to int
        if err != nil {
            fmt.Printf("Invalid port number %q: %v\n", portStr, err)
            continue
        }

		var success bool 
		for i := 0; i < maxRetries; i++ {  	// Retry loop   
			// Retry loop   
			conn, err := dialer.Dial("tcp", addr)	//Attempt tcp connection 

			if err == nil {	// Conection successful
				conn.Close()	// Close connection
				fmt.Printf("Connection to %s was successful\n", addr)
				success = true

				// Grab banner
				banner := grabBanner(conn)
				if banner != "" {
					fmt.Printf("Banner for %s:%d: %s\n", host, port, banner)
				} else {
					fmt.Printf("No banner found for %s:%d\n", host, port)
				}
				
				results[host].mu.Lock()  // Lock the mutex

				// Perform updates
				results[host].Ports = append(results[host].Ports, port)
				results[host].Count++
				results[host].target = host

				results[host].mu.Unlock()  // Unlock the mutex


				fmt.Printf("%s - port %d is open\n", host, port)
				break	// Exit retry loop
			
			}

			// Calculate exponential backoff
			backoff := time.Duration(1<<i) * time.Second
			fmt.Printf("Attempt %d to %s failed. Waiting %v...\n", i+1, addr, backoff)

			time.Sleep(backoff)	// Wait before retrying
	    }

		// Report if all attempts failed
		if !success {
			fmt.Printf("Failed to connect to %v after %d attempts\n", addr, maxRetries)
		}
	}
}

// Grabber func to try to read and print the initial response from the server
func grabBanner(conn net.Conn) string {
	// Set a timeout for reading banner
	conn.SetReadDeadline(time.Now().Add(2*time.Second))

	buffer := make([]byte, 1024)	// Buffer to hold data
	n, err := conn.Read(buffer)
	if err != nil {
		// If data can't be read or timeout, return empty str
		if err.Error() == "i/o timeout" {
			fmt.Printf("Error reading banner: %v\n", err)
		}
		return ""
	}
	// Return the banner as a string
	return string(buffer[:n])
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

	sort.Strings(targetList)  // Added sorting for consistent target scanning order

	// Initialize results with start time
	results:= make(map[string]*scanResults)
	startTimes := make(map[string]time.Time) // Initialize startTimes map
	for _, t := range targetList {
		results[t] = &scanResults{target: t}	//Initialize with target
		startTimes[t] = time.Now()	// Record start time for each target
	}
	
	dialer := net.Dialer{Timeout: *timeout}	// Network dialer with timeout
	tasks := make(chan string, *workers)	// Buffered channel for port scanning tasks (capacity: 100)
	var wg sync.WaitGroup


	// Launch worker goroutines
    for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, dialer, results)
	}

	// Process targets
	for currentTarget, _ := range results {
        for port := *startPort; port <= *endPort; port++ {
            tasks <- net.JoinHostPort(currentTarget, strconv.Itoa(port))
        }
    }

    close(tasks)

    wg.Wait()

    // Print results
    for currentTarget, res := range results {
		res.Duration = time.Since(startTimes[currentTarget])
		fmt.Println(res)
    }
}

