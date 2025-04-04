// Purpose: this program demonstrates a concurrent TCP port scanner that checks for open ports on a target host
// with retry logic and exponential backoff for failed attempts

package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// Worker func handles port scanning
func worker(wg *sync.WaitGroup, tasks chan string, dialer net.Dialer) {
	defer wg.Done()	// Signal done when worker func exits
	maxRetries := 3	// Max retry attempts

	// Process each address from tasks channel
    for addr := range tasks {
		var success bool	// Tracks connection success

		// maxRetry loop
		for i := range maxRetries {     
			conn, err := dialer.Dial("tcp", addr)	//Attempt tcp connection 

			if err == nil {	// Conection successful
				conn.Close()	// Close connection
				fmt.Printf("Connection to %s was successful\n", addr)
				success = true
				break	// Exit retry loop
			
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

	var wg sync.WaitGroup

	// Buffered channel for port scanning tasks (capacity: 100)
	tasks := make(chan string, 100)

	// Target host for scanning
    target := "scanme.nmap.org"

	// Network dialer with timeout
	dialer := net.Dialer {
		Timeout: 5 * time.Second,
	}
  
	// Concurrent workers
	workers := 100

	// Launch worker goroutines
    for i := 1; i <= workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, dialer)
	}

	// Ports to scan (1-512)
	ports := 512

	// Generate scanning tasks for each port
	for p := 1; p <= ports; p++ {
		port := strconv.Itoa(p)	// Convert port num to str
        address := net.JoinHostPort(target, port)
		tasks <- address	// Send addr. to workers via channel
	}

	// Close task channel
	close(tasks)

	// Wait for all workers to complete
	wg.Wait()

	// Program exits when all scanning is done
}
