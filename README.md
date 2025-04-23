## Test #1: TCPPort Scanner
### Purpose: this program demonstrates a concurrent TCP port scanner that checks for open ports on a target host

###  Port Scanner: Files
- main.go

### Features

- Concurrent scanning with configurable worker count
- Automatic retry with exponential backoff
- Banner grabbing for service identification
- Real-time progress tracking
- Support for both port ranges and specific ports
- Configurable timeouts
- 
### Insatallation
1. Create an executable file.
    ```bash
     go build -o scanner main.go
    ```
2. Run the resulting executable.
   ```bash
    ./scanner
    ```
### Usage
- Scan default ports (1-1024) on a target:
     ```cpp
    ./scanner -target scanme.nmap.org
    ```
- Scan specific ports
    ```cpp
    ./scanner -target scanme.nmap.org
    ```
- Scan custom port range
    ```cpp
    ./scanner -target localhost -start 8000 -end 9000
- Advanced options
    ```
## References
  - LLM: DeepSeek, for tutoring, learning necessary concepts, and for guidance when needed.
  

  
  
### Link to Video
[Watch demo here](https://www.youtube.com/watch?v=SGlCMrzM6J8)   
