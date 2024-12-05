## Assignment: Log Analysis Script

### **Objective**

The goal of this assignment is to assess your ability to write a Python script that processes log files to extract and analyze key information. This assignment evaluates your proficiency in **file handling**, **string manipulation**, and **data analysis**, which are essential skills for cybersecurity-related programming tasks.

---

### **Core Requirements**

Your Python script should implement the following functionalities:

1. **Count Requests per IP Address**:
    - Parse the provided log file to extract all IP addresses.
    - Calculate the number of requests made by each IP address.
    - Sort and display the results in descending order of request counts.
    - Example output:
        
        ```bash
        IP Address           Request Count
        192.168.1.1          234
        203.0.113.5          187
        10.0.0.2             92
        ```
        
2. **Identify the Most Frequently Accessed Endpoint**:
    - Extract the endpoints (e.g., URLs or resource paths) from the log file.
    - Identify the endpoint accessed the highest number of times.
    - Provide the endpoint name and its access count.
    - Example output:
        
        ```bash
        Most Frequently Accessed Endpoint:
        /home (Accessed 403 times)
        ```
        
3. **Detect Suspicious Activity**:
    - Identify potential brute force login attempts by:
        - Searching for log entries with failed login attempts (e.g., HTTP status code `401` or a specific failure message like "Invalid credentials").
        - Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
    - Display the flagged IP addresses and their failed login counts.
    - Example output:
        
        ```less
        Suspicious Activity Detected:
        IP Address           Failed Login Attempts
        192.168.1.100        56
        203.0.113.34         12
        ```
        
4. **Output Results**:
    - Display the results in a clear, organized format in the terminal.
    - Save the results to a CSV file named `log_analysis_results.csv` with the following structure:
        - **Requests per IP**: Columns: `IP Address`, `Request Count`
        - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
        - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`

---

## Approaches
### **Naive Approach**

**Usage**: 
`$ python naiveanalyze.py [-h] [-t THRESHOLD] [-o OUTPUTFILE] logfile`

THRESHOLD = 10, OUTPUTFILE = log_analysis_results.csv by default

**Example**:
`$ python naiveanalyze.py -t 15 -o output.csv sample.log`

1. Get the threshold value from the command line argument
2. Go through each line of the log file and parse it using regex 
3. Take the parsed data and analyze it
4. Analyzing it involves: counting the requests of the IPs, collecting the failed login attempts and endpoint access count where Counter and defaultdict are used
5. Displaying the data analysis and Writing it to a CSV file

##### Limitations
1. Everything is done in a single thread synchronously
2. File read which is a I/O bound task will block the CPU until it is read (in case of readlines()), here it is iterating using `line in file` if it's a large file
3. Multiple cores/processors aren't utilized (horizontal scaling)

##### Ideas that may improve
1. Use multiprocessing or threading (though GIL or context switching might)
2. Use Async I/O
3. Buffering/Chunking
4. Check if regex is a bottleneck and split and other approaches could benefit

### **Multi processing**
1. Check if there are more than 1 core
2. If file size is large enough, use a shared queue where chunks of lines are put 
3. Each core's process gets the chunk from the queue and does local analysis and places it in a global results queue
4. After all the chunks are read, the results queue is collected and combined
