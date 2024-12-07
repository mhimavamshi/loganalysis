from concurrent.futures import ProcessPoolExecutor
from math import floor
import multiprocessing.pool
import re
from collections import Counter
import argparse
import csv
import multiprocessing
import os
# import mmap
# import line_profiler

class Parser:

    def __init__(self):
        self.pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\S+" (?P<status>\d{3}) (?P<bytes>\d+)(?: "(?P<message>.*?)")?')

    def parse(self, line: str) -> dict:
        '''
        Uses a precompiled regex and generates a dictionary of the ip address, date, method, endpoint, status, bytes, and message
        '''
        match = re.match(self.pattern, line)
        return match.groupdict()
    
    def lightweight_parse(self, line: str) -> tuple:
        '''
        IP address, endpoint and message are parsed from a line using split, join and array indexing
        '''

        parts = line.split()
        ip = parts[0]
        endpoint = parts[6]
        message = ' '.join(parts[10:]) if len(parts) > 10 else ""
        return ip, endpoint, message.strip('"')


class Analyzer:
    def __init__(self, threshold):
        self.parser = Parser()
        self.threshold = threshold
        self.request_count = Counter() 
        self.endpoint_accesses = Counter() 
        self.failed_logins = Counter() 

    # @line_profiler.profile
    def _figure_out_lines(self, lines, num_of_cores, size, scale_factor=4, min_lines=5_00_000, max_lines=1_00_00_000): 
        '''
        Depending on number of cores, previously sent lines and queue size, a new number of lines to be "chunked" is returned.

        If the queue size is less than the number of cores - number of lines are decreased depending on scale factor so lines can be read faster and put in the queue
        If the queue size is more than the number of cores - number of lines are increased depending on scale factor so reading them would be slower and queue size is maintained 
        '''
        
        if size < num_of_cores:
            return max(lines // scale_factor, min_lines) 
        return min(int(lines * scale_factor), max_lines)

    # @line_profiler.profile
    def _read_file_chunks(self, file_path, shared_queue: multiprocessing.Queue):
        '''
        File is read out in chunks i.e. a group of lines and put in the shared_queue so it can be processed.
        
        Number of lines is figured out during execution
        '''

        num_of_cores = multiprocessing.cpu_count()
        initial_lines = 50_00_000
        with open(file_path, "r") as file:
            while True:
                num_of_lines = self._figure_out_lines(initial_lines, num_of_cores, shared_queue.qsize())
                # print(f"INFO: Adding {num_of_lines} lines...")
                lines = file.readlines(num_of_lines)
                if len(lines) == 0:
                    break
                shared_queue.put(lines)
                # num_of_lines = num


    # @line_profiler.profile
    def _process_chunk(self, shared_queue, results_queue):
        '''
        A chunk of lines are taken from the shared queue, and "locally" processed using counters to get request count, endpoint accesses and failed logins
        The counters are put into the results queue
        '''

        local_request_count = Counter() 
        local_endpoint_accesses = Counter()   
        local_failed_logins = Counter()

        while True:
            lines = shared_queue.get()
            if lines is None: break
            for line in lines:

                ip, endpoint, message = self.parser.lightweight_parse(line)

                local_request_count[ip] += 1


                local_endpoint_accesses[endpoint] += 1

                if message == '': continue

                if endpoint == "/login" and message == "Invalid credentials": 
                    local_failed_logins[ip] += 1

        results_queue.put([local_request_count, local_endpoint_accesses, local_failed_logins])
        
    # @line_profiler.profile    
    def _collect_results(self, results_queue):
        '''
        From the results queue the "locally" processed counters are taken/collected and the global counters of request count, endpoint accesses and failed logins are updated
        '''
        while not results_queue.empty():
            data = results_queue.get()
            self.request_count.update(data[0])
            self.endpoint_accesses.update(data[1])
            self.failed_logins.update(data[2])

    # @line_profiler.profile
    def _pool_collect_results(self, result):
        '''
        Updates the global counters from a result of the map operation using a process pool
        '''
        self.request_count.update(result[0])
        self.endpoint_accesses.update(result[1])
        self.failed_logins.update(result[2])


    # @line_profiler.profile
    def _pool_read_file_chunks(self, file_path, chunk_size):
        '''
        Reads a fixed chunk of lines from the file and returns it; Used as a generator
        '''
        with open(file_path, "r") as file:
            while True:
                lines = file.readlines(chunk_size)
                if not lines:
                    break
                yield lines


    # @line_profiler.profile
    def _pool_process_chunk(self, chunk):
        '''
        Processes a chunk of line and returns a counter of request counts, endpoint accesses and failed logins
        '''

        local_request_count = Counter()
        local_endpoint_accesses = Counter() 
        local_failed_logins = Counter()  

        for line in chunk:
            ip, endpoint, message = self.parser.lightweight_parse(line)

            local_request_count[ip] += 1

            local_endpoint_accesses[endpoint] += 1

            if endpoint == "/login" and message == "Invalid credentials": 
                local_failed_logins[ip] += 1

        return [local_request_count, local_endpoint_accesses, local_failed_logins]

    # @line_profiler.profile
    def multiprocess_analyze_pool(self, file_path, return_data):
        '''
        Uses ProcessPoolExecutor to parallely map a chunk processing function to chunks of lines in file_path
        Returns the data in a dictionary if needed
        '''
        
        print("INFO: Using pool")
        chunks = self._pool_read_file_chunks(file_path, chunk_size=5_00_000)  

        with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
            results = executor.map(self._pool_process_chunk, chunks) 

            for result in results:
                self._pool_collect_results(result)

        if return_data:
            return {
                "requests": dict(self.request_count),
                "endpointaccesses": dict(self.endpoint_accesses),
                "failedlogins": dict(self.failed_logins),
            }

    # @line_profiler.profile
    def multiprocess_analyze(self, file_path, return_data):
        '''
        Uses multiprocessing to parallely parse and retrieve the endpoint accesses, request counts, and failed login information from the file_path.
        Returns the data as dictionary if needed
        Uses Queues to share data among processes and collects the local data into global data
        '''

        print("INFO: Using a shared queue")

        shared_queue = multiprocessing.Queue()
        results_queue = multiprocessing.Queue()

        num_analyzers = multiprocessing.cpu_count()


        processes = []

        for _ in range(num_analyzers):
            process = multiprocessing.Process(target=self._process_chunk, args=(shared_queue, results_queue))
            processes.append(process)
            process.start()

        self._read_file_chunks(file_path, shared_queue)
        
        for _ in range(num_analyzers):
            shared_queue.put(None)
        
        for process in processes: process.join()

        self._collect_results(results_queue)

        if return_data:
            return {'requests': dict(self.request_count), 'endpointaccesses': dict(self.endpoint_accesses), 'failedlogins': dict(self.failed_logins)}

    
    def is_big_file(self, file_path):
        '''
        Returns true if the provided file is greater than 10 MB 
        '''
        return os.path.getsize(file_path) > 10 * 1024 * 1024 
    
    # @line_profiler.profile
    def single_analyze_dynamic(self, file_path, return_data):
        '''
        Reads the file in chunks of lines and parses and retrieves the request counts, endpoint accesses, failed logins.
        Returns the data if needed.
        Adjusts the chunk size dynamically based on processing time 
        '''

        import time
        try:
            print("INFO Using single core, and dynamic chunking")  
            with open(file_path, "r") as file:
                chunk_size = 1_00_000
                prev_time = 1
                factor = 22
                reduction = 2

                min_chunks = 5_00_000
                max_chunks = 1_00_00_000

                while chunk := file.readlines(floor(chunk_size)):
                    start = time.time()

                    for line in chunk: 

                        ip, endpoint, message = self.parser.lightweight_parse(line)

                        self.request_count[ip] += 1


                        self.endpoint_accesses[endpoint] += 1


                        if message == '': continue

                        if endpoint == "/login" and message == "Invalid credentials": 
                            self.failed_logins[ip] += 1
                    
                    end = time.time()
                    if end - start < prev_time: 
                        chunk_size = min(chunk_size * factor, max_chunks) 
                    else: 
                        chunk_size = max(chunk_size / factor, min_chunks)
                        factor = max(factor / reduction, 1)

                    # print(f"Chunk size: {chunk_size}, factor: {factor}, curr: {end-start}, prev: {prev_time}")
                    prev_time = end - start

                if return_data:
                    return {'requests': dict(self.request_count), 'endpointaccesses': dict(self.endpoint_accesses), 'failedlogins': dict(self.failed_logins)}
        
        except FileNotFoundError:
            print(f"ERROR: provided log file {file_path} not found")
            return
            
        except PermissionError:
            print(f"ERROR: permission denied for the provided log file {file_path}")
            return                


   
    # @line_profiler.profile
    def single_analyze(self, file_path, return_data, chunk_size=7_00_000):
        '''
        Reads the file in chunks of lines and parses and retrieves the request counts, endpoint accesses, failed logins.
        Returns the data if needed.
        '''
        try:
            print("INFO: Using single core")  
            with open(file_path, "r") as file:
                while chunk := file.readlines(floor(chunk_size)):

                    for line in chunk: 

                        ip, endpoint, message = self.parser.lightweight_parse(line)

                        self.request_count[ip] += 1


                        self.endpoint_accesses[endpoint] += 1


                        if message == '': continue

                        if endpoint == "/login" and message == "Invalid credentials": 
                            self.failed_logins[ip] += 1


                if return_data:
                    return {'requests': dict(self.request_count), 'endpointaccesses': dict(self.endpoint_accesses), 'failedlogins': dict(self.failed_logins)}
        
        except FileNotFoundError:
            print(f"ERROR: provided log file {file_path} not found")
            return
            
        except PermissionError:
            print(f"ERROR: permission denied for the provided log file {file_path}")
            return      


    # @line_profiler.profile
    def analyze_file(self, file_path, return_data=False, multi=True):
        '''
        Depending on the file size and number of cores available, single or multi processing is chosen and request counts, endpoint accesses and failed logins are retrieved from the file.
        The retrieved data is stored in the object attributes - request_counts, endpoint_accesses and failed_logins 
        '''
        pool = False

        if multiprocessing.cpu_count() > 1 and self.is_big_file(file_path) and multi:
            print("INFO: Using multiprocessing")
            if pool: return self.multiprocess_analyze_pool(file_path, return_data)
            return self.multiprocess_analyze(file_path, return_data)

        return self.single_analyze(file_path, return_data)    

    def print(self):
        '''
        Pretty prints the retrieved data to the console
        '''

        print(f"INFO: Using threshold for suspicious logins: {self.threshold}")
        print()


        print("IP Address\tRequest Count")
        sorted_request_counts = self.request_count.most_common()
        for ip, requests in sorted_request_counts:
            print(f"{ip}\t{requests}")
        print()

        print("Most Frequently Accessed Endpoint:")

        endpoint, accesses = self.endpoint_accesses.most_common(1)[0]
        print(f"{endpoint} Accessed {accesses} times")
        print()
        
        print("Suspicious Activity Detected:")
        print("IP Address\tFailed Login Attempts")

        failed_logins = [(ip, failed_attempts) for ip, failed_attempts in self.failed_logins.most_common() if failed_attempts > self.threshold]

        if failed_logins:
            for ip, failed_attempts in failed_logins: print(f"{ip}\t{failed_attempts}")  
        else:
            print()
            print(f"No suspicious activity detected (threshold: {self.threshold})")

        # empty = True
        # for ip, failed_attempts in self.failed_logins.most_common():
        #     if failed_attempts > self.threshold: 
        #         empty = False
        #         print(f"{ip}\t{failed_attempts}")
        # if empty: print(f"No suspicious activity detected (threshold: {self.threshold})")


    
    def _write_request_count(self, writer):
        # writer.writerow(["Requests per IP"])
        '''
        Writes the request counts using writer
        '''
        writer.writerow([])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in self.request_count.items():
            writer.writerow([ip, count])
        writer.writerow([])

    def _write_endpoint_accesses(self, writer):
        '''
        Writes the endpoint accesses using writer
        '''
        # writer.writerow(["Most Accessed Endpoint"])
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        endpoint, count = self.endpoint_accesses.most_common(1)[0]
        writer.writerow([endpoint, count])
        writer.writerow([])

    def _write_failed_logins(self, writer):
        '''
        Writes the failed login attempts using writer
        '''
        # writer.writerow(["Suspicious Activity"])
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in self.failed_logins.items():
            if count > self.threshold:
                writer.writerow([ip, count])       

    def write_to_csv(self, file_path):
        '''
        Writes the retrieved data to the CSV file at file_path
        '''

        with open(file_path, mode="w", newline="\n") as csvfile:
            writer = csv.writer(csvfile)

            self._write_request_count(writer)

            self._write_endpoint_accesses(writer)

            self._write_failed_logins(writer)
    




def main():
    argparser = argparse.ArgumentParser(description="Analyze server logs and generate a csv file.")
    argparser.add_argument("logfile", help="Path to the log file")


    argparser.add_argument("-t", "--threshold", type=int, default=10, help="Threshold for suspicious logins")
    argparser.add_argument("-o", "--outputfile", type=str, default='log_analysis_results.csv', help="CSV file the data must be written to")
    
    args = argparser.parse_args()


    log_file_path = args.logfile
    threshold = args.threshold
    csv_file_path = args.outputfile

    analyzer = Analyzer(threshold=threshold)

    raw_data = analyzer.analyze_file(log_file_path, return_data=True, multi=True)

    # print(raw_data)
    
    analyzer.print()

    analyzer.write_to_csv(csv_file_path)
    print()
    print(f"Data successfully written to {csv_file_path}")

    # testing = False
    # if testing:
    #     import json
    #     with open("output.json", "w") as file:
    #         json.dump(raw_data, file)
    #     print("INFO: output written to output.json")
    
if __name__ == "__main__":
    main()
