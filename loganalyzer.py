from concurrent.futures import ProcessPoolExecutor
import multiprocessing.pool
import re
from collections import Counter
import argparse
import csv
import multiprocessing
import os
import mmap
import line_profiler

class Parser:

    def __init__(self):
        self.pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\S+" (?P<status>\d{3}) (?P<bytes>\d+)(?: "(?P<message>.*?)")?')

    def parse(self, line: str) -> dict:
        match = re.match(self.pattern, line)
        return match.groupdict()
    
    def lightweight_parse(self, line: str) -> tuple:
        try:
            parts = line.split()
            ip = parts[0]
            endpoint = parts[6]
            message = ' '.join(parts[10:]) if len(parts) > 10 else ""
            return ip, endpoint, message.strip('"')
        except (IndexError, ValueError):
            return None


class Analyzer:
    def __init__(self, threshold):
        self.parser = Parser()
        self.threshold = threshold
        self.request_count = Counter() 
        self.endpoint_accesses = Counter() 
        self.failed_logins = Counter() 

    def _figure_out_lines(self, lines, size):
        if size < 50:
            return lines * 2
        return lines

    @line_profiler.profile
    def _read_file_chunks(self, file_path, shared_queue: multiprocessing.Queue, num_of_lines = 50000):
        with open(file_path, "r") as file:
            while True:
                # num_of_lines = self._figure_out_lines(num_of_lines, shared_queue.qsize())
                # num_of_lines = num
                lines = file.readlines(num_of_lines)
                if len(lines) == 0:
                    break
                shared_queue.put(lines)

    def _process_chunk(self, shared_queue, results_queue):
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
        
    @line_profiler.profile    
    def _collect_results(self, results_queue):
        while not results_queue.empty():
            data = results_queue.get()
            self.request_count.update(data[0])
            self.endpoint_accesses.update(data[1])
            self.failed_logins.update(data[2])

    @line_profiler.profile
    def _pool_collect_results(self, result):
        self.request_count.update(result[0])
        self.endpoint_accesses.update(result[1])
        self.failed_logins.update(result[2])


    @line_profiler.profile
    def _pool_read_file_chunks(self, file_path, chunk_size):
        with open(file_path, "r") as file:
            while True:
                lines = file.readlines(chunk_size)
                if not lines:
                    break
                yield lines


    @line_profiler.profile
    def _pool_process_chunk(self, chunk):
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

    @line_profiler.profile
    def multiprocess_analyze_pool(self, file_path, return_data):
        print("Using pool")
        chunks = self._pool_read_file_chunks(file_path, chunk_size=8_00_000)  

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

    @line_profiler.profile
    def multiprocess_analyze(self, file_path, return_data):
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
        return os.path.getsize(file_path) > 1024 * 1024
    
    @line_profiler.profile
    def analyze_file(self, file_path, return_data=False, multi=True):

        if multiprocessing.cpu_count() > 1 and self.is_big_file(file_path) and multi:
            print("Using multiprocessing")
            return self.multiprocess_analyze_pool(file_path, return_data)
        
        try:
            print("Using single core")
            with open(file_path, "r") as file:
                chunk_size = 10000
                while chunk := file.readlines(chunk_size):
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

    def print(self):

        print(f"Using threshold for suspicious logins: {self.threshold}")
        print()


        print("IP Address\tRequest Count")
        for ip, requests in self.request_count.items():
            print(f"{ip}\t{requests}")
        print()

        print("Most Frequently Accessed Endpoint:")

        endpoint, accesses = self.endpoint_accesses.most_common(1)[0]
        print(f"{endpoint} Accessed {accesses} times")
        print()
        
        print("Suspicious Activity Detected:")
        print("IP Address\tFailed Login Attempts")
        
        
        for ip, failed_attempts in self.failed_logins.items():
            if failed_attempts > self.threshold: print(f"{ip}\t{failed_attempts}")
    
    def _write_request_count(self, writer):
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in self.request_count.items():
            writer.writerow([ip, count])
        writer.writerow([])

    def _write_endpoint_accesses(self, writer):
        writer.writerow(["Endpoint", "Access Count"])
        endpoint, count = self.endpoint_accesses.most_common(1)[0]
        writer.writerow([endpoint, count])
        writer.writerow([])

    def _write_failed_logins(self, writer):
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in self.failed_logins.items():
            if count > self.threshold:
                writer.writerow([ip, count])       

    def write_to_csv(self, file_path):
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

    raw_data = analyzer.analyze_file(log_file_path, return_data=True, multi=False)

    print(raw_data)
    
    analyzer.print()

    analyzer.write_to_csv(csv_file_path)
    print()
    print(f"Data successfully written to {csv_file_path}")

    testing = True
    if testing:
        import json
        with open("output.json", "w") as file:
            json.dump(raw_data, file)
        print("output written to output.json")
    
if __name__ == "__main__":
    main()
