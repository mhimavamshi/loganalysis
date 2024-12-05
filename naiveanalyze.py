import re
from collections import Counter, defaultdict
import argparse
import csv
import multiprocessing
import os

class Parser:

    def __init__(self):

        # pre-compile regex pattern

        self.pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\S+" (?P<status>\d{3}) (?P<bytes>\d+)(?: "(?P<message>.*?)")?')

    def parse(self, line: str) -> dict:

        # use the regex pattern to match and make a dictionary

        match = re.match(self.pattern, line)
        return match.groupdict()
    
class Analyzer:
    def __init__(self, threshold):
        self.parser = Parser()
        self.threshold = threshold
        self.request_count = Counter() # counter object to keep track of ip addresses and number of requests made
        self.endpoint_accesses = Counter() # counter object to keep track of endpoints and number of accesses to each 
        # self.failed_logins = defaultdict(int) # dictionary to keep track of ip addresses and number of failed logins made
        self.failed_logins = Counter()

    def _read_file_chunks(self, file_path, shared_queue, num_of_lines = 50000):
        with open(file_path, "r") as file:
            while True:
                lines = file.readlines(num_of_lines)
                # print(f"read {len(lines)} lines and put on queue")
                if len(lines) == 0:
                    break
                shared_queue.put(lines)

    def _process_chunk(self, shared_queue, results_queue):
        local_request_count = Counter() # counter object to keep track of ip addresses and number of requests made
        local_endpoint_accesses = Counter() # counter object to keep track of endpoints and number of accesses to each 
        local_failed_logins = Counter() # dictionary to keep track of ip addresses and number of failed logins made

        while True:
            lines = shared_queue.get()
            if lines is None: break
            # print(f"{multiprocessing.current_process()}: processing {len(lines)} lines that i got on queue")
            for line in lines:

                data = self.parser.parse(line)

                if data is None: 
                    # print(f"WARNING: failed to parse f{line}")
                    continue

                local_request_count[data['ip']] += 1


                local_endpoint_accesses[data['endpoint']] += 1

                if data['message'] == '': continue

                # print(f"Got data: {data}") 

                if data['endpoint'] == "/login" and data['message'] == "Invalid credentials": 
                    local_failed_logins[data['ip']] += 1
                    # print(f"Failed login: {data['ip']} detected")

        results_queue.put([local_request_count, local_endpoint_accesses, local_failed_logins])

        # what if we do collect results in real time too? 
        
    def _collect_results(self, results_queue):
        while not results_queue.empty():
            data = results_queue.get()
            self.request_count.update(data[0])
            self.endpoint_accesses.update(data[1])
            self.failed_logins.update(data[2])

    def multiprocess_analyze(self, file_path, return_data):
        shared_queue = multiprocessing.Queue()
        results_queue = multiprocessing.Queue()

        num_analyzers = multiprocessing.cpu_count()

        processes = []

        for _ in range(num_analyzers):
            process = multiprocessing.Process(target=self._process_chunk, args=(shared_queue, results_queue))
            processes.append(process)
            process.start()

        # print(processes)
        
        self._read_file_chunks(file_path, shared_queue)
        
        for _ in range(num_analyzers):
            shared_queue.put(None)
        
        for process in processes: process.join()

        self._collect_results(results_queue)

        if return_data:
            return {'requests': dict(self.request_count), 'endpointaccesses': dict(self.endpoint_accesses), 'failedlogins': dict(self.failed_logins)}

    
    def is_big_file(self, file_path):
        return os.path.getsize(file_path) > 1024 * 1024

    def analyze_file(self, file_path, return_data=False, multi=True):
        if multiprocessing.cpu_count() > 1 and self.is_big_file(file_path) and multi:
            print("Using multiprocessing")
            return self.multiprocess_analyze(file_path, return_data)
        try:
            with open(file_path, "r") as file:

                # iterate through the lines in the file

                for line in file: 

                    # parse the file and make a dict

                    data = self.parser.parse(line)

                    # in case there's no match (invalid data) report and continue to next line

                    if data is None: 
                        print(f"WARNING: failed to parse f{line}")
                        continue
                    
                    # increment the number of requests made by the ip

                    self.request_count[data['ip']] += 1

                    # increment the number of accesses made to the endpoint

                    self.endpoint_accesses[data['endpoint']] += 1

                    # if message is absent, continue to next line

                    if data['message'] == '': continue

                    # print(f"Found suspicious login: {data}")

                    # if the endpoint is /login and message is "invalid credentials"
                    # then increment the number of failed logins for the ip

                    if data['endpoint'] == "/login" and data['message'] == "Invalid credentials": 
                        self.failed_logins[data['ip']] += 1

                if return_data:
                    return {'requests': dict(self.request_count), 'endpointaccesses': dict(self.endpoint_accesses), 'failedlogins': dict(self.failed_logins)}
        
        # handle the file not found error

        except FileNotFoundError:
            print(f"ERROR: provided log file {file_path} not found")
            return
            
        # handle not having the permissions to read the file

        except PermissionError:
            print(f"ERROR: permission denied for the provided log file {file_path}")
            return        

    def print(self):
    # display the threshold being used

        print(f"Using threshold for suspicious logins: {self.threshold}")
        print()

        # display the request counts for each ip address

        print("IP Address\tRequest Count")
        for ip, requests in self.request_count.items():
            print(f"{ip}\t{requests}")
        print()

        # display the most accessed endpoint

        print("Most Frequently Accessed Endpoint:")

        # one way is to get the max element from the counter using max() function and key that selects the second element i.e. number of accesses
        # endpoint, accesses = max(endpoint_accesses.items(), key=lambda entry: entry[1])
        
        # or use the function provided by counter of most_common() that takes in number of most common elements to return based on value as a tuple in a list
        
        endpoint, accesses = self.endpoint_accesses.most_common(1)[0]
        print(f"{endpoint} Accessed {accesses} times")
        print()

        # display any failed login attempts if present 
        
        print("Suspicious Activity Detected:")
        print("IP Address\tFailed Login Attempts")
        
        # go through the ip addresses and number of failed logins made
        
        for ip, failed_attempts in self.failed_logins.items():
            # if the number of failed logins exceed a threshold then display it 
            if failed_attempts > self.threshold: print(f"{ip}\t{failed_attempts}")
    
    def _write_request_count(self, writer):
        # Write IP Request Counts
        # writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in self.request_count.items():
            writer.writerow([ip, count])
        writer.writerow([])

    def _write_endpoint_accesses(self, writer):
        # Write Most Accessed Endpoint
        # writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        endpoint, count = self.endpoint_accesses.most_common(1)[0]
        writer.writerow([endpoint, count])
        writer.writerow([])

    def _write_failed_logins(self, writer):
        # Write Suspicious Activity (Failed Logins)
        # writer.writerow(["Suspicious Activity"])
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

    # set the threshold to 10 by default

    argparser.add_argument("-t", "--threshold", type=int, default=10, help="Threshold for suspicious logins")
    argparser.add_argument("-o", "--outputfile", type=str, default='log_analysis_results.csv', help="CSV file the data must be written to")
    
    args = argparser.parse_args()

    # get the parsed log file and threshold (if not provided, it's 10)

    log_file_path = args.logfile
    threshold = args.threshold
    csv_file_path = args.outputfile

    # Make an analyzer object with the given threshold
    analyzer = Analyzer(threshold=threshold)

    # assign the returned data to raw_data if necessary
    raw_data = analyzer.analyze_file(log_file_path, return_data=True)

    print(raw_data)
    
    # use the analyzer's pretty print function to show the analyzed data
    analyzer.print()

    # write the data to the csv file provided
    analyzer.write_to_csv(csv_file_path)
    print()
    print(f"Data successfully written to {csv_file_path}")
    
if __name__ == "__main__":
    main()
