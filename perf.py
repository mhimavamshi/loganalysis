import time
from loganalyzer import Analyzer 
import argparse
import os

def benchmark_analyzer(file_path, threshold, multi=True):
    analyzer = Analyzer(threshold=threshold)

    start_time = time.perf_counter()
    print("Running Pool Method...")
    _ = analyzer.multiprocess_analyze_pool(file_path, return_data=True)
    pool_time = time.perf_counter() - start_time
    print(f"Pool Method executed in {pool_time:.4f} seconds")

    start_time = time.perf_counter()
    print("Running Shared Queue Method...")
    _ = analyzer.multiprocess_analyze(file_path, return_data=True)
    shared_queue_time = time.perf_counter() - start_time
    print(f"Shared Queue Method executed in {shared_queue_time:.4f} seconds")

    start_time = time.perf_counter()
    print("Running Single Core Method...")
    _ = analyzer.single_analyze(file_path, return_data=True)
    single_time = time.perf_counter() - start_time
    print(f"Single core Method executed in {single_time:.4f} seconds")


    start_time = time.perf_counter()
    print("Running Single Core dynamic Method...")
    _ = analyzer.single_analyze_dynamic(file_path, return_data=True)
    single_dynamic_time = time.perf_counter() - start_time
    print(f"Single core dynamic Method executed in {single_dynamic_time:.4f} seconds")


    print("\nPerformance Comparison:")
    print(f"Pool Method: {pool_time:.4f} seconds")
    print(f"Shared Queue Method: {shared_queue_time:.4f} seconds")
    print(f"Single core Method: {single_time: .4f} seconds")
    print(f"Single core dynamic Method: {single_dynamic_time: .4f} seconds")
    
def parse_args():
    argparser = argparse.ArgumentParser(description="Benchmark multiprocessing methods for log analysis.")
    argparser.add_argument("logfile", help="Path to the log file")
    argparser.add_argument("-t", "--threshold", type=int, default=10, help="Threshold for suspicious logins")
    args = argparser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()


    def human_readable_size(size, decimal_places=2):
        for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']:
            if size < 1024.0 or unit == 'PiB':
                break
            size /= 1024.0
        return f"{size:.{decimal_places}f} {unit}"

    print(f"File size is: {human_readable_size(os.path.getsize(args.logfile))}")

    benchmark_analyzer(args.logfile, threshold=args.threshold)
