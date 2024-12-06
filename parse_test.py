import timeit

current_parser_code = """
def lightweight_parse(line):
    try:
        parts = line.split()
        ip = parts[0]
        endpoint = parts[6]
        message = ' '.join(parts[10:]) if len(parts) > 10 else ""
        return ip, endpoint, message.strip('"')
    except (IndexError, ValueError):
        return None
"""

optimized_parser_code = """
def lightweight_parse(line):
    try:
        ip_end = line.find(' ')
        ip = line[:ip_end]

        start_endpoint = line.find(' ', ip_end + 1)
        for _ in range(4):
            start_endpoint = line.find(' ', start_endpoint + 1)
        end_endpoint = line.find(' ', start_endpoint + 1)
        endpoint = line[start_endpoint + 1:end_endpoint]

        message_start = line.find('"', end_endpoint + 1)
        if message_start != -1:
            message_end = line.rfind('"')
            message = line[message_start + 1:message_end].strip('"')
        else:
            message = ""

        return ip, endpoint, message
    except (IndexError, ValueError):
        return None
"""

regex_parser = """
import re
pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\S+" (?P<status>\d{3}) (?P<bytes>\d+)(?: "(?P<message>.*?)")?')

def parse(line: str) -> dict:
    match = re.match(pattern, line)
    return match.groupdict()
"""

# Benchmark the improved parser
improved_code = """
def lightweight_parse(line: str) -> tuple:
    try:
        ip_end = line.index(' ')
        ip = line[:ip_end]

        start_endpoint = ip_end + 1
        for _ in range(5):
            start_endpoint = line.index(' ', start_endpoint + 1)
        end_endpoint = line.index(' ', start_endpoint + 1)
        endpoint = line[start_endpoint + 1:end_endpoint]

        message_start = line.find('"', end_endpoint + 1)
        if message_start != -1:
            message_end = line.rfind('"')
            message = line[message_start + 1:message_end]
        else:
            message = ""

        return ip, endpoint, message
    except ValueError:
        return None
"""

sample_line = '127.0.0.1 - - [10/Dec/2024:13:55:36 +0000] "GET /login HTTP/1.1" 401 210 "Invalid credentials"'

# Benchmark
current_time = timeit.timeit('lightweight_parse(sample_line)', setup=current_parser_code, globals=globals(), number=100000)
optimized_time = timeit.timeit('lightweight_parse(sample_line)', setup=optimized_parser_code, globals=globals(), number=100000)
regex_time = timeit.timeit('parse(sample_line)', setup=regex_parser, globals=globals(), number=100000)
time = timeit.timeit('lightweight_parse(sample_line)', setup=improved_code, globals=globals(), number=100000)


print(f"Current Parser: {current_time:.6f} seconds")
print(f"Optimized Parser: {optimized_time:.6f} seconds")
print(f"Regex Parser: {regex_time:.6f} seconds")
print(f"Improved Parser: {time:.6f} seconds")




