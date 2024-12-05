import random

info = []

ip_addresses = [
    "41.248.92.165",
    "196.21.8.175",
    "194.133.66.134",
    "77.74.82.100",
]

request_counts = {ip: random.randint(1000, 1500) for ip in ip_addresses}
info.append("request counts: " + str(request_counts))


endpoints = [
    "/home",
    "/",
    "/about",
    "/feedback",
    "/dashboard"
]

failed_logins = {ip: random.randint(10, 50) for ip in random.sample(ip_addresses, 2)}
info.append("failed logins: " + str(failed_logins))


endpoint_accesses = {endpoint: 0 for endpoint in endpoints}
endpoint_accesses["/login"] = 0

# 192.168.1.100 - - [03/Dec/2024:10:12:54 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
def make_line(ip, fail):
    endpoint = "/login" if fail else random.choice(endpoints)
    endpoint_accesses[endpoint] += 1
    method = "POST" if fail else "GET"
    code = 401 if fail else 200
    line = f'{ip} - - [03/Dec/2024:10:12:54 +0000] "{method} {endpoint} HTTP/1.1" {code} 128 "{"Invalid credentials" if fail else ""}"'
    return line 

with open("test.log", "w") as file:
    n = 0
    while len(request_counts.keys()):  
        ip = random.choice(tuple(request_counts.keys()))
        request_counts[ip] -= 1
        if request_counts[ip] <= 0:
            del request_counts[ip]        
        fail = False
        if ip in failed_logins:
            fail = True
            failed_logins[ip] -= 1
            if failed_logins[ip] <= 0: del failed_logins[ip]

        line = make_line(ip, fail)
        n += 1
        # print("written line:", line)
        file.write(line + "\n")

print("Generated test log")
print(f"written {n} lines")
info.append("endpoint accesses: " + str(endpoint_accesses))
print('\n'.join(info))
with open("test.txt", "w") as file:
    file.write("\n".join(info))