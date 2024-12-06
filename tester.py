import json

with open("test.json") as file:
    a = json.load(file)

import subprocess

name = "loganalyzer.py"

print("running", name)

subprocess.run(["python", name, "test.log", "-o", "test.csv"])

with open("output.json") as file:
    b = json.load(file)

print("Test.json:")
print(a)
print("Output.json:")
print(b)
print()
print("Matches:", a == b)

from loganalyzer import Parser

p = Parser()

print(p.lightweight_parse('192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"'))
print(p.lightweight_parse('198.51.100.23 - - [03/Dec/2024:10:12:49 +0000] "POST /feedback HTTP/1.1" 200 128'))

