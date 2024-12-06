import json

with open("test.json") as file:
    a = json.load(file)

import subprocess

subprocess.run(["python", "loganalyzer.py", "test.log", "-o", "test.csv"])

with open("output.json") as file:
    b = json.load(file)

print("Test.json:")
print(a)
print("Output.json:")
print(b)
print()
print("Matches:", a == b)

