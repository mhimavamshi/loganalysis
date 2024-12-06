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
