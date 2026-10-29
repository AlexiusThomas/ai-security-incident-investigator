
import json
import py_compile
from pathlib import Path

base = Path(__file__).parent

json_files = [
    "event.json",
    "iam-policy.json",
    "aws-events.json"
]

python_files = [
    "detect.py",
    "iam_analyzer.py",
    "aws_detector.py"
]

passed = 0

for name in json_files:
    try:
        with (base / name).open(encoding="utf-8-sig") as file:
            json.load(file)
        print(f"PASS JSON: {name}")
        passed += 1
    except (OSError, ValueError) as error:
        print(f"FAIL JSON: {name} - {error}")

for name in python_files:
    try:
        py_compile.compile(str(base / name), doraise=True)
        print(f"PASS PYTHON: {name}")
        passed += 1
    except (OSError, py_compile.PyCompileError) as error:
        print(f"FAIL PYTHON: {name} - {error}")

print(f"CHECKS PASSED: {passed}/6")
