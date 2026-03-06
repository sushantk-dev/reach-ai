@echo off
REM Iteration 4 - Comprehensive Test
REM Compares EXPLOITABLE (with exploit demo) vs NOT_REACHABLE (without exploit demo)

echo ========================================================
echo ReachAI Iteration 4 - Comprehensive Exploit Demo Test
echo ========================================================
echo.

REM Check if Python service is running
echo [Step 1] Checking AI service health...
curl -s http://localhost:8001/health >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: AI service is not running on port 8001
    echo Please start: python main.py
    exit /b 1
)
echo ✓ AI service is healthy
echo.

echo ========================================================
echo TEST 1: EXPLOITABLE Vulnerability (Should Have Demo)
echo ========================================================
echo CVE: CVE-2019-14379 (Jackson Deserialization)
echo Status: Has call chains (3 steps)
echo.

curl -s -X POST http://localhost:8001/api/explain ^
  -H "Content-Type: application/json" ^
  -d @test_payload_not_reachable.json ^
  -o test2_exploitable.json

if %errorlevel% neq 0 (
    echo ERROR: Request failed
    exit /b 1
)

echo Response Analysis:
python -c "import json; d=json.load(open('test1_exploitable.json')); print(f\"  Verdict: {d.get('verdict')}\"); print(f\"  Confidence: {d.get('confidenceScore')}\"); print(f\"  Has Exploit Demo: {d.get('exploitDemo') is not None}\"); demo=d.get('exploitDemo', {}); print(f\"  Demo Sections: attackSetup={bool(demo.get('attackSetup'))}, httpRequest={bool(demo.get('httpRequest'))}, steps={len(demo.get('stepByStep', []))}, outcome={bool(demo.get('attackerOutcome'))}, unsafe={bool(demo.get('unsafeCode'))}, safe={bool(demo.get('safeCode'))}\")"

if %errorlevel% neq 0 (
    echo ERROR: Failed to analyze response
    exit /b 1
)

echo.
echo Exploit Demo Preview:
python -c "import json; d=json.load(open('test1_exploitable.json')); demo=d.get('exploitDemo', {}); print(f\"\n  Attack Setup:\n    {demo.get('attackSetup', 'N/A')[:150]}...\"); print(f\"\n  HTTP Request:\n    {demo.get('httpRequest', 'N/A')[:150]}...\"); steps=demo.get('stepByStep', []); print(f\"\n  Steps: {len(steps)} total\"); [print(f\"    {i+1}. {s[:80]}...\") for i, s in enumerate(steps[:2])]; print(f\"\n  Outcome:\n    {demo.get('attackerOutcome', 'N/A')[:150]}...\")"

echo.
echo ========================================================
echo TEST 2: NOT_REACHABLE Vulnerability (Should NOT Have Demo)
echo ========================================================
echo CVE: CVE-2021-44228 (Log4Shell)
echo Status: No call chains (0 steps)
echo.

curl -s -X POST http://localhost:8001/api/explain ^
  -H "Content-Type: application/json" ^
  -d @test_payload_not_reachable.json ^
  -o test2_not_reachable.json

if %errorlevel% neq 0 (
    echo ERROR: Request failed
    exit /b 1
)

echo Response Analysis:
python -c "import json; d=json.load(open('test2_not_reachable.json')); print(f\"  Verdict: {d.get('verdict')}\"); print(f\"  Confidence: {d.get('confidenceScore')}\"); print(f\"  Has Exploit Demo: {d.get('exploitDemo') is not None}\"); print(f\"  Explanation: {d.get('plainEnglishExplanation', 'N/A')[:100]}...\")"

if %errorlevel% neq 0 (
    echo ERROR: Failed to analyze response
    exit /b 1
)

echo.
echo ========================================================
echo Summary
echo ========================================================
echo.
echo Test 1 (EXPLOITABLE):
echo   File: test1_exploitable.json
echo   Expected: Verdict=EXPLOITABLE, Has exploit demo
echo.
echo Test 2 (NOT_REACHABLE):
echo   File: test2_not_reachable.json
echo   Expected: Verdict=NOT_REACHABLE, No exploit demo
echo.
echo ✓ All tests completed!
echo.
echo To view full responses:
echo   type test1_exploitable.json
echo   type test2_not_reachable.json
echo.
pause