@echo off
REM Test script for AI Explanation Service (Iteration 3)
REM This script verifies that the AI service is properly integrated

setlocal enabledelayedexpansion

echo ==========================================
echo ReachAI Iteration 3 Verification
echo AI Explanation Service Testing
echo ==========================================
echo.

set TESTS_PASSED=0
set TESTS_FAILED=0

REM Function to print test results
goto :main

:print_result
if %1 EQU 0 (
    echo [92m✓ PASS[0m: %~2
    set /a TESTS_PASSED+=1
) else (
    echo [91m✗ FAIL[0m: %~2
    set /a TESTS_FAILED+=1
)
exit /b

:main

echo === File Structure Verification ===
echo.

REM Check Python service files
echo Checking Python AI service files...

if exist "ai_service\main.py" (
    call :print_result 0 "main.py exists"
) else (
    call :print_result 1 "main.py exists"
)

if exist "ai_service\requirements.txt" (
    call :print_result 0 "requirements.txt exists"
) else (
    call :print_result 1 "requirements.txt exists"
)

if exist "ai_service\Dockerfile" (
    call :print_result 0 "Dockerfile exists"
) else (
    call :print_result 1 "Dockerfile exists"
)

if exist "ai_service\.env.example" (
    call :print_result 0 ".env.example exists"
) else (
    call :print_result 1 ".env.example exists"
)

if exist "ai_service\README.md" (
    call :print_result 0 "README.md exists"
) else (
    call :print_result 1 "README.md exists"
)

echo.
echo === Java Service Integration Verification ===
echo.

REM Check Java service files
if exist "AIExplanationService.java" (
    call :print_result 0 "AIExplanationService.java exists"
) else (
    call :print_result 1 "AIExplanationService.java exists"
)

REM Check for VulnerableDependency fields
findstr /C:"private String verdict;" VulnerableDependency.java >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "VulnerableDependency has verdict field"
) else (
    call :print_result 1 "VulnerableDependency has verdict field"
)

findstr /C:"private Double confidenceScore;" VulnerableDependency.java >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "VulnerableDependency has confidenceScore field"
) else (
    call :print_result 1 "VulnerableDependency has confidenceScore field"
)

findstr /C:"private String plainEnglishExplanation;" VulnerableDependency.java >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "VulnerableDependency has plainEnglishExplanation field"
) else (
    call :print_result 1 "VulnerableDependency has plainEnglishExplanation field"
)

findstr /C:"private String attackNarrative;" VulnerableDependency.java >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "VulnerableDependency has attackNarrative field"
) else (
    call :print_result 1 "VulnerableDependency has attackNarrative field"
)

REM Check ScanService integration
findstr /C:"aiExplanationService" ScanService.java >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "ScanService integrates AIExplanationService"
) else (
    call :print_result 1 "ScanService integrates AIExplanationService"
)

findstr /C:"generateExplanations" ScanService.java >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "ScanService calls generateExplanations"
) else (
    call :print_result 1 "ScanService calls generateExplanations"
)

echo.
echo === Python Service Code Verification ===
echo.

REM Check Python service implementation
findstr /C:"class AgentState" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "AgentState class defined"
) else (
    call :print_result 1 "AgentState class defined"
)

findstr /C:"def interpret_cve" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "interpret_cve node implemented"
) else (
    call :print_result 1 "interpret_cve node implemented"
)

findstr /C:"def analyze_call_chain" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "analyze_call_chain node implemented"
) else (
    call :print_result 1 "analyze_call_chain node implemented"
)

findstr /C:"def score_confidence" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "score_confidence node implemented"
) else (
    call :print_result 1 "score_confidence node implemented"
)

findstr /C:"def generate_explanation" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "generate_explanation node implemented"
) else (
    call :print_result 1 "generate_explanation node implemented"
)

findstr /C:"def create_explanation_graph" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "LangGraph workflow created"
) else (
    call :print_result 1 "LangGraph workflow created"
)

findstr /C:"ChatAnthropic" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "Claude Sonnet 4 integration"
) else (
    call :print_result 1 "Claude Sonnet 4 integration"
)

echo.
echo === Configuration Verification ===
echo.

REM Check configuration files
if exist "application.properties" (
    call :print_result 0 "application.properties exists"
    
    findstr /C:"reachscanner.ai-service.url" application.properties >nul 2>&1
    if !errorlevel! EQU 0 (
        call :print_result 0 "AI service URL configured"
    ) else (
        call :print_result 1 "AI service URL configured"
    )
    
    findstr /C:"reachscanner.ai-service.enabled" application.properties >nul 2>&1
    if !errorlevel! EQU 0 (
        call :print_result 0 "AI service enable/disable flag configured"
    ) else (
        call :print_result 1 "AI service enable/disable flag configured"
    )
) else (
    call :print_result 1 "application.properties exists"
)

if exist "docker-compose.yml" (
    call :print_result 0 "docker-compose.yml exists"
    
    findstr /C:"ai-service:" docker-compose.yml >nul 2>&1
    if !errorlevel! EQU 0 (
        call :print_result 0 "AI service defined in docker-compose"
    ) else (
        call :print_result 1 "AI service defined in docker-compose"
    )
    
    findstr /C:"ANTHROPIC_API_KEY" docker-compose.yml >nul 2>&1
    if !errorlevel! EQU 0 (
        call :print_result 0 "Anthropic API key configured in docker-compose"
    ) else (
        call :print_result 1 "Anthropic API key configured in docker-compose"
    )
) else (
    call :print_result 1 "docker-compose.yml exists"
)

echo.
echo === API Endpoint Verification ===
echo.

REM Check API endpoints in Python service
findstr /C:"@app.post(\"/api/explain\"" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "/api/explain endpoint implemented"
) else (
    call :print_result 1 "/api/explain endpoint implemented"
)

findstr /C:"@app.get(\"/health\"" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "/health endpoint implemented"
) else (
    call :print_result 1 "/health endpoint implemented"
)

findstr /C:"ExplanationRequest" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "ExplanationRequest model defined"
) else (
    call :print_result 1 "ExplanationRequest model defined"
)

findstr /C:"ExplanationResponse" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "ExplanationResponse model defined"
) else (
    call :print_result 1 "ExplanationResponse model defined"
)

echo.
echo === Dependencies Verification ===
echo.

REM Check Python dependencies
findstr /C:"fastapi" ai_service\requirements.txt >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "FastAPI dependency"
) else (
    call :print_result 1 "FastAPI dependency"
)

findstr /C:"langgraph" ai_service\requirements.txt >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "LangGraph dependency"
) else (
    call :print_result 1 "LangGraph dependency"
)

findstr /C:"langchain-anthropic" ai_service\requirements.txt >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "LangChain Anthropic dependency"
) else (
    call :print_result 1 "LangChain Anthropic dependency"
)

findstr /C:"uvicorn" ai_service\requirements.txt >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "Uvicorn dependency"
) else (
    call :print_result 1 "Uvicorn dependency"
)

echo.
echo === LangGraph Workflow Verification ===
echo.

REM Check LangGraph workflow structure
findstr /C:"workflow.add_node.*interpret_cve" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "interpret_cve node added to workflow"
) else (
    call :print_result 1 "interpret_cve node added to workflow"
)

findstr /C:"workflow.add_node.*analyze_chain" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "analyze_chain node added to workflow"
) else (
    call :print_result 1 "analyze_chain node added to workflow"
)

findstr /C:"workflow.add_node.*score_confidence" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "score_confidence node added to workflow"
) else (
    call :print_result 1 "score_confidence node added to workflow"
)

findstr /C:"workflow.add_node.*generate_explanation" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "generate_explanation node added to workflow"
) else (
    call :print_result 1 "generate_explanation node added to workflow"
)

findstr /C:"workflow.set_entry_point" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "Workflow entry point set"
) else (
    call :print_result 1 "Workflow entry point set"
)

findstr /C:"workflow.add_edge.*END" ai_service\main.py >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "Workflow has termination edge"
) else (
    call :print_result 1 "Workflow has termination edge"
)

echo.
echo === Documentation Verification ===
echo.

REM Check README content
findstr /C:"LangGraph Agent" ai_service\README.md >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "README documents LangGraph agent"
) else (
    call :print_result 1 "README documents LangGraph agent"
)

findstr /C:"EXPLOITABLE" ai_service\README.md >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "README documents verdict types"
) else (
    call :print_result 1 "README documents verdict types"
)

findstr /C:"Confidence Scores" ai_service\README.md >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "README documents confidence scores"
) else (
    call :print_result 1 "README documents confidence scores"
)

findstr /C:"Local Setup" ai_service\README.md >nul 2>&1
if !errorlevel! EQU 0 (
    call :print_result 0 "README includes setup instructions"
) else (
    call :print_result 1 "README includes setup instructions"
)

echo.
echo ==========================================
echo Test Summary
echo ==========================================
echo [92mTests Passed: %TESTS_PASSED%[0m
echo [91mTests Failed: %TESTS_FAILED%[0m
echo.

if %TESTS_FAILED% EQU 0 (
    echo [92m✓ All tests passed! Iteration 3 is complete.[0m
    echo.
    echo Next steps:
    echo 1. Set up ANTHROPIC_API_KEY in ai_service\.env
    echo 2. Install Python dependencies: cd ai_service ^&^& pip install -r requirements.txt
    echo 3. Start AI service: python ai_service\main.py
    echo 4. Run a test scan against a vulnerable repository
    echo.
    exit /b 0
) else (
    echo [91m✗ Some tests failed. Please review the output above.[0m
    exit /b 1
)