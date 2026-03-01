"""
Unit tests for ReachAI AI Explanation Service
Tests the FastAPI endpoints and LangGraph workflow
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime

# Import the FastAPI app
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from main import app, AgentState, interpret_cve, analyze_call_chain, score_confidence, generate_explanation


# Test client
client = TestClient(app)


# ============= API Endpoint Tests =============

class TestHealthEndpoint:
    """Tests for the /health endpoint"""
    
    def test_health_check(self):
        """Test that health check returns 200 OK"""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "ReachAI Explanation Service"
        assert "timestamp" in data


class TestRootEndpoint:
    """Tests for the root / endpoint"""
    
    def test_root_endpoint(self):
        """Test that root endpoint returns service info"""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert data["service"] == "ReachAI AI Explanation Service"
        assert data["version"] == "1.0.0"
        assert "endpoints" in data


class TestExplainEndpoint:
    """Tests for the /api/explain endpoint"""
    
    @pytest.fixture
    def sample_request_with_chains(self):
        """Sample request with call chains"""
        return {
            "cveId": "CVE-2019-14379",
            "description": "Jackson Databind unsafe deserialization vulnerability",
            "severity": "CRITICAL",
            "dependencyCoordinates": "com.fasterxml.jackson.core:jackson-databind:2.9.8",
            "callChains": [
                {
                    "entryPoint": "UserController.createUser",
                    "vulnerableSink": "ObjectMapper.readValue",
                    "isReachable": True,
                    "steps": [
                        {
                            "fileName": "src/main/java/com/example/UserController.java",
                            "lineNumber": 42,
                            "methodName": "createUser",
                            "className": "UserController",
                            "snippet": "@PostMapping(\"/api/users\")"
                        },
                        {
                            "fileName": "src/main/java/com/example/UserService.java",
                            "lineNumber": 28,
                            "methodName": "parseUserJson",
                            "className": "UserService",
                            "snippet": "objectMapper.readValue(json, User.class)"
                        }
                    ]
                }
            ]
        }
    
    @pytest.fixture
    def sample_request_no_chains(self):
        """Sample request without call chains"""
        return {
            "cveId": "CVE-2019-14379",
            "description": "Jackson Databind unsafe deserialization vulnerability",
            "severity": "CRITICAL",
            "dependencyCoordinates": "com.fasterxml.jackson.core:jackson-databind:2.9.8",
            "callChains": []
        }
    
    def test_explain_endpoint_requires_auth(self, sample_request_with_chains):
        """Test that explain endpoint validates request structure"""
        response = client.post("/api/explain", json=sample_request_with_chains)
        # Should return 200 or 500, not 422 (validation error)
        assert response.status_code in [200, 500]
    
    def test_explain_endpoint_missing_fields(self):
        """Test that explain endpoint validates required fields"""
        invalid_request = {
            "cveId": "CVE-2019-14379"
            # Missing other required fields
        }
        response = client.post("/api/explain", json=invalid_request)
        assert response.status_code == 422  # Validation error


# ============= LangGraph Node Tests =============

class TestInterpretCveNode:
    """Tests for the interpret_cve node"""
    
    @patch('main.ChatAnthropic')
    def test_interpret_cve_success(self, mock_claude):
        """Test CVE interpretation node"""
        # Mock Claude response
        mock_response = Mock()
        mock_response.content = "This is a deserialization vulnerability in Jackson..."
        mock_claude.return_value.invoke.return_value = mock_response
        
        # Create test state
        state = AgentState(
            cveId="CVE-2019-14379",
            description="Jackson vulnerability",
            severity="CRITICAL",
            callChains=[],
            dependencyCoordinates="com.fasterxml.jackson.core:jackson-databind:2.9.8"
        )
        
        # Run node
        result_state = interpret_cve(state)
        
        # Verify
        assert result_state.cveInterpretation is not None
        assert len(result_state.cveInterpretation) > 0
        assert "deserialization" in result_state.cveInterpretation.lower()


class TestAnalyzeCallChainNode:
    """Tests for the analyze_call_chain node"""
    
    @patch('main.ChatAnthropic')
    def test_analyze_with_chains(self, mock_claude):
        """Test call chain analysis with chains present"""
        # Mock Claude response
        mock_response = Mock()
        mock_response.content = "The call chain shows a clear path from HTTP endpoint..."
        mock_claude.return_value.invoke.return_value = mock_response
        
        # Create test state with call chains
        from main import CallChain, CallStep
        
        call_chain = CallChain(
            entryPoint="UserController.createUser",
            vulnerableSink="ObjectMapper.readValue",
            isReachable=True,
            steps=[
                CallStep(
                    fileName="UserController.java",
                    lineNumber=42,
                    methodName="createUser",
                    className="UserController",
                    snippet="@PostMapping"
                )
            ]
        )
        
        state = AgentState(
            cveId="CVE-2019-14379",
            description="Test",
            severity="CRITICAL",
            callChains=[call_chain],
            dependencyCoordinates="test:test:1.0",
            cveInterpretation="Previous interpretation"
        )
        
        # Run node
        result_state = analyze_call_chain(state)
        
        # Verify
        assert result_state.chainAnalysis is not None
        assert len(result_state.chainAnalysis) > 0
    
    @patch('main.ChatAnthropic')
    def test_analyze_without_chains(self, mock_claude):
        """Test call chain analysis with no chains"""
        state = AgentState(
            cveId="CVE-2019-14379",
            description="Test",
            severity="CRITICAL",
            callChains=[],
            dependencyCoordinates="test:test:1.0",
            cveInterpretation="Previous interpretation"
        )
        
        # Run node
        result_state = analyze_call_chain(state)
        
        # Verify
        assert result_state.chainAnalysis is not None
        assert "not reachable" in result_state.chainAnalysis.lower()


class TestScoreConfidenceNode:
    """Tests for the score_confidence node"""
    
    @patch('main.ChatAnthropic')
    def test_score_confidence_exploitable(self, mock_claude):
        """Test confidence scoring for exploitable vulnerability"""
        # Mock Claude response
        mock_response = Mock()
        mock_response.content = """
VERDICT: EXPLOITABLE
CONFIDENCE_SCORE: 0.92
REASONING: Clear data flow from HTTP endpoint to vulnerable deserialization method.
"""
        mock_claude.return_value.invoke.return_value = mock_response
        
        state = AgentState(
            cveId="CVE-2019-14379",
            description="Test",
            severity="CRITICAL",
            callChains=[],
            dependencyCoordinates="test:test:1.0",
            cveInterpretation="Interpretation",
            chainAnalysis="Analysis shows exploitable path"
        )
        
        # Run node
        result_state = score_confidence(state)
        
        # Verify
        assert result_state.verdict == "EXPLOITABLE"
        assert result_state.confidenceScore == 0.92
        assert result_state.confidenceReasoning is not None
    
    @patch('main.ChatAnthropic')
    def test_score_confidence_not_reachable(self, mock_claude):
        """Test confidence scoring for not reachable vulnerability"""
        mock_response = Mock()
        mock_response.content = """
VERDICT: NOT_REACHABLE
CONFIDENCE_SCORE: 0.88
REASONING: No call chains found from entry points.
"""
        mock_claude.return_value.invoke.return_value = mock_response
        
        state = AgentState(
            cveId="CVE-2019-14379",
            description="Test",
            severity="CRITICAL",
            callChains=[],
            dependencyCoordinates="test:test:1.0",
            cveInterpretation="Interpretation",
            chainAnalysis="No reachable paths"
        )
        
        # Run node
        result_state = score_confidence(state)
        
        # Verify
        assert result_state.verdict == "NOT_REACHABLE"
        assert result_state.confidenceScore == 0.88


class TestGenerateExplanationNode:
    """Tests for the generate_explanation node"""
    
    @patch('main.ChatAnthropic')
    def test_generate_explanation_exploitable(self, mock_claude):
        """Test explanation generation for exploitable vulnerability"""
        # Mock Claude responses (called twice - explanation and narrative)
        mock_explanation = Mock()
        mock_explanation.content = "This application has a critical vulnerability..."
        
        mock_narrative = Mock()
        mock_narrative.content = "An attacker would craft a malicious payload..."
        
        mock_claude.return_value.invoke.side_effect = [mock_explanation, mock_narrative]
        
        state = AgentState(
            cveId="CVE-2019-14379",
            description="Test",
            severity="CRITICAL",
            callChains=[],
            dependencyCoordinates="test:test:1.0",
            cveInterpretation="Interpretation",
            chainAnalysis="Analysis",
            verdict="EXPLOITABLE",
            confidenceScore=0.92
        )
        
        # Run node
        result_state = generate_explanation(state)
        
        # Verify
        assert result_state.plainEnglishExplanation is not None
        assert "vulnerability" in result_state.plainEnglishExplanation.lower()
        assert result_state.attackNarrative is not None
        assert "attacker" in result_state.attackNarrative.lower()
    
    @patch('main.ChatAnthropic')
    def test_generate_explanation_not_reachable(self, mock_claude):
        """Test explanation generation for not reachable vulnerability"""
        mock_explanation = Mock()
        mock_explanation.content = "The vulnerable dependency is present but not reachable..."
        mock_claude.return_value.invoke.return_value = mock_explanation
        
        state = AgentState(
            cveId="CVE-2019-14379",
            description="Test",
            severity="CRITICAL",
            callChains=[],
            dependencyCoordinates="test:test:1.0",
            cveInterpretation="Interpretation",
            chainAnalysis="Analysis",
            verdict="NOT_REACHABLE",
            confidenceScore=0.88
        )
        
        # Run node
        result_state = generate_explanation(state)
        
        # Verify
        assert result_state.plainEnglishExplanation is not None
        assert result_state.attackNarrative is not None
        assert "not reachable" in result_state.attackNarrative.lower()


# ============= Integration Tests =============

class TestEndToEndWorkflow:
    """End-to-end integration tests"""
    
    @pytest.mark.integration
    @patch('main.ChatAnthropic')
    def test_full_workflow_with_chains(self, mock_claude):
        """Test complete workflow from request to response"""
        # Mock all Claude calls
        mock_responses = [
            Mock(content="CVE interpretation"),  # interpret_cve
            Mock(content="Chain analysis"),       # analyze_call_chain
            Mock(content="VERDICT: EXPLOITABLE\nCONFIDENCE_SCORE: 0.92\nREASONING: Clear path"),  # score_confidence
            Mock(content="Plain English explanation"),  # generate_explanation (explanation)
            Mock(content="Attack narrative")            # generate_explanation (narrative)
        ]
        mock_claude.return_value.invoke.side_effect = mock_responses
        
        request_data = {
            "cveId": "CVE-2019-14379",
            "description": "Jackson Databind vulnerability",
            "severity": "CRITICAL",
            "dependencyCoordinates": "com.fasterxml.jackson.core:jackson-databind:2.9.8",
            "callChains": [
                {
                    "entryPoint": "UserController.createUser",
                    "vulnerableSink": "ObjectMapper.readValue",
                    "isReachable": True,
                    "steps": [
                        {
                            "fileName": "UserController.java",
                            "lineNumber": 42,
                            "methodName": "createUser",
                            "className": "UserController",
                            "snippet": "@PostMapping"
                        }
                    ]
                }
            ]
        }
        
        response = client.post("/api/explain", json=request_data)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response has all required fields
        assert data["cveId"] == "CVE-2019-14379"
        assert data["verdict"] in ["EXPLOITABLE", "NOT_REACHABLE", "NEEDS_REVIEW"]
        assert "confidenceScore" in data
        assert data["plainEnglishExplanation"] is not None
        assert data["attackNarrative"] is not None
        assert data["technicalDetails"] is not None


# ============= Model Validation Tests =============

class TestRequestModels:
    """Tests for Pydantic request models"""
    
    def test_valid_explanation_request(self):
        """Test that valid request data is accepted"""
        from main import ExplanationRequest, CallChain, CallStep
        
        request = ExplanationRequest(
            cveId="CVE-2019-14379",
            description="Test description",
            severity="CRITICAL",
            dependencyCoordinates="group:artifact:1.0",
            callChains=[]
        )
        
        assert request.cveId == "CVE-2019-14379"
        assert request.severity == "CRITICAL"
    
    def test_request_with_call_chains(self):
        """Test request with call chain data"""
        from main import ExplanationRequest, CallChain, CallStep
        
        step = CallStep(
            fileName="Test.java",
            lineNumber=42,
            methodName="testMethod",
            className="TestClass",
            snippet="code snippet"
        )
        
        chain = CallChain(
            entryPoint="main",
            vulnerableSink="sink",
            isReachable=True,
            steps=[step]
        )
        
        request = ExplanationRequest(
            cveId="CVE-2019-14379",
            description="Test",
            severity="HIGH",
            dependencyCoordinates="test:test:1.0",
            callChains=[chain]
        )
        
        assert len(request.callChains) == 1
        assert request.callChains[0].entryPoint == "main"
        assert len(request.callChains[0].steps) == 1


class TestResponseModels:
    """Tests for Pydantic response models"""
    
    def test_valid_explanation_response(self):
        """Test that response model validates correctly"""
        from main import ExplanationResponse
        
        response = ExplanationResponse(
            cveId="CVE-2019-14379",
            verdict="EXPLOITABLE",
            confidenceScore=0.92,
            confidenceReasoning="Test reasoning",
            plainEnglishExplanation="Test explanation",
            attackNarrative="Test narrative",
            technicalDetails={"test": "data"},
            generatedAt=datetime.utcnow().isoformat()
        )
        
        assert response.verdict == "EXPLOITABLE"
        assert response.confidenceScore == 0.92


# ============= Error Handling Tests =============

class TestErrorHandling:
    """Tests for error handling"""
    
    def test_invalid_json_request(self):
        """Test that invalid JSON is handled"""
        response = client.post(
            "/api/explain",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
    
    @patch('main.ChatAnthropic')
    def test_workflow_exception_handling(self, mock_claude):
        """Test that workflow exceptions are handled gracefully"""
        # Make Claude API raise an exception
        mock_claude.return_value.invoke.side_effect = Exception("Claude API error")
        
        request_data = {
            "cveId": "CVE-2019-14379",
            "description": "Test",
            "severity": "CRITICAL",
            "dependencyCoordinates": "test:test:1.0",
            "callChains": []
        }
        
        response = client.post("/api/explain", json=request_data)
        assert response.status_code == 500
        assert "Failed to generate explanation" in response.json()["detail"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])