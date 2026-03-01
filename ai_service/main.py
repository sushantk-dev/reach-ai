"""
ReachAI - AI Explanation Service
FastAPI service that generates human-readable explanations of vulnerabilities using LangGraph
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime

# LangGraph imports
from langgraph.graph import StateGraph, END
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ReachAI Explanation Service", version="1.0.0")


# ============= Request/Response Models =============

class CallStep(BaseModel):
    """Represents a single step in the call chain"""
    fileName: str
    lineNumber: int
    methodName: str
    className: str
    snippet: str


class CallChain(BaseModel):
    """Represents a complete call chain from entry point to vulnerable sink"""
    entryPoint: str
    vulnerableSink: str
    steps: List[CallStep]
    isReachable: bool


class ExplanationRequest(BaseModel):
    """Request for vulnerability explanation"""
    cveId: str = Field(..., description="CVE identifier (e.g., CVE-2019-14379)")
    description: str = Field(..., description="CVE description")
    severity: str = Field(..., description="Vulnerability severity")
    callChains: List[CallChain] = Field(..., description="Call chains showing reachability")
    dependencyCoordinates: str = Field(..., description="Maven coordinates of vulnerable dependency")


class ExplanationResponse(BaseModel):
    """Response containing AI-generated explanation"""
    cveId: str
    verdict: str  # EXPLOITABLE, NOT_REACHABLE, NEEDS_REVIEW
    confidenceScore: float  # 0.0 to 1.0
    confidenceReasoning: str
    plainEnglishExplanation: str
    attackNarrative: str
    technicalDetails: Dict[str, Any]
    generatedAt: str


# ============= LangGraph Agent State =============

class AgentState(BaseModel):
    """State maintained throughout the LangGraph workflow"""
    # Input
    cveId: str
    description: str
    severity: str
    callChains: List[CallChain]
    dependencyCoordinates: str
    
    # Intermediate state
    cveInterpretation: Optional[str] = None
    chainAnalysis: Optional[str] = None
    confidenceScore: Optional[float] = None
    confidenceReasoning: Optional[str] = None
    
    # Output
    verdict: Optional[str] = None
    plainEnglishExplanation: Optional[str] = None
    attackNarrative: Optional[str] = None
    
    class Config:
        arbitrary_types_allowed = True


# ============= LangGraph Node Functions =============

def interpret_cve(state: AgentState) -> AgentState:
    """
    Node 1: Interpret the CVE
    Analyzes the CVE description to understand what the vulnerability is about
    """
    logger.info(f"Node 1: Interpreting CVE {state.cveId}")
    
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0.3)
    
    prompt = f"""You are a security expert analyzing a vulnerability.

CVE ID: {state.cveId}
Severity: {state.severity}
Description: {state.description}
Vulnerable Dependency: {state.dependencyCoordinates}

Provide a clear, technical interpretation of:
1. What is this vulnerability?
2. What attack vector does it enable?
3. What are the prerequisites for exploitation?
4. What is the potential impact?

Be concise but comprehensive. Focus on actionable security information."""

    messages = [HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    
    state.cveInterpretation = response.content
    logger.info("CVE interpretation completed")
    
    return state


def analyze_call_chain(state: AgentState) -> AgentState:
    """
    Node 2: Analyze the call chain
    Examines the data flow paths to determine actual exploitability
    """
    logger.info(f"Node 2: Analyzing call chains for {state.cveId}")
    
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0.3)
    
    if not state.callChains or len(state.callChains) == 0:
        state.chainAnalysis = "No call chains found. The vulnerable dependency is present but not reachable from any entry point."
        logger.info("No call chains to analyze")
        return state
    
    # Format call chains for analysis
    chain_descriptions = []
    for i, chain in enumerate(state.callChains, 1):
        steps_summary = "\n".join([
            f"    Step {j}: {step.className}.{step.methodName} ({step.fileName}:{step.lineNumber})"
            for j, step in enumerate(chain.steps, 1)
        ])
        chain_descriptions.append(f"""
Call Chain {i}:
  Entry Point: {chain.entryPoint}
  Vulnerable Sink: {chain.vulnerableSink}
  Path ({len(chain.steps)} steps):
{steps_summary}
""")
    
    chains_text = "\n".join(chain_descriptions)
    
    prompt = f"""You are analyzing data flow paths in a Java application to determine if a vulnerability is exploitable.

CVE Context:
{state.cveInterpretation}

Call Chains Found:
{chains_text}

Analyze these call chains and determine:
1. Are these legitimate paths from user-controlled input to vulnerable code?
2. What input mechanisms could an attacker use (HTTP requests, file uploads, etc.)?
3. Are there any security controls in the path that might prevent exploitation?
4. What would an attacker need to control to exploit this?

Provide a detailed technical analysis."""

    messages = [HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    
    state.chainAnalysis = response.content
    logger.info("Call chain analysis completed")
    
    return state


def score_confidence(state: AgentState) -> AgentState:
    """
    Node 3: Score confidence and determine verdict
    Assigns a confidence score and verdict based on the analysis
    """
    logger.info(f"Node 3: Scoring confidence for {state.cveId}")
    
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0.2)
    
    prompt = f"""You are a security analyst determining the exploitability of a vulnerability.

CVE Interpretation:
{state.cveInterpretation}

Call Chain Analysis:
{state.chainAnalysis}

Based on this analysis, provide:

1. VERDICT: Choose exactly one of:
   - EXPLOITABLE: Clear path from entry point to vulnerable code with user-controlled input
   - NOT_REACHABLE: Vulnerable code exists but is not reachable from any entry point
   - NEEDS_REVIEW: Call chain exists but exploitation is uncertain (requires manual review)

2. CONFIDENCE_SCORE: A number between 0.0 and 1.0 representing certainty:
   - 0.9-1.0: Very high confidence (clear evidence)
   - 0.7-0.89: High confidence (strong indicators)
   - 0.5-0.69: Medium confidence (some uncertainty)
   - 0.3-0.49: Low confidence (significant gaps)
   - 0.0-0.29: Very low confidence (insufficient evidence)

3. REASONING: Explain your confidence score in 2-3 sentences.

Respond in this exact format:
VERDICT: [EXPLOITABLE|NOT_REACHABLE|NEEDS_REVIEW]
CONFIDENCE_SCORE: [0.0-1.0]
REASONING: [Your reasoning here]"""

    messages = [HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    
    # Parse the response
    content = response.content.strip()
    lines = content.split('\n')
    
    verdict = None
    confidence_score = None
    reasoning = []
    
    for line in lines:
        if line.startswith('VERDICT:'):
            verdict = line.replace('VERDICT:', '').strip()
        elif line.startswith('CONFIDENCE_SCORE:'):
            try:
                confidence_score = float(line.replace('CONFIDENCE_SCORE:', '').strip())
            except ValueError:
                confidence_score = 0.5
        elif line.startswith('REASONING:'):
            reasoning.append(line.replace('REASONING:', '').strip())
        elif reasoning and line.strip():
            reasoning.append(line.strip())
    
    state.verdict = verdict or "NEEDS_REVIEW"
    state.confidenceScore = confidence_score if confidence_score is not None else 0.5
    state.confidenceReasoning = ' '.join(reasoning) if reasoning else "Analysis completed with standard confidence."
    
    logger.info(f"Verdict: {state.verdict}, Confidence: {state.confidenceScore}")
    
    return state


def generate_explanation(state: AgentState) -> AgentState:
    """
    Node 4: Generate plain English explanation and attack narrative
    Creates user-friendly explanations of the vulnerability and how it could be exploited
    """
    logger.info(f"Node 4: Generating explanation for {state.cveId}")
    
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0.4)
    
    # Generate plain English explanation
    explanation_prompt = f"""You are explaining a security vulnerability to a software developer.

CVE: {state.cveId}
Verdict: {state.verdict}
Confidence: {state.confidenceScore}

Analysis:
{state.cveInterpretation}

{state.chainAnalysis}

Write a clear, plain English explanation (3-4 paragraphs) that:
1. Explains what the vulnerability is in simple terms
2. Describes how it exists in this codebase
3. Explains the risk level and potential impact
4. Provides actionable next steps

Write for a developer audience - technical but accessible."""

    messages = [HumanMessage(content=explanation_prompt)]
    explanation_response = llm.invoke(messages)
    state.plainEnglishExplanation = explanation_response.content.strip()
    
    # Generate attack narrative
    if state.verdict == "EXPLOITABLE":
        narrative_prompt = f"""You are a security researcher demonstrating how an attacker would exploit a vulnerability.

CVE: {state.cveId}
Call Chain Analysis:
{state.chainAnalysis}

Write an attack narrative (2-3 paragraphs) that describes:
1. How an attacker would discover this vulnerability
2. Step-by-step: what the attacker would do to exploit it
3. What the attacker would achieve (data access, code execution, etc.)

Write from the attacker's perspective, be specific about the attack steps, but remain professional and educational."""

        messages = [HumanMessage(content=narrative_prompt)]
        narrative_response = llm.invoke(messages)
        state.attackNarrative = narrative_response.content.strip()
    else:
        state.attackNarrative = f"This vulnerability is marked as {state.verdict}. No attack narrative is generated as the vulnerable code is not reachable from application entry points."
    
    logger.info("Explanation and narrative generation completed")
    
    return state


# ============= LangGraph Workflow =============

def create_explanation_graph() -> StateGraph:
    """
    Creates the LangGraph workflow for generating vulnerability explanations
    """
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("interpret_cve", interpret_cve)
    workflow.add_node("analyze_chain", analyze_call_chain)
    workflow.add_node("score_confidence", score_confidence)
    workflow.add_node("generate_explanation", generate_explanation)
    
    # Define edges (flow)
    workflow.set_entry_point("interpret_cve")
    workflow.add_edge("interpret_cve", "analyze_chain")
    workflow.add_edge("analyze_chain", "score_confidence")
    workflow.add_edge("score_confidence", "generate_explanation")
    workflow.add_edge("generate_explanation", END)
    
    return workflow.compile()


# ============= FastAPI Endpoints =============

@app.post("/api/explain", response_model=ExplanationResponse)
async def explain_vulnerability(request: ExplanationRequest) -> ExplanationResponse:
    """
    Generates an AI-powered explanation of a vulnerability
    
    This endpoint uses a LangGraph agent to:
    1. Interpret the CVE
    2. Analyze call chains
    3. Score confidence
    4. Generate plain English explanation and attack narrative
    """
    try:
        logger.info(f"Received explanation request for {request.cveId}")
        
        # Create initial state
        initial_state = AgentState(
            cveId=request.cveId,
            description=request.description,
            severity=request.severity,
            callChains=request.callChains,
            dependencyCoordinates=request.dependencyCoordinates
        )
        
        # Run the LangGraph workflow
        graph = create_explanation_graph()
        final_state_dict = graph.invoke(initial_state)
        
        # LangGraph returns a dictionary, not an AgentState object
        # Extract fields from the dictionary
        logger.info(f"Workflow completed for {request.cveId}")
        
        # Build response from dictionary
        response = ExplanationResponse(
            cveId=final_state_dict.get("cveId", request.cveId),
            verdict=final_state_dict.get("verdict") or "NEEDS_REVIEW",
            confidenceScore=final_state_dict.get("confidenceScore") or 0.5,
            confidenceReasoning=final_state_dict.get("confidenceReasoning") or "Analysis completed",
            plainEnglishExplanation=final_state_dict.get("plainEnglishExplanation") or "Explanation not available",
            attackNarrative=final_state_dict.get("attackNarrative") or "No attack narrative available",
            technicalDetails={
                "cveInterpretation": final_state_dict.get("cveInterpretation"),
                "chainAnalysis": final_state_dict.get("chainAnalysis"),
                "numberOfCallChains": len(request.callChains)
            },
            generatedAt=datetime.utcnow().isoformat()
        )
        
        logger.info(f"Successfully generated explanation for {request.cveId}")
        return response
        
    except Exception as e:
        logger.error(f"Error generating explanation: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate explanation: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "ReachAI Explanation Service",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "ReachAI AI Explanation Service",
        "version": "1.0.0",
        "description": "Generates AI-powered explanations of security vulnerabilities using LangGraph",
        "endpoints": {
            "explain": "/api/explain",
            "health": "/health",
            "docs": "/docs"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)