"""
Simple test to verify Claude API is working
Just makes one API call to check the response
"""

import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Check API key
api_key = os.getenv("ANTHROPIC_API_KEY")
if not api_key:
    print("❌ ERROR: ANTHROPIC_API_KEY not found in .env file")
    print()
    print("Please create a .env file with:")
    print("ANTHROPIC_API_KEY=sk-ant-api03-your-key-here")
    exit(1)

print("✓ API key found:", api_key[:20] + "..." + api_key[-4:])
print()

# Import after checking API key
try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage
    print("✓ Libraries imported successfully")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print()
    print("Install required packages:")
    print("  pip install langchain-anthropic")
    exit(1)

print()
print("=" * 80)
print("Testing Claude API Connection")
print("=" * 80)
print()

# Initialize Claude
print("Initializing Claude Sonnet 4...")
try:
    llm = ChatAnthropic(
        model="claude-sonnet-4-20250514",
        temperature=0.3,
        timeout=30
    )
    print("✓ Claude initialized")
except Exception as e:
    print(f"❌ Failed to initialize Claude: {e}")
    exit(1)

print()
print("-" * 80)
print("Sending test prompt to Claude...")
print("-" * 80)

prompt = """Explain in 2-3 sentences what a deserialization vulnerability is and why it's dangerous."""

print()
print("Prompt:")
print(prompt)
print()
print("-" * 80)
print("Claude's Response:")
print("-" * 80)
print()

try:
    messages = [HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    
    print(response.content)
    print()
    print("-" * 80)
    print("✓ API call successful!")
    print("-" * 80)
    print()
    print("Response details:")
    print(f"  Model: {response.response_metadata.get('model', 'unknown')}")
    print(f"  Usage: {response.usage_metadata if hasattr(response, 'usage_metadata') else 'N/A'}")
    
except Exception as e:
    print(f"❌ API call failed: {e}")
    print()
    print("Common issues:")
    print("  1. Invalid API key")
    print("  2. No internet connection")
    print("  3. API rate limit exceeded")
    print("  4. Billing issue with Anthropic account")
    exit(1)

print()
print("=" * 80)
print("Test completed successfully!")
print("=" * 80)
print()
print("Your Claude API is working correctly.")
print("You can now run the full AI service:")
print("  python main.py")