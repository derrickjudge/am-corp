#!/usr/bin/env python3
"""
Gemini API Diagnostic Script

Tests the Gemini API connection and shows detailed error information.
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()


def main():
    print("=" * 60)
    print("Gemini API Diagnostic")
    print("=" * 60)
    
    # Check API key
    api_key = os.getenv("GEMINI_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    
    print(f"\n1. Configuration:")
    print(f"   API Key: {'✅ Set' if api_key else '❌ Missing'}")
    if api_key:
        print(f"   API Key prefix: {api_key[:15]}...")
    print(f"   Model: {model_name}")
    
    if not api_key:
        print("\n❌ GEMINI_API_KEY not set in .env")
        return
    
    # Import and configure
    print(f"\n2. Importing google.generativeai...")
    try:
        import google.generativeai as genai
        print("   ✅ Import successful")
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")
        return
    
    genai.configure(api_key=api_key)
    
    # List available models
    print(f"\n3. Available models (that support generateContent):")
    try:
        models = list(genai.list_models())
        generate_models = [m for m in models if 'generateContent' in m.supported_generation_methods]
        for m in generate_models[:10]:
            marker = "👉" if model_name in m.name else "  "
            print(f"   {marker} {m.name}")
        if len(generate_models) > 10:
            print(f"   ... and {len(generate_models) - 10} more")
    except Exception as e:
        print(f"   ❌ Error listing models: {e}")
    
    # Test generation
    print(f"\n4. Testing generation with model '{model_name}'...")
    try:
        model = genai.GenerativeModel(model_name)
        
        test_prompt = "Say 'Howdy partner!' in a Texas accent. One sentence only."
        print(f"   Prompt: {test_prompt}")
        print(f"   Sending request...")
        
        response = model.generate_content(test_prompt)
        
        print(f"\n   ✅ SUCCESS!")
        print(f"   Response: {response.text}")
        
    except Exception as e:
        print(f"\n   ❌ FAILED!")
        print(f"   Error type: {type(e).__name__}")
        print(f"   Error message: {str(e)[:500]}")
        
        # Parse common errors
        error_str = str(e).lower()
        if "404" in str(e) and "not found" in error_str:
            print(f"\n   💡 Model '{model_name}' not found.")
            print(f"      Try one of the models listed above.")
        elif "429" in str(e) or "quota" in error_str:
            print(f"\n   💡 Rate limit / quota exceeded.")
            print(f"      Wait a minute or check your billing at https://aistudio.google.com/")
        elif "403" in str(e) or "permission" in error_str:
            print(f"\n   💡 Permission denied. Check your API key.")
        elif "invalid" in error_str and "key" in error_str:
            print(f"\n   💡 Invalid API key. Generate a new one at https://aistudio.google.com/")
    
    # Test with system instruction (like Randy uses)
    print(f"\n5. Testing with system instruction (Randy mode)...")
    try:
        model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction="You are Randy Recon, a Texas cowboy cybersecurity specialist. Be friendly and use occasional Texas expressions."
        )
        
        response = model.generate_content("Introduce yourself in one sentence.")
        
        print(f"   ✅ SUCCESS!")
        print(f"   Response: {response.text}")
        
    except Exception as e:
        print(f"   ❌ FAILED: {type(e).__name__}: {str(e)[:200]}")
    
    print("\n" + "=" * 60)
    print("Diagnostic complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()

