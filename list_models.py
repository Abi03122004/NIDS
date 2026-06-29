import os
import google.generativeai as genai

# Make sure GEMINI_API_KEY is set in your environment
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("Error: GEMINI_API_KEY environment variable not set.")
    exit(1)

genai.configure(api_key=api_key)

print("Available models that support generateContent for your API Key:\n")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f" - {m.name.replace('models/', '')}")
    print("\nPlease copy one of the model names above (e.g. gemini-1.5-pro or gemini-pro) and update `web/chatbot.py` (line 83).")
except Exception as e:
    print(f"Error fetching models: {e}")
