import os
import re
import json
import time
import sqlite3
from typing import Tuple, List, Any
import google.generativeai as genai
from database import DB_PATH

# Configure Gemini API
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

def execute_sql(query: str) -> str:
    """Executes a read-only SQLite query and returns the results."""
    cleaned_query = query.strip().rstrip(";").strip()
    if not re.match(r"^\s*select\b", cleaned_query, re.IGNORECASE):
        return "Error: Unauthorized query modification. Only SELECT queries are permitted."
        
    try:
        abs_path = os.path.abspath(DB_PATH)
        uri_path = abs_path.replace("\\", "/")
        db_uri = f"file:{uri_path}?mode=ro"
        
        conn = sqlite3.connect(db_uri, uri=True, timeout=5.0)
        conn.execute("PRAGMA query_only = ON;")
        
        cursor = conn.cursor()
        
        # Avoid appending LIMIT if the query already has one
        if not re.search(r'\blimit\s+\d+', cleaned_query, re.IGNORECASE):
            cleaned_query += " LIMIT 15"
            
        cursor.execute(cleaned_query + ";")
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description] if cursor.description else []
        conn.close()
        
        if not rows:
            return "No results found."
            
        result = [dict(zip(columns, row)) for row in rows]
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"SQL Error: {str(e)}"

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    
    SYSTEM_INSTRUCTION = """You are KryptaFlow AI, an expert Network Security Architect and NIDS Chatbot.
You are tasked with answering user questions about the network intrusion detection system and executing SQL queries against the local database to find insights.

Database Information:
Database Path: ids_predictions.db (SQLite)
Schema:
1. Table `predictions`
   - id (INTEGER, PRIMARY KEY)
   - timestamp (TEXT, ISO8601)
   - prediction (TEXT) - e.g., 'BENIGN', 'DoS', 'DDoS', 'PortScan'
   - confidence (REAL)
   - severity (TEXT) - 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
   - src_ip (TEXT)
   - dst_ip (TEXT)
   - src_port (INTEGER)
   - dst_port (INTEGER)
   - protocol (INTEGER)
   - detection_method (TEXT) - 'SIGNATURE' or 'BEHAVIOR'
   
2. Table `incidents`
   - id (INTEGER PRIMARY KEY)
   - start_time (TEXT)
   - last_update (TEXT)
   - src_ip (TEXT)
   - dst_ip (TEXT)
   - attack_type (TEXT)
   - event_count (INTEGER)
   - severity (TEXT)
   - status (TEXT)
   - notified (INTEGER)

If the user asks a question about historical data, use the `execute_sql` tool to run a READ-ONLY query.
Always ensure your SQL is valid SQLite. ONLY use SELECT statements. DO NOT use INSERT, UPDATE, or DELETE.

If the user asks a general networking or system architecture question, use your general knowledge to assist them.
Keep your responses concise, professional, and formatted in Markdown.
"""

    # gemini-2.0-flash — confirmed available, 1500 free req/day (vs 25/day for 2.5-flash)
    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash",
        system_instruction=SYSTEM_INSTRUCTION,
        tools=[execute_sql]
    )
else:
    model = None

class NIDSChatbot:
    """Orchestrates Text-to-SQL generation and RAG synthesis via Gemini."""
    
    def __init__(self):
        self.chat_sessions = {}
        
    def ask(self, session_id: str, question: str) -> str:
        """Processes a user message through Gemini with Text-to-SQL capabilities."""
        if not GEMINI_API_KEY or not model:
            return "⚠️ Error: GEMINI_API_KEY environment variable is not set. Please set the GEMINI_API_KEY in your environment before starting the server."
            
        # Retry up to 2 times on quota/rate-limit errors
        for attempt in range(3):
            try:
                # Initialize or retrieve chat session
                if session_id not in self.chat_sessions:
                    self.chat_sessions[session_id] = model.start_chat(
                        enable_automatic_function_calling=True
                    )
                    
                chat = self.chat_sessions[session_id]
                response = chat.send_message(question)
                return response.text

            except Exception as e:
                err = str(e)

                # Rate limit / quota exceeded — friendly message
                if "429" in err or "quota" in err.lower() or "rate" in err.lower():
                    if attempt < 2:
                        wait = 15 * (attempt + 1)   # 15s, then 30s
                        time.sleep(wait)
                        continue
                    return (
                        "⚠️ **Gemini API quota reached.** The free tier allows a limited number of "
                        "requests per day.\n\n"
                        "**Options:**\n"
                        "- Wait a few minutes and try again.\n"
                        "- Upgrade your Google AI Studio plan at https://ai.dev/rate-limit\n"
                        "- The rest of the dashboard (live alerts, charts) works perfectly without the AI."
                    )

                # Model not found — give a clear hint
                if "404" in err:
                    return (
                        "⚠️ **Gemini model not found.** Run `list_models.py` in your project "
                        "directory to see the models your API key supports, then update "
                        "`web/chatbot.py` line 83."
                    )

                return f"⚠️ Error communicating with Gemini AI: {err}"

# Singleton instance
chatbot_engine = NIDSChatbot()
