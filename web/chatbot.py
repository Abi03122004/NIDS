import os
import re
import json
import time
import sqlite3
import hashlib
import eventlet.tpool
from groq import Groq
from database import DB_PATH

# ─── Configuration ──────────────────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

# Simple in-memory cache — avoids burning quota on repeated questions
_response_cache = {}
CACHE_TTL_SECONDS = 300  # Cache responses for 5 minutes

# System prompt injected into every session
SYSTEM_PROMPT = """You are KryptaFlow AI, an expert Network Security Architect and NIDS assistant.
You help analysts understand their network intrusion detection system and query historical threat data.

Database Schema (SQLite — ids_predictions.db):
Table `predictions`:
  - id (INTEGER PK), timestamp (TEXT ISO8601), prediction (TEXT: BENIGN/DoS/DDoS/PortScan)
  - confidence (REAL), severity (TEXT: LOW/MEDIUM/HIGH/CRITICAL)
  - src_ip (TEXT), dst_ip (TEXT), src_port (INTEGER), dst_port (INTEGER)
  - protocol (INTEGER), detection_method (TEXT: SIGNATURE or BEHAVIOR)

Table `incidents`:
  - id (INTEGER PK), start_time (TEXT), last_update (TEXT)
  - src_ip (TEXT), dst_ip (TEXT), attack_type (TEXT)
  - event_count (INTEGER), severity (TEXT), status (TEXT), notified (INTEGER)

Rules:
- When user asks about data/stats/logs, call the execute_sql tool with a valid SQLite SELECT query.
- ONLY use SELECT. Never use INSERT, UPDATE, DELETE, or DROP.
- Keep answers concise, professional, formatted in Markdown.
- For general network security questions, answer from your own knowledge.
"""

# Tool definition for Groq function calling
SQL_TOOL = {
    "type": "function",
    "function": {
        "name": "execute_sql",
        "description": "Executes a read-only SELECT query on the local KryptaFlow SQLite database (ids_predictions.db) and returns the results as JSON. Use this to answer any question about historical network logs, threats, incidents, or statistics.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "A valid SQLite SELECT statement to run against the database."
                }
            },
            "required": ["query"]
        }
    }
}

# ─── SQL Executor ────────────────────────────────────────────────────────────
def execute_sql(query: str) -> str:
    """Executes a read-only SQLite query and returns results as JSON string."""
    cleaned = query.strip().rstrip(";").strip()
    if not re.match(r"^\s*select\b", cleaned, re.IGNORECASE):
        return json.dumps({"error": "Only SELECT queries are permitted."})
    try:
        abs_path = os.path.abspath(DB_PATH)
        uri_path = abs_path.replace("\\", "/")
        db_uri = f"file:{uri_path}?mode=ro"

        conn = sqlite3.connect(db_uri, uri=True, timeout=5.0)
        conn.execute("PRAGMA query_only = ON;")
        cursor = conn.cursor()

        if not re.search(r'\blimit\s+\d+', cleaned, re.IGNORECASE):
            cleaned += " LIMIT 20"

        cursor.execute(cleaned + ";")
        rows = cursor.fetchall()
        columns = [d[0] for d in cursor.description] if cursor.description else []
        conn.close()

        if not rows:
            return json.dumps({"result": "No records found."})

        return json.dumps([dict(zip(columns, row)) for row in rows], indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ─── Chatbot Class ───────────────────────────────────────────────────────────
class NIDSChatbot:
    """RAG + LLM chatbot using Groq's Llama 3.3 with Text-to-SQL tool calling."""

    MODEL = "llama-3.3-70b-versatile"   # Best free model: smart + tool calling

    def __init__(self):
        self.client = Groq(api_key=GROQ_API_KEY, timeout=15.0) if GROQ_API_KEY else None
        # Each session holds its own message history for multi-turn conversation
        self.sessions: dict[str, list] = {}

    def ask(self, session_id: str, question: str) -> str:
        if not self.client:
            return (
                "⚠️ **GROQ_API_KEY not set.**\n"
                "Get a free key at https://console.groq.com → API Keys\n"
                "Then set it as an environment variable: `GROQ_API_KEY=your_key`"
            )

        # Check cache to save quota on repeated questions
        cache_key = hashlib.md5(question.strip().lower().encode()).hexdigest()
        if cache_key in _response_cache:
            cached_at, cached_response = _response_cache[cache_key]
            if time.time() - cached_at < CACHE_TTL_SECONDS:
                return f"{cached_response}\n\n*⚡ Cached response*"

        # Initialize session history if new
        if session_id not in self.sessions:
            self.sessions[session_id] = [
                {"role": "system", "content": SYSTEM_PROMPT}
            ]

        # Append user message
        self.sessions[session_id].append({"role": "user", "content": question})

        try:
            # ── First call: let the LLM decide if it needs to run SQL ────────
            response = eventlet.tpool.execute(
                self.client.chat.completions.create,
                model=self.MODEL,
                messages=self.sessions[session_id],
                tools=[SQL_TOOL],
                tool_choice="auto",
                max_tokens=1024,
                temperature=0.3
            )

            msg = response.choices[0].message

            # ── If the LLM called execute_sql, run it and feed result back ───
            if msg.tool_calls:
                # Add assistant's tool call to history
                self.sessions[session_id].append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        } for tc in msg.tool_calls
                    ]
                })

                # Execute each tool call
                for tool_call in msg.tool_calls:
                    args = json.loads(tool_call.function.arguments)
                    sql_result = execute_sql(args.get("query", ""))
                    self.sessions[session_id].append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": sql_result
                    })

                # ── Second call: synthesize the SQL results into a final answer
                final_response = eventlet.tpool.execute(
                    self.client.chat.completions.create,
                    model=self.MODEL,
                    messages=self.sessions[session_id],
                    max_tokens=1024,
                    temperature=0.3
                )
                result = final_response.choices[0].message.content
            else:
                result = msg.content

            # Add assistant's final answer to history
            self.sessions[session_id].append({"role": "assistant", "content": result})

            # Cache the result
            _response_cache[cache_key] = (time.time(), result)
            return result

        except Exception as e:
            err = str(e)
            if "429" in err or "rate" in err.lower():
                return (
                    "⚠️ **Groq rate limit hit.** Wait a moment and try again.\n"
                    "Groq free tier allows 14,400 requests/day — this is likely a per-minute limit."
                )
            return f"⚠️ Error: {err}"

    def ask_stream(self, session_id: str, question: str):
        """Optimized generator streaming responses for sub-second UI rendering."""
        if not self.client:
            yield "⚠️ **GROQ_API_KEY not set.**\nGet a free key at https://console.groq.com → API Keys\nThen set it as an environment variable: `GROQ_API_KEY=your_key`"
            return

        t_start = time.perf_counter()

        # 11. Cache lookup (Instant 0ms latency for repeated queries)
        cache_key = hashlib.md5(question.strip().lower().encode()).hexdigest()
        if cache_key in _response_cache:
            cached_at, cached_response = _response_cache[cache_key]
            if time.time() - cached_at < CACHE_TTL_SECONDS:
                yield f"{cached_response}\n\n*⚡ Cached response*"
                print(f"[CHATBOT LATENCY] Cache Hit! Total Time: {(time.perf_counter() - t_start)*1000:.2f}ms")
                return

        # Initialize session
        if session_id not in self.sessions:
            self.sessions[session_id] = [
                {"role": "system", "content": SYSTEM_PROMPT}
            ]

        # 4. History Pruning: Keep only last 10 messages (5 turns) + system prompt
        if len(self.sessions[session_id]) > 11:
            self.sessions[session_id] = [self.sessions[session_id][0]] + self.sessions[session_id][-10:]

        self.sessions[session_id].append({"role": "user", "content": question})

        t_pre = time.perf_counter()
        print(f"[CHATBOT LATENCY] Preprocessing: {(t_pre - t_start)*1000:.2f}ms")

        try:
            # 3. First Call (Reduced max_tokens to 256 for rapid routing check)
            response = eventlet.tpool.execute(
                self.client.chat.completions.create,
                model=self.MODEL,
                messages=self.sessions[session_id],
                tools=[SQL_TOOL],
                tool_choice="auto",
                max_tokens=256,
                temperature=0.1
            )
            
            t_first_call = time.perf_counter()
            print(f"[CHATBOT LATENCY] First LLM API Call: {(t_first_call - t_pre)*1000:.2f}ms")

            msg = response.choices[0].message

            # If tool calls are requested (RAG/Text-to-SQL logic)
            if msg.tool_calls:
                self.sessions[session_id].append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        } for tc in msg.tool_calls
                    ]
                })

                t_sql_start = time.perf_counter()
                for tool_call in msg.tool_calls:
                    args = json.loads(tool_call.function.arguments)
                    sql_result = execute_sql(args.get("query", ""))
                    self.sessions[session_id].append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": sql_result
                    })
                t_sql_end = time.perf_counter()
                print(f"[CHATBOT LATENCY] DB Execution: {(t_sql_end - t_sql_start)*1000:.2f}ms")

                # 2. Second Call (Streaming active synthesis)
                stream_response = eventlet.tpool.execute(
                    self.client.chat.completions.create,
                    model=self.MODEL,
                    messages=self.sessions[session_id],
                    max_tokens=512,  # Optimized token envelope
                    temperature=0.3,
                    stream=True
                )
                
                full_reply = []
                for chunk in stream_response:
                    if chunk.choices[0].delta.content:
                        token = chunk.choices[0].delta.content
                        full_reply.append(token)
                        yield token
                        
                result = "".join(full_reply)
            else:
                # No database query needed, directly stream the first response
                result = msg.content or ""
                yield result

            self.sessions[session_id].append({"role": "assistant", "content": result})
            _response_cache[cache_key] = (time.time(), result)
            print(f"[CHATBOT LATENCY] Total Generation & Stream Time: {(time.perf_counter() - t_first_call)*1000:.2f}ms")

        except Exception as e:
            err = str(e)
            if "429" in err or "rate" in err.lower():
                yield "⚠️ **Groq rate limit hit.** Wait a moment and try again."
            else:
                yield f"⚠️ Error: {err}"


# Singleton instance
chatbot_engine = NIDSChatbot()
