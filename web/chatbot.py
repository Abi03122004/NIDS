# web/chatbot.py
# Production-ready Text-to-SQL + RAG Chatbot Engine for KryptaFlow NIDS
# Uses local Ollama model inference and read-only SQLite security controls

import os
import re
import sqlite3
import urllib.parse
from typing import Dict, Any, List, Tuple, Optional

# Enforce import of ollama client library
try:
    import ollama
except ImportError:
    ollama = None

class ReadOnlyDatabaseError(Exception):
    """Custom exception for read-only database query enforcement violations."""
    pass

def execute_readonly_query(db_path: str, sql_query: str) -> Tuple[List[str], List[Tuple[Any, ...]]]:
    """
    Connects to the SQLite NIDS database in strict read-only mode and executes the query.
    Hard-codes an automatic LIMIT 15 to prevent DoS or excessive memory usage.
    """
    # Normalize path and check existence
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found at: {db_path}")

    # Enforce SELECT-only checks via regex
    cleaned_query = sql_query.strip().rstrip(";").strip()
    if not re.match(r"^\s*select\b", cleaned_query, re.IGNORECASE):
        raise ReadOnlyDatabaseError("Unauthorized query modification. Only SELECT queries are permitted.")
    
    # Enforce LIMIT 15 cap
    limit_match = re.search(r"\blimit\s+(\d+)\s*$", cleaned_query, re.IGNORECASE)
    if limit_match:
        val = int(limit_match.group(1))
        if val > 15:
            # Cap it to 15
            cleaned_query = cleaned_query[:limit_match.start()] + "LIMIT 15"
    else:
        # Append limit 15
        cleaned_query = cleaned_query + " LIMIT 15"
        
    final_sql = cleaned_query + ";"

    # Establish connection with mode=ro via sqlite3 URI
    # On Windows, path must be absolute or formatted correctly as file URI
    abs_path = os.path.abspath(db_path)
    # Convert backslashes to forward slashes for URI format
    uri_path = abs_path.replace("\\", "/")
    # Parse path and construct file URI
    db_uri = f"file:{uri_path}?mode=ro"
    
    conn = None
    try:
        conn = sqlite3.connect(db_uri, uri=True, timeout=5.0)
        # Extra security measures inside SQLite connection
        conn.execute("PRAGMA query_only = ON;")
        
        cursor = conn.cursor()
        cursor.execute(final_sql)
        
        # Extract column names/headers
        headers = [description[0] for description in cursor.description] if cursor.description else []
        rows = cursor.fetchall()
        return headers, rows
    finally:
        if conn:
            conn.close()

class NIDSChatbot:
    """Orchestrates Text-to-SQL generation, read-only query execution, and RAG synthesis."""
    
    def __init__(self, model_name: str = "llama3", db_path: str = "logs/ids_predictions.db"):
        self.model_name = model_name
        self.db_path = db_path
        
    def generate_sql(self, question: str) -> str:
        """
        Step A: Ask the local LLM to generate a clean SQLite query for the predictions schema.
        """
        if ollama is None:
            raise ImportError("The 'ollama' Python library is not installed.")

        # System prompt describing schema and formatting rules
        system_prompt = (
            "You are a SQL expert and database analyzer for the KryptaFlow Network Intrusion Detection System.\n\n"
            "Database Schema (predictions table):\n"
            "- id (INTEGER PRIMARY KEY AUTOINCREMENT)\n"
            "- timestamp (TEXT NOT NULL) -> formatted as 'YYYY-MM-DD HH:MM:SS'\n"
            "- src_ip (TEXT NOT NULL) -> source IP\n"
            "- dst_ip (TEXT NOT NULL) -> destination IP (Note: always use 'dst_ip', NOT 'dest_ip')\n"
            "- src_port (INTEGER), dst_port (INTEGER)\n"
            "- protocol (INTEGER) -> 6 for TCP, 17 for UDP\n"
            "- prediction (TEXT NOT NULL) -> threat class, one of: 'BENIGN', 'DoS', 'DDoS', 'PortScan'\n"
            "- detection_method (TEXT NOT NULL) -> detection method, one of: 'SIGNATURE', 'BEHAVIOR' (Note: always use 'detection_method', NOT 'method')\n"
            "- confidence (REAL NOT NULL) -> classification probability score\n"
            "- severity (TEXT NOT NULL) -> 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'\n\n"
            "Instructions:\n"
            "1. Generate a valid SQLite query to answer the user's question.\n"
            "2. Wrap your query inside markdown code blocks like this:\n"
            "```sql\n"
            "SELECT ...\n"
            "```\n"
            "3. Do NOT provide any explanations, comments, or extra text. Output ONLY the query inside markdown code blocks."
        )

        response = ollama.chat(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": question}
            ],
            options={"temperature": 0.0}  # Deterministic generation
        )
        
        return response["message"]["content"]

    def extract_sql(self, raw_response: str) -> str:
        """Helper to extract clean SQL string from markdown code blocks."""
        # Find block matches
        match = re.search(r"```sql\s*(.*?)\s*```", raw_response, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        # Fallback if markdown blocks were omitted
        return raw_response.strip()

    def synthesize_response(self, question: str, sql_used: str, headers: List[str], rows: List[Tuple[Any, ...]]) -> str:
        """
        Step B: Ask the local LLM to summarize query results into a clear operator report.
        """
        if ollama is None:
            raise ImportError("The 'ollama' Python library is not installed.")

        # Format database rows as raw context
        if not rows:
            data_context = "No records found in the database matching the criteria."
        else:
            # Format as a simple markdown table
            header_str = " | ".join(headers)
            separator = " | ".join(["---"] * len(headers))
            row_strs = [" | ".join(map(str, row)) for row in rows]
            data_context = f"{header_str}\n{separator}\n" + "\n".join(row_strs)

        system_prompt = (
            "You are an expert SOC Analyst reporting on the KryptaFlow Network Intrusion Detection System.\n"
            "Analyze the database query results and provide a clean, professional summary for the security operator.\n\n"
            "Requirements:\n"
            "1. Answer the operator's original question using only the provided database records.\n"
            "2. Mention the exact SQL query used for auditing transparency.\n"
            "3. If no records are found, state that politely.\n"
            "4. Keep the report concise and professional."
        )

        user_content = (
            f"Operator Question: {question}\n\n"
            f"SQL Query Executed:\n```sql\n{sql_used}\n```\n\n"
            f"Query Results:\n{data_context}"
        )

        response = ollama.chat(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            options={"temperature": 0.3}
        )
        
        return response["message"]["content"]

    def ask(self, question: str) -> str:
        """
        Full two-step agent workflow with complete exception handling.
        """
        if ollama is None:
            return (
                "⚠️ Error: The 'ollama' Python package is not installed. "
                "Please run `pip install ollama` to enable chatbot capabilities."
            )

        try:
            # Step 1: Generate SQL query from question
            raw_llm_sql = self.generate_sql(question)
            clean_sql = self.extract_sql(raw_llm_sql)
            
            if not clean_sql:
                return "⚠️ Sorry, I was unable to construct a valid database query for that question."
                
        except Exception as e:
            return f"⚠️ Error generating SQL query from local model: {str(e)}"

        try:
            # Step 2: Execute SQL in read-only mode
            headers, rows = execute_readonly_query(self.db_path, clean_sql)
        except sqlite3.Error as e:
            return (
                f"⚠️ Database Error: Failed to execute the generated query.\n"
                f"Generated SQL:\n```sql\n{clean_sql}\n```\n"
                f"Error Details: {str(e)}"
            )
        except Exception as e:
            return (
                f"⚠️ Security Error: The query failed safety checks.\n"
                f"Generated SQL:\n```sql\n{clean_sql}\n```\n"
                f"Error Details: {str(e)}"
            )

        try:
            # Step 3: Synthesize results back into natural language
            report = self.synthesize_response(question, clean_sql, headers, rows)
            return report
        except Exception as e:
            # Fallback formatting if synthesis fails
            data_summary = f"Query executed successfully: `{clean_sql}`\n\nResults:\n"
            if not rows:
                data_summary += "No matching records found."
            else:
                data_summary += f"Headers: {headers}\n"
                for r in rows:
                    data_summary += f"{r}\n"
            return (
                f"⚠️ Error synthesizing final response: {str(e)}\n\n"
                f"Raw Query Results:\n{data_summary}"
            )

if __name__ == "__main__":
    # Self-test code if executed directly
    print("[*] Initializing NIDSChatbot self-test...")
    bot = NIDSChatbot(model_name="llama3", db_path="../logs/ids_predictions.db" if not os.path.exists("logs/ids_predictions.db") else "logs/ids_predictions.db")
    
    # Try a simple read-only query check
    try:
        headers, rows = execute_readonly_query(bot.db_path, "SELECT * FROM predictions LIMIT 5;")
        print(f"[*] Read-Only Connection Test: Success! Columns: {headers}")
        print(f"[*] Sample Rows: {len(rows)} fetched.")
    except Exception as e:
        print(f"[!] Read-Only Connection Test Failed: {e}")
