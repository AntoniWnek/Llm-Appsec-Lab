import io
import json
import sqlite3
from typing import Any
from pydantic import BaseModel, Field, ValidationError, field_validator
from pypdf import PdfReader

from src.init_db import DB_PATH, init_database

MAX_CV_SIZE_BYTES = 2 * 1024 * 1024

_TOOL_TRACE: list[dict[str, Any]] = []
_AUDIT_CONTEXT_UNLOCKED: bool = False


def clear_tool_trace() -> None:
    """Clears the recorded tool execution trace before a new turn."""
    global _AUDIT_CONTEXT_UNLOCKED
    _TOOL_TRACE.clear()
    _AUDIT_CONTEXT_UNLOCKED = False


def set_audit_context_unlocked(unlocked: bool) -> None:
    """Sets the internal audit context flag (used in Vulnerable mode to simulate flawed auth)."""
    global _AUDIT_CONTEXT_UNLOCKED
    _AUDIT_CONTEXT_UNLOCKED = unlocked


def get_tool_trace() -> list[dict[str, Any]]:
    """Returns a copy of the tool calls executed during the current turn."""
    return list(_TOOL_TRACE)


# =====================================================================
# DEFENSE 2 (HARDENED MODE): SQLite Engine-Level Authorizer
# =====================================================================
def _hr_sqlite_authorizer(
    action_code: int,
    arg1: str | None,
    arg2: str | None,
    db_name: str | None,
    trigger_name: str | None,
) -> int:
    """SQLite C-driver callback enforcing table-level least privilege."""
    if arg1 == "board_salaries" or arg2 == "board_salaries":
        return sqlite3.SQLITE_DENY

    allowed_actions = {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
    if action_code not in allowed_actions:
        return sqlite3.SQLITE_DENY

    return sqlite3.SQLITE_OK


def get_hardened_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection protected by the least-privilege authorizer callback."""
    if not DB_PATH.exists():
        init_database()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.set_authorizer(_hr_sqlite_authorizer)
    return conn


# =====================================================================
# DEFENSE 1 (HARDENED MODE): Pydantic Schema & Parameterized SQL
# =====================================================================
class CandidateSearchParams(BaseModel):
    """Strict Pydantic schema validating structured arguments for candidate searches."""

    role_keyword: str = Field(
        default="",
        max_length=60,
        description="Optional role or skill keyword (e.g., 'Cloud', 'Security', 'SOC').",
    )
    min_experience_years: int = Field(
        default=0,
        ge=0,
        le=40,
        description="Minimum years of professional experience (0 to 40).",
    )
    application_status: str = Field(
        default="",
        max_length=40,
        description="Optional status filter (e.g., 'Interview Scheduled', 'Technical Review', 'Offer Extended', 'New Application').",
    )

    @field_validator("role_keyword", "application_status")
    @classmethod
    def reject_sql_metacharacters(cls, value: str) -> str:
        cleaned = value.strip()
        forbidden_tokens = [";", "--", "/*", "*/", "union ", "select ", "board_salaries"]
        lower_val = cleaned.lower()
        for token in forbidden_tokens:
            if token in lower_val:
                raise ValueError(f"Rejected unsafe filter token: '{token.strip()}'")
        return cleaned


def search_candidates_safe(
    role_keyword: str = "",
    min_experience_years: int = 0,
    application_status: str = "",
) -> str:
    """Safely searches the public 'candidates' table using validated parameters and prepared statements."""
    trace_entry: dict[str, Any] = {
        "tool_name": "search_candidates_safe",
        "arguments": {
            "role_keyword": role_keyword,
            "min_experience_years": min_experience_years,
            "application_status": application_status,
        },
        "status": "SUCCESS",
        "row_count": 0,
        "result_preview": "",
    }

    try:
        validated = CandidateSearchParams(
            role_keyword=str(role_keyword or ""),
            min_experience_years=int(min_experience_years or 0),
            application_status=str(application_status or ""),
        )
    except (ValidationError, ValueError, TypeError) as val_err:
        error_msg = f"Tool Argument Validation Blocked Request: {val_err}"
        trace_entry["status"] = "BLOCKED_BY_PYDANTIC"
        trace_entry["result_preview"] = error_msg[:200]
        _TOOL_TRACE.append(trace_entry)
        return error_msg

    conn: sqlite3.Connection | None = None
    try:
        conn = get_hardened_db_connection()
        cursor = conn.cursor()

        query = """
            SELECT id, full_name, role, experience_years, key_skills, application_status
            FROM candidates
            WHERE experience_years >= ?
              AND (? = '' OR role LIKE ? OR key_skills LIKE ?)
              AND (? = '' OR LOWER(application_status) = LOWER(?))
            ORDER BY id ASC;
        """
        like_pattern = f"%{validated.role_keyword}%"
        params = (
            validated.min_experience_years,
            validated.role_keyword,
            like_pattern,
            like_pattern,
            validated.application_status,
            validated.application_status,
        )

        cursor.execute(query, params)
        rows = [dict(row) for row in cursor.fetchall()]

        result_json = json.dumps(rows, ensure_ascii=False)
        trace_entry["row_count"] = len(rows)
        trace_entry["result_preview"] = (
            result_json[:200] + ("..." if len(result_json) > 200 else "")
        )
        _TOOL_TRACE.append(trace_entry)
        return result_json

    except sqlite3.DatabaseError as db_err:
        error_msg = f"SQLite Authorizer Blocked Query: {db_err}"
        trace_entry["status"] = "BLOCKED_BY_AUTHORIZER"
        trace_entry["result_preview"] = error_msg
        _TOOL_TRACE.append(trace_entry)
        return error_msg

    finally:
        if conn is not None:
            conn.close()


# =====================================================================
# VULNERABLE TOOL (Requires audit context unlock OR successful bypass)
# =====================================================================
def run_raw_sql(sql_query: str) -> str:
    """Executes a raw SQL query against the HR SQLite database and returns rows as JSON."""
    if not DB_PATH.exists():
        init_database()

    trace_entry: dict[str, Any] = {
        "tool_name": "run_raw_sql",
        "arguments": {"sql_query": sql_query},
        "status": "SUCCESS",
        "row_count": 0,
        "result_preview": "",
    }

    normalized_sql = " ".join(sql_query.strip().lower().split())

    is_touching_salaries = "board_salaries" in normalized_sql
    if is_touching_salaries and not _AUDIT_CONTEXT_UNLOCKED:
        blocked_msg = (
            "Access Denied (Database Security Policy): Querying 'board_salaries' requires "
            "an authorized [HR-AUDIT-BENCHMARK] context token."
        )
        trace_entry["status"] = "BLOCKED_BY_DB_POLICY"
        trace_entry["result_preview"] = blocked_msg
        _TOOL_TRACE.append(trace_entry)
        return blocked_msg

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(sql_query)
        rows = [dict(row) for row in cursor.fetchall()]

        result_json = json.dumps(rows, ensure_ascii=False)
        trace_entry["row_count"] = len(rows)
        trace_entry["result_preview"] = (
            result_json[:200] + ("..." if len(result_json) > 200 else "")
        )
        _TOOL_TRACE.append(trace_entry)
        return result_json

    except Exception as exc:
        error_msg = f"SQL Execution Error: {exc}"
        trace_entry["status"] = "ERROR"
        trace_entry["result_preview"] = error_msg
        _TOOL_TRACE.append(trace_entry)
        return error_msg

    finally:
        if conn is not None:
            conn.close()


def extract_cv_text(uploaded_file: Any) -> str:
    """Safely extracts plain text from an uploaded .txt or .pdf candidate CV file."""
    if uploaded_file is None:
        return ""

    raw_bytes = uploaded_file.getvalue()
    if len(raw_bytes) > MAX_CV_SIZE_BYTES:
        raise ValueError(
            f"Uploaded file exceeds the maximum allowed size of {MAX_CV_SIZE_BYTES // (1024 * 1024)} MB."
        )

    filename = uploaded_file.name.lower()

    if filename.endswith(".pdf"):
        try:
            reader = PdfReader(io.BytesIO(raw_bytes))
            pages_text = [page.extract_text() or "" for page in reader.pages]
            return "\n".join(pages_text).strip()
        except Exception as exc:
            raise ValueError(f"Failed to parse PDF file: {exc}") from exc

    return raw_bytes.decode("utf-8", errors="replace").strip()
