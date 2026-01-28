# web_search_tool.py
import json
from typing import List, Dict
import asyncio
import logging

# -------------------------------------------------------------
# 1️⃣ Import the GoogleSearch client (works with the serpapi package)
# -------------------------------------------------------------
try:                     # 1️⃣  newer version: serpapi
    from serpapi import GoogleSearch
except Exception:
    try:                 # 2️⃣  older submodule
        from serpapi.serpapi import GoogleSearch
    except Exception:
        try:             # 3️⃣  the original google-search-results package
            from google_search_results import GoogleSearch
        except Exception as exc:
            raise ImportError(
                "Could not import GoogleSearch. "
                "Install it with `pip install serpapi` or "
                "`pip install google-search-results`."
            ) from exc

# -------------------------------------------------------------
# 2️⃣ Tool implementation that satisfies fairlib's AbstractTool
# -------------------------------------------------------------
from fairlib.core.interfaces.tools import AbstractTool

# ToolResult compatibility (path differs across versions, sometimes absent)
try:
    from fairlib.modules.action.tools.tool_result import ToolResult  # your original
except Exception:
    ToolResult = None  # we'll return a plain dict instead

import threading

def _run_coro_in_new_loop(coro):
    """Run an async coroutine in a dedicated event loop in a new thread and return its result."""
    result_container = {}
    exc_container = {}

    def runner():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result_container["result"] = loop.run_until_complete(coro)
        except Exception as e:
            exc_container["exc"] = e
        finally:
            try:
                loop.close()
            except Exception:
                pass

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join()

    if "exc" in exc_container:
        raise exc_container["exc"]
    return result_container.get("result")


class WebSearchTool(AbstractTool):
    name: str = "web_search"
    description: str = (
        "Searches the web (Google / SerpAPI) and returns a list of "
        "results with title, link and snippet."
    )

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key

    def use(self, arguments: str):
        logging.info(f"[WebSearchTool] called with: {arguments!r}")

        # fairlib ToolExecutor.execute() is sync, so we must return a *real* result synchronously
        # even though _run is async.
        return _run_coro_in_new_loop(self._run(arguments))



    async def _run(self, arguments: str):
        payload = {}
        query = None

        # Accept raw string query OR JSON {"query": "..."}
        if isinstance(arguments, str):
            s = arguments.strip()
            if s.startswith("{"):
                try:
                    payload = json.loads(s)
                    query = payload.get("query") or payload.get("q")
                except json.JSONDecodeError:
                    query = s  # fall back to raw string
            else:
                query = s
        elif isinstance(arguments, dict):
            payload = arguments
            query = payload.get("query") or payload.get("q")

        if not query:
            raise ValueError("WebSearchTool requires a query (raw string or JSON with 'query').")


        params: Dict[str, str] = {
            "engine": "google",
            "q": query,
            "api_key": self._api_key or "",
            "num": 10,
            "safe": 0,
        }
        if isinstance(payload, dict):
            params.update({k: v for k, v in payload.items() if k not in ("q", "query")})




        # SerpAPI client is sync; run in a thread so you don't block the event loop
        import asyncio
        search = GoogleSearch(params)
        results_dict = await asyncio.to_thread(search.get_dict)

        docs: List[Dict[str, str]] = [
            {
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
            }
            for item in results_dict.get("organic_results", [])
        ]

        # Return ToolResult if available; otherwise return a dict (often accepted)
        if ToolResult is not None:
            return ToolResult(tool_name=self.name, result=docs, is_success=True)

        return {"tool_name": self.name, "result": docs, "is_success": True}
