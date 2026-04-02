import argparse
import asyncio
import collections
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from dotenv import load_dotenv

try:
    from serpapi import GoogleSearch
except Exception:
    try:
        from serpapi.serpapi import GoogleSearch
    except Exception:
        try:
            from google_search_results import GoogleSearch
        except Exception as exc:
            raise ImportError(
                "Could not import GoogleSearch. "
                "Install it with `pip install serpapi` or "
                "`pip install google-search-results`."
            ) from exc

from fairlib.core.interfaces.tools import AbstractTool

try:
    from fairlib.modules.action.tools.tool_result import ToolResult
except Exception:
    ToolResult = None

try:
    from fairlib import KnowledgeBaseQueryTool, LongTermMemory, SentenceTransformerEmbedder, SimpleRetriever, settings
    from fairlib.modules.memory.retriever_rerank import CrossEncoderRerankingRetriever
    from fairlib.modules.memory.vector_faiss import FaissVectorStore
    from fairlib.utils.document_processor import DocumentProcessor
    from sentence_transformers import CrossEncoder
except Exception:
    KnowledgeBaseQueryTool = None
    LongTermMemory = None
    SentenceTransformerEmbedder = None
    SimpleRetriever = None
    settings = None
    CrossEncoderRerankingRetriever = None
    FaissVectorStore = None
    DocumentProcessor = None
    CrossEncoder = None


logger = logging.getLogger("security_script_agent")
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = BASE_DIR / "generated_security_scripts"


def _run_coro_in_new_loop(coro):
    """Run an async coroutine in a dedicated event loop in a new thread."""
    result_container: Dict[str, Any] = {}
    exc_container: Dict[str, Exception] = {}

    def runner():
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result_container["result"] = loop.run_until_complete(coro)
        except Exception as exc:
            exc_container["exc"] = exc
        finally:
            if loop is not None:
                try:
                    loop.close()
                except Exception:
                    pass

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()

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
        logger.info("[WebSearchTool] called with: %r", arguments)
        return _run_coro_in_new_loop(self._run(arguments))

    async def _run(self, arguments: str):
        payload: Dict[str, Any] = {}
        query = None

        if isinstance(arguments, str):
            stripped = arguments.strip()
            if stripped.startswith("{"):
                try:
                    payload = json.loads(stripped)
                    query = payload.get("query") or payload.get("q")
                except json.JSONDecodeError:
                    query = stripped
            else:
                query = stripped
        elif isinstance(arguments, dict):
            payload = arguments
            query = payload.get("query") or payload.get("q")

        if not query:
            raise ValueError("WebSearchTool requires a query (raw string or JSON with 'query').")

        params: Dict[str, Any] = {
            "engine": "google",
            "q": query,
            "api_key": self._api_key or "",
            "num": 10,
            "safe": "off",
        }
        params.update({k: v for k, v in payload.items() if k not in {"q", "query"}})

        if not params.get("api_key"):
            err = "SERPAPI api_key is missing."
            logger.error("[WebSearchTool] %s", err)
            if ToolResult is not None:
                return ToolResult(tool_name=self.name, result=[], is_success=False)
            return {"tool_name": self.name, "result": [], "is_success": False, "error": err}

        search = GoogleSearch(params)
        results_dict = await asyncio.to_thread(search.get_dict)
        if not isinstance(results_dict, dict):
            err = f"Unexpected SerpAPI response type: {type(results_dict)}"
            logger.error("[WebSearchTool] %s", err)
            if ToolResult is not None:
                return ToolResult(tool_name=self.name, result=[], is_success=False)
            return {"tool_name": self.name, "result": [], "is_success": False, "error": err}

        if results_dict.get("error"):
            err = str(results_dict["error"])
            logger.error("[WebSearchTool] SerpAPI error: %s", err)
            if ToolResult is not None:
                return ToolResult(tool_name=self.name, result=[], is_success=False)
            return {"tool_name": self.name, "result": [], "is_success": False, "error": err}

        docs = [
            {
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
            }
            for item in results_dict.get("organic_results", [])
        ]

        if ToolResult is not None:
            return ToolResult(tool_name=self.name, result=docs, is_success=True)
        return {"tool_name": self.name, "result": docs, "is_success": True}


def _load_env() -> str:
    load_dotenv(BASE_DIR / ".env")
    load_dotenv()
    return os.getenv("SERPAPI_KEY", "")


def _extract_tool_result(payload: Any) -> List[Any]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, str):
        return [payload] if payload.strip() else []
    if hasattr(payload, "result"):
        result = payload.result
        if isinstance(result, list):
            return result
        if isinstance(result, str):
            return [result] if result.strip() else []
    if isinstance(payload, dict):
        result = payload.get("result")
        if isinstance(result, list):
            return result
        if isinstance(result, str):
            return [result] if result.strip() else []
    return []


def _truncate(text: str, limit: int = 1200) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _dedupe_web_docs(web_docs: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    deduped = []
    for item in web_docs:
        link = (item.get("link") or "").strip()
        title = (item.get("title") or "").strip()
        key = link or title
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _sanitize_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "target"


@dataclass
class LocalContextFile:
    path: Path
    excerpt: str
    indicators: List[str]
    keyphrases: List[str]


@dataclass
class RagResources:
    knowledge_tool: Any
    index_dir: Path


class SecurityScriptAgent:
    """Agent-style workflow that combines web context and local files."""

    def __init__(self, web_tool: WebSearchTool) -> None:
        self.web_tool = web_tool

    def collect_local_context(
        self,
        target: str,
        paths: Sequence[Path],
        extra_queries: Sequence[str],
        max_chars: int = 4000,
    ) -> List[LocalContextFile]:
        rag_resources = self._setup_rag(paths)
        if rag_resources is not None:
            try:
                return self._collect_rag_context(target, extra_queries, rag_resources, max_chars=max_chars)
            finally:
                self._cleanup_rag(rag_resources.index_dir)

        logger.info("Falling back to direct file reads for local context.")
        return self._collect_direct_context(paths, max_chars=max_chars)

    def _collect_direct_context(self, paths: Sequence[Path], max_chars: int = 4000) -> List[LocalContextFile]:
        context_files: List[LocalContextFile] = []
        for path in paths:
            resolved = path.expanduser().resolve()
            if not resolved.exists() or not resolved.is_file():
                logger.warning("Skipping missing context file: %s", resolved)
                continue
            try:
                text = resolved.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                logger.warning("Skipping unreadable context file %s: %s", resolved, exc)
                continue
            excerpt = _truncate(text, max_chars)
            indicators = self._extract_indicators(excerpt)
            keyphrases = self._extract_keyphrases(excerpt)
            context_files.append(
                LocalContextFile(
                    path=resolved,
                    excerpt=excerpt,
                    indicators=indicators,
                    keyphrases=keyphrases,
                )
            )
        return context_files

    def _setup_rag(self, paths: Sequence[Path]) -> RagResources | None:
        if not paths:
            return None
        if not all(
            (
                KnowledgeBaseQueryTool,
                LongTermMemory,
                SentenceTransformerEmbedder,
                SimpleRetriever,
                settings,
                CrossEncoderRerankingRetriever,
                FaissVectorStore,
                DocumentProcessor,
                CrossEncoder,
            )
        ):
            logger.warning("RAG dependencies are unavailable. Using direct file reads instead.")
            return None

        rag_cfg = getattr(settings, "rag_system", None)
        index_dir = (BASE_DIR / "out" / f"script_agent_faiss_{os.getpid()}").resolve()
        index_dir.mkdir(parents=True, exist_ok=True)

        embed_model = getattr(
            getattr(rag_cfg, "embeddings", None),
            "embedding_model",
            "sentence-transformers/all-MiniLM-L6-v2",
        )
        cross_model = getattr(
            getattr(rag_cfg, "embeddings", None),
            "cross_encoder_model",
            "cross-encoder/ms-marco-MiniLM-L-6-v2",
        )
        use_gpu = getattr(getattr(rag_cfg, "vector_store", None), "use_gpu", False)
        batch_size = getattr(getattr(rag_cfg, "embeddings", None), "batch_size", 128)

        embedder = SentenceTransformerEmbedder(model_name=embed_model)
        vector_store = FaissVectorStore(
            embedder=embedder,
            index_dir=str(index_dir),
            use_gpu=use_gpu,
            normalize=True,
            batch_size=batch_size,
        )
        vector_store.load()
        long_term_memory = LongTermMemory(vector_store)
        base_retriever = SimpleRetriever(vector_store)
        cross_encoder = CrossEncoder(cross_model)
        retriever = CrossEncoderRerankingRetriever(base=base_retriever, cross_encoder=cross_encoder, rerank_k=12)
        processor = DocumentProcessor()

        all_documents = []
        for path in paths:
            resolved = path.expanduser().resolve()
            if not resolved.exists() or not resolved.is_file():
                logger.warning("Skipping missing context file during RAG setup: %s", resolved)
                continue
            try:
                all_documents.extend(processor.process_file(str(resolved)))
            except Exception as exc:
                logger.warning("Skipping document %s during RAG setup: %s", resolved, exc)

        if not all_documents:
            self._cleanup_rag(index_dir)
            return None

        long_term_memory.vector_store.add_documents(all_documents)
        logger.info("Indexed %d local chunks into FAISS for script generation.", len(all_documents))
        return RagResources(knowledge_tool=KnowledgeBaseQueryTool(retriever), index_dir=index_dir)

    def _collect_rag_context(
        self,
        target: str,
        extra_queries: Sequence[str],
        rag_resources: RagResources,
        max_chars: int = 4000,
    ) -> List[LocalContextFile]:
        seed_queries = [
            target,
            f"{target} security hardening",
            f"{target} configuration risks",
            *extra_queries[:3],
        ]
        seen = set()
        context_files: List[LocalContextFile] = []
        for query in dict.fromkeys(q for q in seed_queries if q.strip()):
            payload = rag_resources.knowledge_tool.use(query)
            docs = _extract_tool_result(payload)
            for item in docs[:6]:
                if hasattr(item, "page_content"):
                    text = str(getattr(item, "page_content", "")).strip()
                    meta = getattr(item, "metadata", {}) or {}
                elif isinstance(item, dict):
                    text = str(item.get("page_content") or item.get("content") or item.get("text") or "").strip()
                    meta = item.get("metadata", {}) or {}
                else:
                    text = str(item).strip()
                    meta = {}
                source = str(meta.get("source") or "retrieved_chunk")
                excerpt = _truncate(text, max_chars)
                key = (source, excerpt[:220])
                if not excerpt or key in seen:
                    continue
                seen.add(key)
                indicators = self._extract_indicators(excerpt)
                keyphrases = self._extract_keyphrases(excerpt)
                context_files.append(
                    LocalContextFile(
                        path=Path(source),
                        excerpt=excerpt,
                        indicators=indicators,
                        keyphrases=keyphrases,
                    )
                )
        return context_files

    def _cleanup_rag(self, index_dir: Path) -> None:
        try:
            import shutil

            if index_dir.exists() and index_dir.is_dir():
                shutil.rmtree(index_dir)
        except Exception as exc:
            logger.warning("Could not remove temporary FAISS store %s: %s", index_dir, exc)

    def search(self, queries: Sequence[str]) -> List[Dict[str, str]]:
        all_docs: List[Dict[str, str]] = []
        for query in queries:
            payload = self.web_tool.use(query)
            docs = _extract_tool_result(payload)
            logger.info("Web query returned %d results: %s", len(docs), query)
            all_docs.extend(doc for doc in docs if isinstance(doc, dict))
        deduped = _dedupe_web_docs(all_docs)
        return self._balance_domains(deduped)

    def build_queries(self, target: str, local_files: Sequence[LocalContextFile], extra_queries: Sequence[str]) -> List[str]:
        base_queries = [
            f"{target} security hardening guide",
            f"{target} vendor security advisory",
            f"{target} default credentials ports protocols",
            f"{target} installation manual security configuration",
            f"{target} network segmentation firewall guidance",
        ]
        file_terms: List[str] = []
        for context in local_files:
            for indicator in context.indicators[:2]:
                file_terms.extend(
                    [
                        f"{target} {indicator}",
                        f"{target} {indicator} site:automationdirect.com",
                        f"{target} {indicator} site:cisa.gov",
                    ]
                )
            for phrase in context.keyphrases[:3]:
                file_terms.extend(
                    [
                        f"{target} {phrase}",
                        f"{target} {phrase} security",
                    ]
                )
        queries = [*extra_queries, *base_queries, *file_terms]
        return list(dict.fromkeys(query for query in queries if query.strip()))[:18]

    def generate(self, target: str, local_paths: Sequence[Path], output_dir: Path, extra_queries: Sequence[str] | None = None) -> Dict[str, Path]:
        extra_queries = extra_queries or []
        local_files = self.collect_local_context(target, local_paths, extra_queries)
        queries = self.build_queries(target, local_files, extra_queries)
        web_docs = self.search(queries) if queries and self.web_tool._api_key else []

        summary = self._build_summary(target, local_files, web_docs, queries)
        plan = self._build_plan(target, local_files, web_docs)
        script = self._build_script(target, local_files, web_docs)
        read_only_script = self._build_read_only_hmi_validation_script(target, local_files, web_docs)
        runbook = self._build_approved_change_runbook(target, local_files, web_docs)
        verification_script = self._build_post_change_verification_script(target, local_files, web_docs)

        output_dir.mkdir(parents=True, exist_ok=True)
        summary_path = output_dir / "security_research_brief.md"
        plan_path = output_dir / "generated_security_test_plan.md"
        script_name = f"{_sanitize_identifier(target)}_security_baseline.py"
        script_path = output_dir / script_name
        read_only_path = output_dir / f"{_sanitize_identifier(target)}_read_only_hmi_validation.py"
        runbook_path = output_dir / "approved_change_runbook.md"
        verification_path = output_dir / f"{_sanitize_identifier(target)}_post_change_verification.py"

        summary_path.write_text(summary, encoding="utf-8")
        plan_path.write_text(plan, encoding="utf-8")
        script_path.write_text(script, encoding="utf-8")
        read_only_path.write_text(read_only_script, encoding="utf-8")
        runbook_path.write_text(runbook, encoding="utf-8")
        verification_path.write_text(verification_script, encoding="utf-8")
        os.chmod(script_path, 0o755)
        os.chmod(read_only_path, 0o755)
        os.chmod(verification_path, 0o755)

        return {
            "summary": summary_path,
            "plan": plan_path,
            "script": script_path,
            "read_only_validation": read_only_path,
            "change_runbook": runbook_path,
            "post_change_verification": verification_path,
        }

    def _extract_indicators(self, text: str) -> List[str]:
        patterns = {
            "default credentials": [r"default credential", r"default password", r"admin[:/ ]admin"],
            "network segmentation": [r"\bsegment", r"\bdmz\b", r"\bfirewall\b", r"\bvlan\b"],
            "unencrypted management": [r"plaintext", r"unencrypted", r"clear[- ]text", r"http\b", r"telnet\b"],
            "industrial protocols": [r"modbus", r"dnp3", r"ethernet/ip", r"profinet", r"opc ua"],
            "remote administration": [r"ssh\b", r"rdp\b", r"vpn\b", r"remote access"],
            "firmware update": [r"firmware", r"signed update", r"boot integrity", r"secure boot"],
        }
        lowered = text.lower()
        indicators = []
        for label, regexes in patterns.items():
            if any(re.search(regex, lowered) for regex in regexes):
                indicators.append(label)
        return indicators

    def _extract_keyphrases(self, text: str, max_phrases: int = 8) -> List[str]:
        stopwords = {
            "the", "and", "that", "with", "from", "this", "are", "for", "use", "using",
            "only", "into", "when", "than", "have", "has", "your", "their", "there",
            "also", "should", "could", "these", "those", "through", "about", "apply",
            "click", "plc", "security",
        }
        phrase_counts: collections.Counter[str] = collections.Counter()
        for match in re.findall(r"\b[a-zA-Z][a-zA-Z0-9/_-]{3,}\b(?:\s+\b[a-zA-Z][a-zA-Z0-9/_-]{3,}\b){0,2}", text):
            phrase = re.sub(r"\s+", " ", match.strip()).lower()
            tokens = phrase.split()
            if not tokens:
                continue
            if all(token in stopwords for token in tokens):
                continue
            if len(tokens) == 1 and tokens[0] in stopwords:
                continue
            phrase_counts[phrase] += 1
        return [phrase for phrase, _ in phrase_counts.most_common(max_phrases)]

    def _balance_domains(self, web_docs: Sequence[Dict[str, str]], max_per_domain: int = 2) -> List[Dict[str, str]]:
        domain_counts: Dict[str, int] = collections.defaultdict(int)
        balanced: List[Dict[str, str]] = []
        overflow: List[Dict[str, str]] = []
        for item in web_docs:
            link = (item.get("link") or "").strip()
            domain_match = re.search(r"https?://([^/]+)", link)
            domain = domain_match.group(1).lower() if domain_match else "unknown"
            domain = domain.removeprefix("www.")
            if domain_counts[domain] < max_per_domain:
                domain_counts[domain] += 1
                balanced.append(item)
            else:
                overflow.append(item)
        return balanced + overflow[:6]

    def _build_summary(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
        queries: Sequence[str],
    ) -> str:
        lines = [f"# Security Research Brief: {target}", "", "## Intent", ""]
        lines.append(
            "Generate defensive, authorized validation scripts using local project files and publicly available security guidance."
        )
        lines.extend(["", "## Local Context", ""])
        if not local_files:
            lines.append("- No local files were provided or readable.")
        for item in local_files:
            lines.append(f"- `{item.path}`")
            indicator_text = ", ".join(item.indicators) if item.indicators else "no strong indicators detected"
            lines.append(f"  Signals: {indicator_text}")
            if item.keyphrases:
                lines.append(f"  Keyphrases: {', '.join(item.keyphrases[:5])}")
            lines.append(f"  Excerpt: {_truncate(item.excerpt, 500)}")

        lines.extend(["", "## Queries Used", ""])
        for query in queries:
            lines.append(f"- {query}")

        lines.extend(["", "## Web Findings", ""])
        if not web_docs:
            lines.append("- No web results collected. Check `SERPAPI_KEY` if web context is expected.")
        for item in web_docs[:10]:
            title = item.get("title", "Untitled")
            link = item.get("link", "")
            snippet = _truncate(item.get("snippet", ""), 240)
            lines.append(f"- {title}")
            lines.append(f"  Link: {link}")
            lines.append(f"  Note: {snippet}")
        return "\n".join(lines) + "\n"

    def _build_plan(self, target: str, local_files: Sequence[LocalContextFile], web_docs: Sequence[Dict[str, str]]) -> str:
        indicators = sorted({indicator for item in local_files for indicator in item.indicators})
        lines = [
            f"# Generated Security Test Plan: {target}",
            "",
            "This plan is limited to authorized, defensive validation. It excludes exploitation and destructive testing.",
            "",
            "## Priorities",
            "",
        ]
        if indicators:
            for indicator in indicators:
                lines.append(f"- Validate controls related to {indicator}.")
        else:
            lines.append("- Validate exposure, authentication, transport security, and configuration hygiene.")

        lines.extend(
            [
                "",
                "## Recommended Sequence",
                "",
                "1. Review local configuration and implementation files for obvious security assumptions.",
                "2. Run the offline baseline checker against exported configs and service inventory data.",
                "3. Run the read-only HMI validation script to collect current settings and evidence without making changes.",
                "4. Use the approved change runbook for human-reviewed, manual changes only.",
                "5. Run the post-change verification script to confirm the approved settings are present.",
                "",
                "## Generated Artifacts",
                "",
                f"- `{_sanitize_identifier(target)}_security_baseline.py`",
                f"- `{_sanitize_identifier(target)}_read_only_hmi_validation.py`",
                "- `approved_change_runbook.md`",
                f"- `{_sanitize_identifier(target)}_post_change_verification.py`",
                "",
                "## Web Sources",
                "",
            ]
        )
        if not web_docs:
            lines.append("- None collected.")
        else:
            for item in web_docs[:10]:
                lines.append(f"- {item.get('title', 'Untitled')} | {item.get('link', '')}")
        return "\n".join(lines) + "\n"

    def _build_script(self, target: str, local_files: Sequence[LocalContextFile], web_docs: Sequence[Dict[str, str]]) -> str:
        indicator_map = sorted({indicator for item in local_files for indicator in item.indicators})
        evidence_links = [item.get("link", "") for item in web_docs[:8] if item.get("link")]
        target_slug = _sanitize_identifier(target)
        return f"""#!/usr/bin/env python3
\"\"\"Defensive baseline security validation script for {target}.

Authorized use only. This script performs non-destructive checks against
exported configurations and operator-supplied service inventory data.
\"\"\"

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


TARGET_NAME = {target!r}
TARGET_SLUG = {target_slug!r}
LOCAL_SIGNALS = {indicator_map!r}
REFERENCE_LINKS = {evidence_links!r}


def load_structured_file(path: Path) -> Any:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="ignore")
    if suffix == ".json":
        return json.loads(text)
    return text


def get_nested(data: Any, dotted_key: str) -> Any:
    current = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def check_config_exports(config_dir: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    required_keys = [
        "accounts",
        "services",
        "network",
    ]
    recommended_paths = [
        "accounts.default_accounts",
        "accounts.password_policy.min_length",
        "network.allowed_management_subnets",
        "network.segmentation.enabled",
        "services.remote_admin.enabled",
        "services.web.enabled",
        "services.modbus.enabled",
        "services.tls.enabled",
    ]

    for path in sorted(config_dir.glob("*")):
        if path.suffix.lower() not in {{".json", ".txt", ".cfg", ".conf", ".yaml", ".yml"}}:
            continue
        try:
            data = load_structured_file(path)
        except Exception as exc:
            findings.append({{"severity": "WARN", "file": path.name, "check": "read", "detail": str(exc)}})
            continue

        if isinstance(data, dict):
            for key in required_keys:
                if key not in data:
                    findings.append({{"severity": "WARN", "file": path.name, "check": key, "detail": "missing top-level section"}})
            for dotted in recommended_paths:
                if get_nested(data, dotted) is None:
                    findings.append({{"severity": "WARN", "file": path.name, "check": dotted, "detail": "missing recommended setting"}})

            min_length = get_nested(data, "accounts.password_policy.min_length")
            if isinstance(min_length, int) and min_length < 12:
                findings.append({{"severity": "FAIL", "file": path.name, "check": "password length", "detail": f"min length {{min_length}} < 12"}})

            default_accounts = get_nested(data, "accounts.default_accounts")
            if default_accounts:
                findings.append({{"severity": "FAIL", "file": path.name, "check": "default accounts", "detail": f"present: {{default_accounts}}"}})

            remote_admin = get_nested(data, "services.remote_admin.enabled")
            allowed_subnets = get_nested(data, "network.allowed_management_subnets")
            if remote_admin and not allowed_subnets:
                findings.append({{"severity": "WARN", "file": path.name, "check": "remote admin restrictions", "detail": "enabled without allowed_management_subnets"}})

            tls_enabled = get_nested(data, "services.tls.enabled")
            web_enabled = get_nested(data, "services.web.enabled")
            if web_enabled and not tls_enabled:
                findings.append({{"severity": "WARN", "file": path.name, "check": "web transport", "detail": "web enabled without tls.enabled"}})
        else:
            lowered = str(data).lower()
            if "password" in lowered and "default" in lowered:
                findings.append({{"severity": "WARN", "file": path.name, "check": "plaintext review", "detail": "mentions default password"}})
            if "telnet" in lowered or "http://" in lowered:
                findings.append({{"severity": "WARN", "file": path.name, "check": "plaintext protocols", "detail": "mentions insecure management protocol"}})
    return findings


def check_service_inventory(inventory_file: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not inventory_file.exists():
        return findings

    with inventory_file.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            host = row.get("host", "unknown")
            port = row.get("port", "")
            service = (row.get("service", "") or "").lower()
            exposure = (row.get("exposure", "") or "").lower()

            if port in {{"23", "80"}} or service in {{"telnet", "http"}}:
                findings.append({{"severity": "WARN", "file": inventory_file.name, "check": f"host {{host}}", "detail": f"insecure management service {{service or port}}"}})
            if exposure in {{"internet", "public"}}:
                findings.append({{"severity": "FAIL", "file": inventory_file.name, "check": f"host {{host}}", "detail": "publicly exposed management path"}})
    return findings


def write_report(findings: list[dict[str, str]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Target: {{TARGET_NAME}}",
        "Authorized defensive baseline results",
        "",
        "Signals from source material:",
        *[f"- {{item}}" for item in LOCAL_SIGNALS],
        "",
        "Reference links:",
        *[f"- {{link}}" for link in REFERENCE_LINKS],
        "",
        "Findings:",
    ]
    if not findings:
        lines.append("- PASS: no baseline issues detected by the generated checks.")
    for finding in findings:
        lines.append(
            f"- {{finding['severity']}} | {{finding['file']}} | {{finding['check']}} | {{finding['detail']}}"
        )
    output.write_text("\\n".join(lines) + "\\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run defensive baseline checks for authorized security validation.")
    parser.add_argument("--config-dir", default="config_exports", help="Directory containing exported configs.")
    parser.add_argument("--inventory-csv", default="service_inventory.csv", help="CSV with host,port,service,exposure columns.")
    parser.add_argument("--output", default=f"{{TARGET_SLUG}}_security_report.txt", help="Output report path.")
    args = parser.parse_args()

    findings = []
    findings.extend(check_config_exports(Path(args.config_dir)))
    findings.extend(check_service_inventory(Path(args.inventory_csv)))
    write_report(findings, Path(args.output))


if __name__ == "__main__":
    main()
"""

    def _build_read_only_hmi_validation_script(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> str:
        indicator_map = sorted({indicator for item in local_files for indicator in item.indicators})
        evidence_links = [item.get("link", "") for item in web_docs[:8] if item.get("link")]
        target_slug = _sanitize_identifier(target)
        return f"""#!/usr/bin/env python3
\"\"\"Read-only HMI/PLC validation helper for {target}.

Authorized use only. This script does not send write operations. It records
operator-supplied observations and validates them against a defensive baseline.
\"\"\"

from __future__ import annotations

import argparse
import csv
from pathlib import Path


TARGET_NAME = {target!r}
LOCAL_SIGNALS = {indicator_map!r}
REFERENCE_LINKS = {evidence_links!r}
EXPECTED_CHECKS = [
    "default accounts disabled",
    "strong password policy configured",
    "management access restricted to approved subnets",
    "unused services disabled",
    "secure transport enabled where supported",
]


def evaluate_observations(observation_csv: Path) -> list[str]:
    findings: list[str] = []
    if not observation_csv.exists():
        return ["WARN | observations | file missing; no read-only HMI observations were provided"]

    with observation_csv.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        observed = list(reader)

    for check in EXPECTED_CHECKS:
        matched = next((row for row in observed if (row.get("check") or "").strip().lower() == check), None)
        if not matched:
            findings.append(f"WARN | {{check}} | not captured")
            continue
        status = (matched.get("status") or "").strip().lower()
        detail = (matched.get("detail") or "").strip() or "no detail provided"
        if status not in {{"pass", "ok", "true", "yes"}}:
            findings.append(f"FAIL | {{check}} | {{detail}}")
    return findings


def write_report(output: Path, findings: list[str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Target: {{TARGET_NAME}}",
        "Read-only HMI validation report",
        "",
        "Signals:",
        *[f"- {{item}}" for item in LOCAL_SIGNALS],
        "",
        "Reference links:",
        *[f"- {{link}}" for link in REFERENCE_LINKS],
        "",
        "Expected checks:",
        *[f"- {{item}}" for item in EXPECTED_CHECKS],
        "",
        "Findings:",
    ]
    if not findings:
        lines.append("- PASS | all supplied read-only checks matched the expected baseline")
    else:
        lines.extend(f"- {{finding}}" for finding in findings)
    output.write_text("\\n".join(lines) + "\\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate operator-recorded HMI observations without changing settings.")
    parser.add_argument("--observations", default="hmi_read_only_observations.csv", help="CSV with check,status,detail columns.")
    parser.add_argument("--output", default="{target_slug}_read_only_hmi_report.txt", help="Output report path.")
    args = parser.parse_args()

    findings = evaluate_observations(Path(args.observations))
    write_report(Path(args.output), findings)


if __name__ == "__main__":
    main()
"""

    def _build_approved_change_runbook(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> str:
        indicators = sorted({indicator for item in local_files for indicator in item.indicators})
        evidence_links = [item.get("link", "") for item in web_docs[:8] if item.get("link")]
        lines = [
            f"# Approved Change Runbook: {target}",
            "",
            "This runbook is human-in-the-loop only. It is intended for approved manual changes and explicitly excludes automated writes through HMI, PLC, or protocol interfaces.",
            "",
            "## Preconditions",
            "",
            "- Confirm written authorization and maintenance window approval.",
            "- Confirm a current project backup and screenshot/export of relevant HMI settings.",
            "- Confirm rollback owner, test owner, and sign-off owner.",
            "- Confirm the read-only validation report has been collected.",
            "",
            "## Recommended Change Themes",
            "",
        ]
        if indicators:
            lines.extend(f"- Review settings related to {indicator}." for indicator in indicators)
        else:
            lines.append("- Review authentication, exposure, transport security, and service enablement settings.")
        lines.extend(
            [
                "",
                "## Manual Procedure Template",
                "",
                "1. Record the current value of the target setting in the change log.",
                "2. Apply the approved value manually through the vendor-supported interface.",
                "3. Capture screenshots or exports of the updated value.",
                "4. Verify system state remains healthy and expected alarms/status remain normal.",
                "5. Run the post-change verification script and attach the output to the change ticket.",
                "",
                "## Rollback Template",
                "",
                "1. Restore the previously recorded setting value.",
                "2. Reapply the saved project or backup if a single-setting rollback is insufficient.",
                "3. Re-run read-only validation and post-change verification to confirm restoration.",
                "",
                "## Reference Links",
                "",
            ]
        )
        if evidence_links:
            lines.extend(f"- {link}" for link in evidence_links)
        else:
            lines.append("- None collected.")
        return "\n".join(lines) + "\n"

    def _build_post_change_verification_script(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> str:
        indicator_map = sorted({indicator for item in local_files for indicator in item.indicators})
        target_slug = _sanitize_identifier(target)
        return f"""#!/usr/bin/env python3
\"\"\"Post-change verification helper for {target}.

Authorized use only. This script validates recorded post-change evidence and
does not send write operations to PLC or HMI systems.
\"\"\"

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TARGET_NAME = {target!r}
LOCAL_SIGNALS = {indicator_map!r}
REQUIRED_EXPECTATIONS = {{
    "default_accounts_disabled": True,
    "password_min_length": 12,
    "management_subnets_defined": True,
    "secure_transport_enabled": True,
}}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {{}}
    return json.loads(path.read_text(encoding="utf-8"))


def verify(data: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if data.get("default_accounts_disabled") is not True:
        findings.append("FAIL | default_accounts_disabled | expected true")
    if int(data.get("password_min_length", 0) or 0) < REQUIRED_EXPECTATIONS["password_min_length"]:
        findings.append("FAIL | password_min_length | expected >= 12")
    if data.get("management_subnets_defined") is not True:
        findings.append("FAIL | management_subnets_defined | expected true")
    if data.get("secure_transport_enabled") is not True:
        findings.append("WARN | secure_transport_enabled | expected true when supported")
    return findings


def write_report(output: Path, findings: list[str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Target: {{TARGET_NAME}}",
        "Post-change verification report",
        "",
        "Signals:",
        *[f"- {{item}}" for item in LOCAL_SIGNALS],
        "",
        "Findings:",
    ]
    if not findings:
        lines.append("- PASS | supplied post-change evidence satisfies the baseline checks")
    else:
        lines.extend(f"- {{finding}}" for finding in findings)
    output.write_text("\\n".join(lines) + "\\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate supplied post-change evidence without changing PLC or HMI settings.")
    parser.add_argument("--evidence-json", default="post_change_observations.json", help="JSON with post-change observation fields.")
    parser.add_argument("--output", default="{target_slug}_post_change_verification.txt", help="Output report path.")
    args = parser.parse_args()

    data = load_json(Path(args.evidence_json))
    findings = verify(data)
    write_report(Path(args.output), findings)


if __name__ == "__main__":
    main()
"""


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search the web and local files to generate defensive security test artifacts."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="System, product, or environment to assess.",
    )
    parser.add_argument(
        "--context-file",
        action="append",
        default=[],
        help="Local file to use as evidence. Can be passed multiple times.",
    )
    parser.add_argument(
        "--query",
        action="append",
        default=[],
        help="Extra web query to run before generating artifacts.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory to write the generated brief, plan, and script.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s - %(levelname)s - %(message)s")

    api_key = _load_env()
    if not api_key:
        logger.warning("SERPAPI_KEY is not set. Proceeding with local-file context only.")

    web_tool = WebSearchTool(api_key=api_key)
    agent = SecurityScriptAgent(web_tool=web_tool)
    output_paths = agent.generate(
        target=args.target,
        local_paths=[Path(path) for path in args.context_file],
        output_dir=Path(args.output_dir),
        extra_queries=args.query,
    )

    for label, path in output_paths.items():
        print(f"{label}: {path}")


if __name__ == "__main__":
    main()
