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
from urllib.parse import urlparse

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


@dataclass(frozen=True)
class CheckModule:
    module_id: str
    title: str
    rationale: str
    trigger_terms: tuple[str, ...]
    config_checks: tuple[dict[str, Any], ...] = ()
    text_checks: tuple[dict[str, Any], ...] = ()
    inventory_checks: tuple[dict[str, Any], ...] = ()


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
            f"{target} backup restore configuration export",
            f"{target} firmware version diagnostics error codes",
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
                        f"{target} {phrase} site:automationdirect.com",
                    ]
                )
            file_terms.extend(self._build_project_specific_queries(target, context))
        queries = [*extra_queries, *base_queries, *file_terms]
        return list(dict.fromkeys(query for query in queries if query.strip()))[:18]

    def _build_project_specific_queries(self, target: str, context: LocalContextFile) -> List[str]:
        lowered = context.excerpt.lower()
        queries: List[str] = []
        if any(token in lowered for token in ("firmware", "_firmware_version", "firmware_version")):
            queries.extend(
                [
                    f"{target} firmware version error diagnostics",
                    f"{target} firmware version release notes",
                ]
            )
        if any(token in lowered for token in ("modbus", "port_2", "port_3", "received_data_len")):
            queries.extend(
                [
                    f"{target} modbus communication security",
                    f"{target} serial port hardening rs-232 rs-485",
                ]
            )
        if any(token in lowered for token in ("battery", "lost sdram data", "_plc error", "watchdog")):
            queries.extend(
                [
                    f"{target} watchdog battery low voltage troubleshooting",
                    f"{target} maintenance backup error history",
                ]
            )
        return queries

    def generate(self, target: str, local_paths: Sequence[Path], output_dir: Path, extra_queries: Sequence[str] | None = None) -> Dict[str, Path]:
        extra_queries = extra_queries or []
        local_files = self.collect_local_context(target, local_paths, extra_queries)
        queries = self.build_queries(target, local_files, extra_queries)
        web_docs = self.search(queries) if queries and self.web_tool._api_key else []

        summary = self._build_summary(target, local_files, web_docs, queries)
        plan = self._build_plan(target, local_files, web_docs)
        script = self._build_script(target, local_files, web_docs)
        change_set = self._build_proposed_hmi_change_set(target, local_files, web_docs)
        pre_change_checklist = self._build_pre_change_checklist(target, local_files, web_docs)
        runbook = self._build_operator_execution_runbook(target, local_files, web_docs)
        rollback_plan = self._build_rollback_plan(target, local_files, web_docs)
        verification_script = self._build_post_change_verification_script(target, local_files, web_docs)
        manifest = self._build_manifest(target, local_files, web_docs, queries)
        web_sources = self._build_web_sources(web_docs)

        output_dir.mkdir(parents=True, exist_ok=True)
        summary_path = output_dir / "security_research_brief.md"
        plan_path = output_dir / "generated_security_test_plan.md"
        script_name = f"{_sanitize_identifier(target)}_security_baseline.py"
        script_path = output_dir / script_name
        change_set_path = output_dir / "proposed_hmi_change_set.json"
        pre_change_path = output_dir / "pre_change_checklist.md"
        runbook_path = output_dir / "operator_execution_runbook.md"
        rollback_path = output_dir / "rollback_plan.md"
        verification_path = output_dir / f"{_sanitize_identifier(target)}_post_change_verification.py"
        manifest_path = output_dir / "offline_generation_manifest.json"
        web_sources_path = output_dir / "web_research_sources.json"

        summary_path.write_text(summary, encoding="utf-8")
        plan_path.write_text(plan, encoding="utf-8")
        script_path.write_text(script, encoding="utf-8")
        change_set_path.write_text(json.dumps(change_set, indent=2) + "\n", encoding="utf-8")
        pre_change_path.write_text(pre_change_checklist, encoding="utf-8")
        runbook_path.write_text(runbook, encoding="utf-8")
        rollback_path.write_text(rollback_plan, encoding="utf-8")
        verification_path.write_text(verification_script, encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        web_sources_path.write_text(json.dumps(web_sources, indent=2) + "\n", encoding="utf-8")
        os.chmod(script_path, 0o755)
        os.chmod(verification_path, 0o755)

        return {
            "summary": summary_path,
            "plan": plan_path,
            "script": script_path,
            "proposed_change_set": change_set_path,
            "pre_change_checklist": pre_change_path,
            "operator_runbook": runbook_path,
            "rollback_plan": rollback_path,
            "post_change_verification": verification_path,
            "manifest": manifest_path,
            "web_sources": web_sources_path,
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

    def _check_module_catalog(self) -> List[CheckModule]:
        return [
            CheckModule(
                module_id="default_accounts_review",
                title="Default account review",
                rationale="Defaults and shared credentials are high-risk in PLC environments.",
                trigger_terms=("default credentials", "default password", "accounts", "admin"),
                config_checks=(
                    {
                        "kind": "dict_value_empty",
                        "path": "accounts.default_accounts",
                        "severity": "FAIL",
                        "message": "default accounts are present",
                    },
                ),
                text_checks=(
                    {
                        "kind": "forbidden_substring",
                        "needles": ["default password", "admin:admin", "admin/admin"],
                        "severity": "WARN",
                        "message": "text export mentions a default credential pattern",
                    },
                ),
            ),
            CheckModule(
                module_id="password_policy",
                title="Password policy strength",
                rationale="Classroom systems should still demonstrate strong password policy configuration.",
                trigger_terms=("password", "credential", "policy"),
                config_checks=(
                    {
                        "kind": "min_int",
                        "path": "accounts.password_policy.min_length",
                        "min": 12,
                        "severity": "FAIL",
                        "message": "password minimum length is below 12",
                    },
                    {
                        "kind": "bool_true",
                        "path": "accounts.password_policy.complexity_enabled",
                        "severity": "WARN",
                        "message": "password complexity is not enabled",
                    },
                ),
            ),
            CheckModule(
                module_id="segmentation_and_subnets",
                title="Segmentation and management subnet restrictions",
                rationale="OT access should be narrowed to approved management paths.",
                trigger_terms=("network segmentation", "firewall", "vlan", "subnet", "dmz"),
                config_checks=(
                    {
                        "kind": "bool_true",
                        "path": "network.segmentation.enabled",
                        "severity": "WARN",
                        "message": "network segmentation is not enabled",
                    },
                    {
                        "kind": "non_empty",
                        "path": "network.allowed_management_subnets",
                        "severity": "WARN",
                        "message": "allowed management subnets are not defined",
                    },
                ),
            ),
            CheckModule(
                module_id="remote_admin_hardening",
                title="Remote administration hardening",
                rationale="Remote administration should be limited and tied to restricted paths.",
                trigger_terms=("remote administration", "remote access", "vpn", "ssh", "rdp"),
                config_checks=(
                    {
                        "kind": "bool_requires_non_empty",
                        "path": "services.remote_admin.enabled",
                        "requires_path": "network.allowed_management_subnets",
                        "severity": "WARN",
                        "message": "remote admin is enabled without allowed management subnets",
                    },
                ),
                inventory_checks=(
                    {
                        "kind": "service_exposure",
                        "services": ["ssh", "rdp", "vnc"],
                        "severity": "WARN",
                        "message": "remote administration service appears in inventory; verify restriction to approved paths",
                    },
                ),
            ),
            CheckModule(
                module_id="web_transport_security",
                title="Web management transport security",
                rationale="If a web interface exists, plaintext transport should be flagged.",
                trigger_terms=("unencrypted management", "http", "plaintext", "web"),
                config_checks=(
                    {
                        "kind": "bool_requires_true",
                        "path": "services.web.enabled",
                        "requires_path": "services.tls.enabled",
                        "severity": "WARN",
                        "message": "web management is enabled without TLS",
                    },
                ),
                inventory_checks=(
                    {
                        "kind": "service_exposure",
                        "services": ["http", "telnet"],
                        "severity": "WARN",
                        "message": "plaintext management service appears in inventory",
                    },
                    {
                        "kind": "public_exposure",
                        "severity": "FAIL",
                        "message": "public or internet exposure appears in inventory",
                    },
                ),
            ),
            CheckModule(
                module_id="industrial_protocol_review",
                title="Industrial protocol exposure review",
                rationale="Protocol availability should be documented and protected, especially Modbus-related paths.",
                trigger_terms=("industrial protocols", "modbus", "rs-232", "rs-485", "port_2", "port_3"),
                config_checks=(
                    {
                        "kind": "bool_requires_true",
                        "path": "services.modbus.enabled",
                        "requires_path": "services.modbus.secure_transport",
                        "severity": "WARN",
                        "message": "Modbus is enabled without a documented secure transport or tunnel flag",
                    },
                ),
                inventory_checks=(
                    {
                        "kind": "port_presence",
                        "ports": ["502"],
                        "severity": "WARN",
                        "message": "Modbus-related service appears in the service inventory",
                    },
                ),
            ),
            CheckModule(
                module_id="firmware_and_diagnostics",
                title="Firmware and diagnostic evidence capture",
                rationale="Version and diagnostic state should be captured in exported evidence for review.",
                trigger_terms=("firmware update", "firmware", "watchdog", "error code", "battery", "scan time"),
                text_checks=(
                    {
                        "kind": "required_substring",
                        "needles": ["firmware", "_firmware_version", "error", "watchdog"],
                        "severity": "INFO",
                        "message": "project text includes firmware/diagnostic indicators for follow-up review",
                    },
                ),
                config_checks=(
                    {
                        "kind": "non_empty",
                        "path": "controller.firmware_version",
                        "severity": "WARN",
                        "message": "controller firmware version is not captured in exports",
                    },
                ),
            ),
            CheckModule(
                module_id="backup_and_recovery_evidence",
                title="Backup and recovery evidence",
                rationale="Project backup and rollback evidence should exist before classroom changes are demonstrated.",
                trigger_terms=("backup", "restore", "project file", "recovery"),
                config_checks=(
                    {
                        "kind": "non_empty",
                        "path": "evidence.last_backup_date",
                        "severity": "WARN",
                        "message": "last backup date is not recorded in exported evidence",
                    },
                ),
            ),
        ]

    def _select_check_modules(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> List[CheckModule]:
        corpus_parts = [target.lower()]
        for item in local_files:
            corpus_parts.append(" ".join(item.indicators).lower())
            corpus_parts.append(" ".join(item.keyphrases).lower())
            corpus_parts.append(item.excerpt.lower())
        for item in web_docs[:12]:
            corpus_parts.append((item.get("title") or "").lower())
            corpus_parts.append((item.get("snippet") or "").lower())
        corpus = "\n".join(corpus_parts)

        selected: List[CheckModule] = []
        for module in self._check_module_catalog():
            if any(term.lower() in corpus for term in module.trigger_terms):
                selected.append(module)

        if not selected:
            selected = self._check_module_catalog()[:4]

        selected_ids = {module.module_id for module in selected}
        if "default_accounts_review" not in selected_ids:
            selected.insert(0, self._check_module_catalog()[0])
        if "password_policy" not in selected_ids:
            selected.insert(1, self._check_module_catalog()[1])

        deduped: List[CheckModule] = []
        seen = set()
        for module in selected:
            if module.module_id in seen:
                continue
            seen.add(module.module_id)
            deduped.append(module)
        return deduped

    def _build_summary(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
        queries: Sequence[str],
    ) -> str:
        modules = self._select_check_modules(target, local_files, web_docs)
        lines = [f"# Security Research Brief: {target}", "", "## Intent", ""]
        lines.append(
            "Generate defensive, authorized operator review packages using local project files and publicly available security guidance."
        )
        lines.extend(
            [
                "",
                "## Safety Boundary",
                "",
                "- Generation may use web research when configured.",
                "- Generated artifacts are offline-only and must not write to PLC, HMI, or field devices.",
                "- Outputs are intended for exported files, human-reviewed change packages, and post-change evidence review.",
            ]
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

        lines.extend(["", "## Selected Check Modules", ""])
        for module in modules:
            lines.append(f"- {module.title}")
            lines.append(f"  Module ID: `{module.module_id}`")
            lines.append(f"  Why selected: {module.rationale}")

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
        modules = self._select_check_modules(target, local_files, web_docs)
        lines = [
            f"# Generated Security Test Plan: {target}",
            "",
            "This plan is limited to authorized, defensive validation. It excludes exploitation, destructive testing, and automated writes to PLC/HMI systems.",
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
                "2. Review `web_research_sources.json` and trim any irrelevant public results before classroom use.",
                "3. Run the offline baseline checker against exported configs and service inventory data.",
                "4. Review `proposed_hmi_change_set.json` with a trained operator and confirm each value is appropriate for the classroom system.",
                "5. Complete `pre_change_checklist.md` before any manual HMI work.",
                "6. Follow `operator_execution_runbook.md` to apply the approved changes manually through the HMI.",
                "7. If needed, use `rollback_plan.md` to restore the previous settings.",
                "8. Run the post-change verification script to confirm the approved settings are present.",
                "",
                "## Offline Boundary",
                "",
                "- Do not point the generated scripts at live PLC write interfaces.",
                "- Do not add protocol write operations, forcing commands, or ladder-logic download steps.",
                "- Treat exported project/config files as the primary automation input for proposed changes.",
                "",
                "## Generated Artifacts",
                "",
                f"- `{_sanitize_identifier(target)}_security_baseline.py`",
                "- `proposed_hmi_change_set.json`",
                "- `pre_change_checklist.md`",
                "- `operator_execution_runbook.md`",
                "- `rollback_plan.md`",
                f"- `{_sanitize_identifier(target)}_post_change_verification.py`",
                "- `offline_generation_manifest.json`",
                "- `web_research_sources.json`",
                "",
                "## Selected Modules",
                "",
            ]
        )
        if modules:
            for module in modules:
                lines.append(f"- `{module.module_id}` | {module.title}")
            lines.append("")
        lines.extend(["## Web Sources", ""])
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
        modules = self._select_check_modules(target, local_files, web_docs)
        selected_modules = [
            {
                "module_id": module.module_id,
                "title": module.title,
                "rationale": module.rationale,
                "config_checks": list(module.config_checks),
                "text_checks": list(module.text_checks),
                "inventory_checks": list(module.inventory_checks),
            }
            for module in modules
        ]
        return f"""#!/usr/bin/env python3
\"\"\"Defensive baseline security validation script for {target}.

Authorized use only. This script performs non-destructive checks against
exported configurations and operator-supplied service inventory data.
It does not connect to or write to PLC, HMI, or field devices.
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
SELECTED_MODULES = {selected_modules!r}


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

    for path in sorted(config_dir.glob("*")):
        if path.suffix.lower() not in {{".json", ".txt", ".cfg", ".conf", ".yaml", ".yml"}}:
            continue
        try:
            data = load_structured_file(path)
        except Exception as exc:
            findings.append({{"severity": "WARN", "file": path.name, "check": "read", "detail": str(exc)}})
            continue

        if isinstance(data, dict):
            for module in SELECTED_MODULES:
                for check in module.get("config_checks", []):
                    findings.extend(run_config_check(path.name, data, module["module_id"], check))
        else:
            lowered = str(data).lower()
            for module in SELECTED_MODULES:
                for check in module.get("text_checks", []):
                    findings.extend(run_text_check(path.name, lowered, module["module_id"], check))
    return findings


def check_service_inventory(inventory_file: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not inventory_file.exists():
        return findings

    with inventory_file.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            for module in SELECTED_MODULES:
                for check in module.get("inventory_checks", []):
                    findings.extend(run_inventory_check(inventory_file.name, row, module["module_id"], check))
    return findings


def run_config_check(file_name: str, data: dict[str, Any], module_id: str, check: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    kind = check.get("kind")
    path = check.get("path", "")
    value = get_nested(data, path) if path else None
    severity = check.get("severity", "WARN")
    message = check.get("message", "check failed")

    if kind == "dict_value_empty" and value:
        findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{path}}", "detail": message}})
    elif kind == "min_int":
        if value is None:
            findings.append({{"severity": "WARN", "file": file_name, "check": f"{{module_id}}:{{path}}", "detail": "recommended setting missing"}})
        elif int(value) < int(check.get("min", 0)):
            findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{path}}", "detail": f"{{message}} (found {{value}})"}})
    elif kind == "bool_true" and value is not True:
        findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{path}}", "detail": message}})
    elif kind == "non_empty" and not value:
        findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{path}}", "detail": message}})
    elif kind == "bool_requires_non_empty":
        required_value = get_nested(data, check.get("requires_path", ""))
        if value is True and not required_value:
            findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{path}}", "detail": message}})
    elif kind == "bool_requires_true":
        required_value = get_nested(data, check.get("requires_path", ""))
        if value is True and required_value is not True:
            findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{path}}", "detail": message}})
    return findings


def run_text_check(file_name: str, lowered_text: str, module_id: str, check: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    needles = [needle.lower() for needle in check.get("needles", [])]
    severity = check.get("severity", "WARN")
    message = check.get("message", "text pattern matched")
    kind = check.get("kind")
    if kind == "forbidden_substring" and any(needle in lowered_text for needle in needles):
        findings.append({{"severity": severity, "file": file_name, "check": module_id, "detail": message}})
    elif kind == "required_substring" and any(needle in lowered_text for needle in needles):
        findings.append({{"severity": severity, "file": file_name, "check": module_id, "detail": message}})
    return findings


def run_inventory_check(file_name: str, row: dict[str, str], module_id: str, check: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    host = row.get("host", "unknown")
    port = str(row.get("port", "") or "")
    service = (row.get("service", "") or "").lower()
    exposure = (row.get("exposure", "") or "").lower()
    severity = check.get("severity", "WARN")
    message = check.get("message", "inventory pattern matched")
    kind = check.get("kind")

    if kind == "service_exposure":
        services = {{item.lower() for item in check.get("services", [])}}
        if service in services or port in services:
            findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{host}}", "detail": message}})
    elif kind == "public_exposure":
        if exposure in {{"internet", "public"}}:
            findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{host}}", "detail": message}})
    elif kind == "port_presence":
        ports = {{str(item) for item in check.get("ports", [])}}
        if port in ports:
            findings.append({{"severity": severity, "file": file_name, "check": f"{{module_id}}:{{host}}", "detail": message}})
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
        "Selected modules:",
        *[f"- {{module['module_id']}} | {{module['title']}}" for module in SELECTED_MODULES],
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

    def _build_proposed_hmi_change_set(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> Dict[str, Any]:
        modules = self._select_check_modules(target, local_files, web_docs)
        settings = []
        for module in modules:
            if module.module_id == "default_accounts_review":
                settings.append({
                    "setting_id": "accounts.default_accounts",
                    "location_hint": "HMI or engineering workstation account configuration screen",
                    "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                    "proposed_value": [],
                    "operator_action": "Disable, remove, or rename any default/shared accounts after confirming replacements exist.",
                    "rationale": module.rationale,
                })
            elif module.module_id == "password_policy":
                settings.extend([
                    {
                        "setting_id": "accounts.password_policy.min_length",
                        "location_hint": "HMI or engineering workstation password policy screen",
                        "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                        "proposed_value": 12,
                        "operator_action": "Set minimum password length to at least 12 if the platform supports it.",
                        "rationale": module.rationale,
                    },
                    {
                        "setting_id": "accounts.password_policy.complexity_enabled",
                        "location_hint": "HMI or engineering workstation password policy screen",
                        "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                        "proposed_value": True,
                        "operator_action": "Enable complexity requirements if the platform supports them.",
                        "rationale": module.rationale,
                    },
                ])
            elif module.module_id == "segmentation_and_subnets":
                settings.extend([
                    {
                        "setting_id": "network.segmentation.enabled",
                        "location_hint": "Network configuration screen or supporting gateway/firewall management view",
                        "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                        "proposed_value": True,
                        "operator_action": "Confirm network segmentation is enabled or documented in the classroom environment.",
                        "rationale": module.rationale,
                    },
                    {
                        "setting_id": "network.allowed_management_subnets",
                        "location_hint": "Management access control or allowlist configuration screen",
                        "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                        "proposed_value": ["TO_BE_FILLED_WITH_APPROVED_CLASSROOM_SUBNET"],
                        "operator_action": "Restrict management access to the approved classroom engineering subnet.",
                        "rationale": module.rationale,
                    },
                ])
            elif module.module_id == "remote_admin_hardening":
                settings.append({
                    "setting_id": "services.remote_admin.enabled",
                    "location_hint": "Remote access service configuration",
                    "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                    "proposed_value": False,
                    "operator_action": "Disable remote administration unless a documented classroom use case requires it.",
                    "rationale": module.rationale,
                })
            elif module.module_id == "web_transport_security":
                settings.extend([
                    {
                        "setting_id": "services.web.enabled",
                        "location_hint": "Embedded web management configuration",
                        "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                        "proposed_value": "REVIEW_REQUIRED",
                        "operator_action": "If web management is not needed, disable it. If needed, keep it restricted to approved management paths.",
                        "rationale": module.rationale,
                    },
                    {
                        "setting_id": "services.tls.enabled",
                        "location_hint": "Embedded web management configuration",
                        "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                        "proposed_value": True,
                        "operator_action": "Enable TLS or equivalent secure transport if web management remains enabled.",
                        "rationale": module.rationale,
                    },
                ])
            elif module.module_id == "industrial_protocol_review":
                settings.append({
                    "setting_id": "services.modbus.enabled",
                    "location_hint": "Protocol/service configuration",
                    "current_value": "TO_BE_RECORDED_BY_OPERATOR",
                    "proposed_value": "REVIEW_REQUIRED",
                    "operator_action": "Disable Modbus if it is not needed for the classroom exercise; otherwise document and protect the path.",
                    "rationale": module.rationale,
                })
        return {
            "target": target,
            "review_status": "draft_for_operator_review",
            "generated_from_modules": [module.module_id for module in modules],
            "required_human_checks": [
                "Confirm each current value before editing.",
                "Validate each proposed value against the classroom lesson objective.",
                "Reject any proposal that conflicts with vendor guidance or lab constraints.",
            ],
            "settings": settings,
        }

    def _build_pre_change_checklist(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> str:
        modules = self._select_check_modules(target, local_files, web_docs)
        lines = [
            f"# Pre-Change Checklist: {target}",
            "",
            "Complete this checklist before a trained operator makes any manual HMI changes.",
            "",
            "- Confirm the PLC is the classroom/test unit and not connected to production equipment.",
            "- Record the current value of every setting listed in `proposed_hmi_change_set.json`.",
            "- Capture screenshots or exports of each HMI page that will be edited.",
            "- Confirm a recent backup or restorable project file is available.",
            "- Confirm who is acting as operator, reviewer, and rollback owner.",
            "- Review the selected modules and remove any proposed change that does not fit the lesson or platform.",
            "- Confirm post-change evidence collection steps are ready before starting.",
            "",
            "## Modules In Scope",
            "",
        ]
        for module in modules:
            lines.append(f"- `{module.module_id}` | {module.title}")
        return "\n".join(lines) + "\n"

    def _build_operator_execution_runbook(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> str:
        indicators = sorted({indicator for item in local_files for indicator in item.indicators})
        evidence_links = [item.get("link", "") for item in web_docs[:8] if item.get("link")]
        lines = [
            f"# Operator Execution Runbook: {target}",
            "",
            "This runbook is human-in-the-loop only. It is intended for approved manual changes and explicitly excludes automated writes through HMI, PLC, or protocol interfaces.",
            "",
            "## Preconditions",
            "",
            "- Confirm `pre_change_checklist.md` is complete.",
            "- Confirm `proposed_hmi_change_set.json` has been reviewed and annotated with accepted/rejected items.",
            "- Confirm a current project backup and screenshot/export of relevant HMI settings.",
            "- Confirm rollback owner, operator, and sign-off owner.",
            "",
            "## Execution Sequence",
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
                "1. Open `proposed_hmi_change_set.json` and work through settings one at a time.",
                "2. On the HMI, navigate to the setting indicated by `location_hint`.",
                "3. Record the current value in the change log before editing.",
                "4. Manually apply the approved value only after confirming it matches the accepted proposal.",
                "5. Capture a screenshot or export showing the new value.",
                "6. Pause after each setting to confirm the classroom system remains healthy and expected alarms/status remain normal.",
                "7. When all accepted settings are complete, run the post-change verification script and attach the output to the exercise record.",
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

    def _build_rollback_plan(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
    ) -> str:
        lines = [
            f"# Rollback Plan: {target}",
            "",
            "Use this plan if a manual HMI change produces unexpected behavior.",
            "",
            "1. Stop applying additional settings immediately.",
            "2. Restore the most recent recorded pre-change value for the affected setting.",
            "3. If the setting cannot be restored individually, reload the saved classroom backup or project export using the vendor-supported process.",
            "4. Confirm the system returns to the pre-change state using screenshots, exports, and status indicators.",
            "5. Re-run the post-change verification script against the restored evidence and note which values were rolled back.",
            "6. Document the rollback trigger, affected setting, and final restored state.",
        ]
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
It is designed for offline evidence review only.
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

    def _build_manifest(
        self,
        target: str,
        local_files: Sequence[LocalContextFile],
        web_docs: Sequence[Dict[str, str]],
        queries: Sequence[str],
    ) -> Dict[str, Any]:
        modules = self._select_check_modules(target, local_files, web_docs)
        return {
            "target": target,
            "generation_mode": "web-informed offline-only",
            "safety_boundary": {
                "allow_web_research_during_generation": True,
                "allow_generated_artifact_network_access": False,
                "allow_generated_artifact_plc_writes": False,
                "allow_generated_artifact_hmi_writes": False,
                "allowed_inputs": [
                    "exported configuration files",
                    "operator-supplied service inventory CSV files",
                    "post-change evidence JSON files",
                ],
            },
            "query_count": len(queries),
            "local_context_files": [str(item.path) for item in local_files],
            "local_signals": sorted({indicator for item in local_files for indicator in item.indicators}),
            "selected_modules": [
                {
                    "module_id": module.module_id,
                    "title": module.title,
                    "rationale": module.rationale,
                }
                for module in modules
            ],
            "web_result_count": len(web_docs),
        }

    def _build_web_sources(self, web_docs: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
        sources: List[Dict[str, str]] = []
        for item in web_docs:
            link = (item.get("link") or "").strip()
            parsed = urlparse(link)
            sources.append(
                {
                    "title": (item.get("title") or "").strip(),
                    "link": link,
                    "domain": parsed.netloc.lower(),
                    "snippet": (item.get("snippet") or "").strip(),
                }
            )
        return sources


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
