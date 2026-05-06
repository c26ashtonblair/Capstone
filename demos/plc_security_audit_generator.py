"""Generate defensive PLC security audit scripts from local docs + web context.

This tool does NOT generate exploit code. It produces defensive scripts/checklists
for authorized security assessments in OT environments.
"""

import argparse
import json
import logging
import os
import re
import shutil
from pathlib import Path

from dotenv import load_dotenv
from fairlib import KnowledgeBaseQueryTool, LongTermMemory, SentenceTransformerEmbedder, SimpleRetriever, settings
from fairlib.modules.memory.retriever_rerank import CrossEncoderRerankingRetriever
from fairlib.modules.memory.vector_faiss import FaissVectorStore
from fairlib.utils.document_processor import DocumentProcessor
from sentence_transformers import CrossEncoder

from web_search_tool import WebSearchTool

try:
    from fairlib import HuggingFaceAdapter
except ImportError:
    HuggingFaceAdapter = None


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("plc_security_audit_generator")

BASE_DIR = Path(__file__).resolve().parent
DOCS_ROOT = BASE_DIR / "docs"
OUTPUT_DIR = BASE_DIR / "generated_security_audit"
SUPPORTED_DOC_SUFFIXES = {".md", ".txt", ".pdf", ".docx"}
CHAT_SYSTEM_PROMPT = """
You are a defensive PLC security audit assistant.
Answer only with information supported by the retrieved knowledge-base and web context provided to you.
If the answer is not supported by the provided context, say that it is not present in the knowledge base.
Keep answers practical, concise, and clearly grounded in the retrieved sources.
""".strip()


class ChatMessage:
    """Fallback ChatMessage shim for older fairlib versions."""

    def __init__(self, role: str, content: str):
        self.role = role
        self.content = content

    def to_dict(self):
        return {"role": self.role, "content": self.content}


def _load_env() -> str:
    load_dotenv(BASE_DIR / ".env")
    load_dotenv()
    key = os.getenv("SERPAPI_KEY", "")
    if not key:
        raise RuntimeError("SERPAPI_KEY not found. Add it to demos/.env.")
    return key


def _extract_tool_result(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, str):
        return [payload.strip()] if payload.strip() else []
    if hasattr(payload, "result"):
        result = payload.result
        if isinstance(result, list):
            return result
        if isinstance(result, str):
            return [result.strip()] if result.strip() else []
    if isinstance(payload, dict):
        for key in ("result", "observation", "content", "data"):
            value = payload.get(key)
            if not value:
                continue
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                return [value]
            return [str(value)]
    return []


def _format_local_context(local_docs, max_items: int = 8) -> str:
    if not local_docs:
        return "No local retrieval results available."
    lines = []
    for idx, item in enumerate(local_docs[:max_items], start=1):
        if hasattr(item, "page_content"):
            text = str(getattr(item, "page_content", "")).strip()
            meta = getattr(item, "metadata", {}) or {}
        elif isinstance(item, dict):
            text = str(item.get("page_content") or item.get("content") or item.get("text") or "").strip()
            meta = item.get("metadata", {}) or {}
        else:
            text = str(item).strip()
            meta = {}
        source = meta.get("source", "UNKNOWN_SOURCE")
        excerpt = (text[:900] + "...") if len(text) > 900 else text
        lines.append(f"{idx}. Source: {source}\\nExcerpt: {excerpt}")
    return "\\n\\n".join(lines)


def _dedupe_web_docs(all_docs):
    seen = set()
    deduped = []
    for item in all_docs:
        if not isinstance(item, dict):
            continue
        link = (item.get("link") or "").strip()
        key = link or (item.get("title") or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _filter_relevant_web_docs(web_docs):
    keywords = {
        "click", "plc", "automationdirect", "industrial", "ics", "scada",
        "modbus", "ethernet", "firmware", "default", "credential", "password",
        "segmentation", "firewall", "ot security",
    }
    filtered = []
    for item in web_docs:
        title = (item.get("title") or "").lower()
        snippet = (item.get("snippet") or "").lower()
        text = f"{title} {snippet}"
        if any(k in text for k in keywords):
            filtered.append(item)
    return filtered or web_docs[:12]


def _format_web_context(web_docs, max_items: int = 5) -> str:
    if not web_docs:
        return "No web retrieval results available."
    lines = []
    for idx, item in enumerate(web_docs[:max_items], start=1):
        title = (item.get("title") or "Untitled").strip()
        link = (item.get("link") or "NO_LINK").strip()
        snippet = (item.get("snippet") or "NO_SNIPPET").strip()
        lines.append(f"{idx}. {title}\nURL: {link}\nSnippet: {snippet}")
    return "\n\n".join(lines)


def _source_links(web_docs, max_links: int = 8):
    links = []
    for item in web_docs:
        link = (item.get("link") or "").strip()
        if link and link not in links:
            links.append(link)
        if len(links) >= max_links:
            break
    return links


def _extract_indicators(local_context: str, web_docs) -> dict:
    lower = local_context.lower()
    indicators = {
        "mentions_default_credentials": ("default" in lower and "password" in lower) or ("credential" in lower),
        "mentions_segmentation": "segment" in lower or "dmz" in lower,
        "mentions_firewall": "firewall" in lower,
        "mentions_modbus": "modbus" in lower,
        "mentions_plaintext": "plaintext" in lower or "unencrypted" in lower,
    }

    for item in web_docs:
        snippet = ((item.get("snippet") or "") + " " + (item.get("title") or "")).lower()
        indicators["mentions_modbus"] = indicators["mentions_modbus"] or ("modbus" in snippet)
        indicators["mentions_plaintext"] = indicators["mentions_plaintext"] or ("plaintext" in snippet or "unencrypted" in snippet)
    return indicators


def _resolve_doc_files(doc_roots):
    doc_files = []
    for root in doc_roots:
        resolved = Path(root).expanduser().resolve()
        if not resolved.exists():
            logger.warning("Skipping missing docs path: %s", resolved)
            continue
        if resolved.is_file() and resolved.suffix.lower() in SUPPORTED_DOC_SUFFIXES:
            doc_files.append(resolved)
            continue
        if resolved.is_dir():
            doc_files.extend(
                path for path in sorted(resolved.rglob("*.*")) if path.suffix.lower() in SUPPORTED_DOC_SUFFIXES
            )
    deduped = []
    seen = set()
    for path in doc_files:
        if path not in seen:
            deduped.append(path)
            seen.add(path)
    return deduped


def _setup_tools(serp_key: str, doc_roots):
    rag_cfg = getattr(settings, "rag_system", None)

    index_dir = Path(
        getattr(getattr(rag_cfg, "paths", None), "vector_store_dir", "out/vector_store")
    ).resolve()
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
    retriever = CrossEncoderRerankingRetriever(base=base_retriever, cross_encoder=cross_encoder, rerank_k=25)

    doc_files = _resolve_doc_files(doc_roots)
    if not doc_files:
        raise RuntimeError(f"No supported document files found in: {', '.join(str(Path(p).resolve()) for p in doc_roots)}")

    processor = DocumentProcessor()
    all_documents = []
    for file_path in doc_files:
        try:
            docs = processor.process_file(str(file_path))
            all_documents.extend(docs)
        except Exception as exc:
            logger.warning("Skipping document %s due to processing error: %s", file_path, exc)

    if all_documents:
        long_term_memory.vector_store.add_documents(all_documents)

    llm = None
    if HuggingFaceAdapter is None:
        logger.warning("HuggingFaceAdapter is unavailable; interactive answers will fall back to retrieval only.")
    else:
        try:
            llm = HuggingFaceAdapter("dolphin3-qwen25-3b", auth_token="")
        except Exception as exc:
            logger.warning("Could not initialize chat model; interactive answers will fall back to retrieval only: %s", exc)

    return KnowledgeBaseQueryTool(retriever), WebSearchTool(api_key=serp_key), llm, index_dir


def _gather_context(question: str, knowledge_tool: KnowledgeBaseQueryTool, web_tool: WebSearchTool):
    web_queries = [
        question,
        "CLICK PLC default services ports protocol hardening",
        "CLICK PLC password policy default credentials",
        "CLICK PLC segmentation firewall OT guidance",
    ]
    all_web_docs = []
    for query in web_queries:
        payload = web_tool.use(query)
        docs = _extract_tool_result(payload)
        logger.info("Web query returned %d results: %s", len(docs), query)
        all_web_docs.extend(docs)
    web_docs = _filter_relevant_web_docs(_dedupe_web_docs(all_web_docs))

    local_payload = knowledge_tool.use(question)
    local_docs = _extract_tool_result(local_payload)
    local_context = _format_local_context(local_docs)
    return local_context, web_docs


async def _answer_with_knowledge_base(
    question: str,
    knowledge_tool: KnowledgeBaseQueryTool,
    web_tool: WebSearchTool | None,
    llm,
    history,
    use_web: bool = False,
):
    local_payload = knowledge_tool.use(question)
    local_docs = _extract_tool_result(local_payload)
    local_context = _format_local_context(local_docs)
    web_docs = []
    web_context = "Web context disabled for interactive mode."
    if use_web and web_tool is not None:
        web_payload = web_tool.use(question)
        web_docs = _filter_relevant_web_docs(_dedupe_web_docs(_extract_tool_result(web_payload)))
        web_context = _format_web_context(web_docs)

    if llm is None:
        return (
            "Model-based chat is unavailable, so here are the most relevant knowledge-base excerpts:\n\n"
            f"{local_context}\n\n"
            f"{web_context if use_web else ''}"
        )

    history_text = ""
    if history:
        history_lines = []
        for turn in history[-4:]:
            history_lines.append(f"User: {turn['question']}")
            history_lines.append(f"Assistant: {turn['answer']}")
        history_text = "\n".join(history_lines)

    prompt = (
        f"Conversation so far:\n{history_text or 'No previous conversation.'}\n\n"
        f"Current user question:\n{question}\n\n"
        "Knowledge-base context:\n"
        f"{local_context}\n\n"
        "Web context:\n"
        f"{web_context}\n\n"
        "Answer the user using only the context above. "
        "If the answer is partial, say what is known and what is missing. "
        "End with a short 'Sources:' list using the source names from the context."
    )

    response = await llm.ainvoke(
        [
            ChatMessage(role="system", content=CHAT_SYSTEM_PROMPT),
            ChatMessage(role="user", content=prompt),
        ]
    )
    return response.content if hasattr(response, "content") else str(response)


async def _interactive_chat_loop(
    knowledge_tool: KnowledgeBaseQueryTool,
    web_tool: WebSearchTool | None,
    llm,
    use_web: bool = False,
):
    print("\nInteractive knowledge-base mode")
    print("Ask follow-up questions about the indexed docs.")
    if use_web:
        print("Fresh web search is enabled for each follow-up question.")
    print("Type 'exit', 'quit', or press Ctrl-D to stop.\n")

    history = []
    while True:
        try:
            question = input("You> ").strip()
        except EOFError:
            print()
            break

        if not question:
            continue
        if question.lower() in {"exit", "quit"}:
            break

        try:
            answer = await _answer_with_knowledge_base(question, knowledge_tool, web_tool, llm, history, use_web=use_web)
            print(f"\nAgent>\n{answer}\n")
            history.append({"question": question, "answer": answer})
        except Exception as exc:
            logger.error("Interactive chat failed for question '%s': %s", question, exc, exc_info=True)
            print("\nAgent>\nUnable to answer that question from the current knowledge base.\n")


def _write_outputs(question: str, local_context: str, web_docs, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    indicators = _extract_indicators(local_context, web_docs)
    links = _source_links(web_docs)

    scan_script = f"""#!/usr/bin/env bash
set -euo pipefail

# Defensive OT network exposure audit script (authorized environments only)
# Usage: OT_SUBNET=10.10.0.0/24 bash network_exposure_audit.sh

: "${{OT_SUBNET:?Set OT_SUBNET (example: 10.10.0.0/24)}}"

OUT_DIR="audit_output"
mkdir -p "$OUT_DIR"

# Non-intrusive host discovery
nmap -sn "$OT_SUBNET" -oN "$OUT_DIR/01_host_discovery.txt"

# Conservative TCP service inventory for common ICS/management ports
nmap -sT -Pn -n --open -p 21,22,23,80,443,502,44818,102,789,2455 "$OT_SUBNET" -oN "$OUT_DIR/02_service_inventory.txt"

# Banner/version hints without exploit scripts
nmap -sV -Pn -n --version-light -p 502,44818,102 "$OT_SUBNET" -oN "$OUT_DIR/03_ics_protocol_hints.txt"

cat <<'EOF' > "$OUT_DIR/04_manual_review_checklist.txt"
Manual Review Checklist
- Confirm PLC programming ports are reachable only from approved engineering stations.
- Confirm no internet-routable exposure for PLC management interfaces.
- Confirm firewall ACLs enforce least privilege between IT and OT zones.
- Confirm all default credentials are removed and unique account policies are in place.
EOF

printf "Audit complete. Outputs in %s\\n" "$OUT_DIR"
"""

    config_script = """#!/usr/bin/env python3
\"\"\"Offline PLC config/policy audit helper.

Input: JSON files exported from PLC/HMI/SCADA config management tools.
This script performs defensive checks only.
\"\"\"

from pathlib import Path
import json

CONFIG_DIR = Path("config_exports")

REQUIRED = [
    "password_policy.min_length",
    "password_policy.complexity_enabled",
    "network.segmentation.enabled",
    "network.allowed_management_subnets",
    "services.modbus_tcp.enabled",
    "services.web_admin.enabled",
]


def get_nested(data, dotted):
    node = data
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def evaluate(doc):
    findings = []
    for key in REQUIRED:
        value = get_nested(doc, key)
        if value is None:
            findings.append(("MISSING", key, "Not present"))

    min_len = get_nested(doc, "password_policy.min_length")
    if isinstance(min_len, int) and min_len < 12:
        findings.append(("FAIL", "password_policy.min_length", f"{min_len} < 12"))

    default_accounts = get_nested(doc, "accounts.default_accounts") or []
    if default_accounts:
        findings.append(("FAIL", "accounts.default_accounts", f"Found default accounts: {default_accounts}"))

    modbus_enabled = get_nested(doc, "services.modbus_tcp.enabled")
    modbus_tls = get_nested(doc, "services.modbus_tcp.secure_transport")
    if modbus_enabled and not modbus_tls:
        findings.append(("WARN", "services.modbus_tcp.secure_transport", "Modbus enabled without secure transport/tunnel"))

    return findings


def main():
    if not CONFIG_DIR.exists():
        raise SystemExit("Create config_exports/ with JSON exports first.")

    for path in sorted(CONFIG_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = evaluate(data)
        print(f"\\n=== {{path.name}} ===")
        if not findings:
            print("PASS: No policy issues detected by baseline checks.")
            continue
        for sev, key, msg in findings:
            print(f"{{sev}} | {{key}} | {{msg}}")


if __name__ == "__main__":
    main()
"""

    checklist = f"""# PLC Security Audit Plan (Generated)

## Scope Question
{question}

## Evidence Highlights (Local)
{local_context[:2500]}

## Signals Detected
- Mentions default credentials: {indicators['mentions_default_credentials']}
- Mentions segmentation controls: {indicators['mentions_segmentation']}
- Mentions firewall controls: {indicators['mentions_firewall']}
- Mentions Modbus: {indicators['mentions_modbus']}
- Mentions plaintext traffic risk: {indicators['mentions_plaintext']}

## Generated Artifacts
- `network_exposure_audit.sh` (safe network inventory)
- `offline_config_policy_audit.py` (config export checks)

## Recommended Validation Sequence
1. Run network inventory in lab/authorized subnet only.
2. Confirm exposed services and map to approved asset list.
3. Run offline policy audit on exported controller/HMI configs.
4. Prioritize remediation for default credentials and segmentation gaps.
5. Re-run both scripts after remediation.

## Source Links (Web)
"""
    if links:
        checklist += "\n".join(f"- {link}" for link in links)
    else:
        checklist += "- None captured"

    (out_dir / "network_exposure_audit.sh").write_text(scan_script, encoding="utf-8")
    (out_dir / "offline_config_policy_audit.py").write_text(config_script, encoding="utf-8")
    (out_dir / "audit_plan.md").write_text(checklist + "\n", encoding="utf-8")

    os.chmod(out_dir / "network_exposure_audit.sh", 0o755)
    os.chmod(out_dir / "offline_config_policy_audit.py", 0o755)


async def main():
    parser = argparse.ArgumentParser(description="Generate defensive PLC security audit scripts.")
    parser.add_argument(
        "--question",
        default="List network exposure, default configuration, and password policy risks for CLICK PLC deployments.",
        help="Assessment question used to gather context.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_DIR),
        help="Directory where generated scripts/checklists will be written.",
    )
    parser.add_argument(
        "--docs-path",
        action="append",
        default=[],
        help="Additional document file or directory to index. Repeat this flag to include multiple sources.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Keep the agent running after generation so you can ask follow-up questions against the knowledge base.",
    )
    parser.add_argument(
        "--interactive-web",
        action="store_true",
        help="During interactive mode, include fresh web search context for each follow-up question.",
    )
    args = parser.parse_args()

    doc_roots = [DOCS_ROOT, *args.docs_path]
    serp_key = _load_env()
    knowledge_tool, web_tool, llm, index_dir = _setup_tools(serp_key, doc_roots)

    try:
        local_context, web_docs = _gather_context(args.question, knowledge_tool, web_tool)
        _write_outputs(args.question, local_context, web_docs, Path(args.output_dir))
        logger.info("Generated defensive artifacts in: %s", Path(args.output_dir).resolve())
        if args.interactive:
            await _interactive_chat_loop(knowledge_tool, web_tool, llm, use_web=args.interactive_web)
    finally:
        try:
            if index_dir.exists() and index_dir.is_dir():
                shutil.rmtree(index_dir)
                logger.info("Cleaned up FAISS store directory: %s", index_dir)
        except Exception as exc:
            logger.warning("Could not remove FAISS store directory %s: %s", index_dir, exc)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
