# demo_faiss_rag_from_readme.py
"""
================================================================================
        FAISS RAG Demonstration (Async, Always Re-Rank, Full ReACT Loop)
================================================================================
 
This mirrors demo_rag_from_documents.py, but:
  • Uses DocumentProcessor (split_text_semantic) for chunking
  • Stores/retrieves with FaissVectorStore (persistent)
  • Always re-ranks via CrossEncoder
  • Runs the full ReACT agent loop
"""
 
import asyncio
import logging
from pathlib import Path
import shutil




 
from fairlib import (
    settings,
    HuggingFaceAdapter,
    ToolRegistry,
    ToolExecutor,
    WorkingMemory,
    LongTermMemory,
    ReActPlanner,
    SimpleAgent,
    SentenceTransformerEmbedder,
    SimpleRetriever,
    KnowledgeBaseQueryTool
)
 
from fairlib.utils.document_processor import DocumentProcessor
from fairlib.modules.memory.vector_faiss import FaissVectorStore
from fairlib.modules.memory.retriever_rerank import CrossEncoderRerankingRetriever
from sentence_transformers import CrossEncoder
 
docs_root = Path("docs")
 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("demo_faiss_rag_from_documents")

# Fallback ChatMessage shim for older fairlib versions
class ChatMessage:
    def __init__(self, role: str, content: str):
        self.role = role
        self.content = content

    def to_dict(self):
        return {"role": self.role, "content": self.content}

 
async def main():
    """Set up and run the FAISS + ReRank RAG agent demonstration."""
 
    logger.info("Initializing FAISS RAG components with DocumentProcessor + Cross-Encoder re-ranking...")
 
    rag_cfg = getattr(settings, "rag_system", None)
 
    # Paths
    index_dir = Path(getattr(getattr(rag_cfg, "paths", None), "vector_store_dir", "out/vector_store")).resolve()
    index_dir.mkdir(parents=True, exist_ok=True)
 
    # Models
    embed_model = getattr(getattr(rag_cfg, "embeddings", None), "embedding_model",
                          "sentence-transformers/all-MiniLM-L6-v2")
    cross_model = getattr(getattr(rag_cfg, "embeddings", None), "cross_encoder_model",
                          "cross-encoder/ms-marco-MiniLM-L-6-v2")
 
    # Retrieval params
    use_gpu = getattr(getattr(rag_cfg, "vector_store", None), "use_gpu", False)
    batch_size = getattr(getattr(rag_cfg, "embeddings", None), "batch_size", 128)
    pool_multiplier = getattr(getattr(rag_cfg, "retrieval", None), "pool_multiplier", 5)
    max_initial_docs = getattr(getattr(rag_cfg, "retrieval", None), "max_initial_retrieval_docs", 50)
    top_k = 5
    rerank_k = min(top_k * pool_multiplier, max_initial_docs)
 
    try:
        llm = HuggingFaceAdapter("dolphin3-qwen25-3b", auth_token = "")
        embedder = SentenceTransformerEmbedder(model_name=embed_model)
    except Exception as e:
        logger.critical(f"Failed to initialize LLM or embedder: {e}", exc_info=True)
        return
 
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
    retriever = CrossEncoderRerankingRetriever(
        base=base_retriever,
        cross_encoder=cross_encoder,
        rerank_k=rerank_k
    )
 
    doc_files = sorted(docs_root.rglob("*.*"))
    doc_files = [p for p in doc_files
                 if p.suffix.lower() in {".md", ".txt", ".pdf", ".docx"}]
 
 
    if not doc_files:        
        logger.error(f"No document files found in {docs_root}. Please add some and re-run this demo.")
        return
 
    document_processor= DocumentProcessor()
 
    all_documents = []
 
    for file_path in doc_files:
        try:
            logger.info(f"Processing document: {file_path}")
            documents = document_processor.process_file(str(file_path))
            all_documents.extend(documents)
            logger.info(f"Processed {len(documents)} chunks from {file_path}.")
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}", exc_info=True)
 
    if all_documents:
        logger.info(f"Ingesting a total of {len(all_documents)} document chunks into FAISS...")
        long_term_memory.vector_store.add_documents(all_documents)
        logger.info("Documents successfully ingested into FAISS-backed Long-Term Memory.")
    else:
        logger.warning("No documents were processed for ingestion.")
 
 
        # Build the ReACT Agent
    knowledge_tool = KnowledgeBaseQueryTool(retriever)
    tool_registry = ToolRegistry()
    tool_registry.register_tool(knowledge_tool)

    planner = ReActPlanner(llm, tool_registry)
    executor = ToolExecutor(tool_registry)
    working_memory = WorkingMemory()

    # 🔐 System prompt for the RAG agent
    rag_system_prompt = (
        "You are a security-analysis assistant that reads system documentation "
        "and identifies potential vulnerabilities. Your ONLY knowledge source is "
        "the retrieved documentation passages; do NOT rely on outside knowledge.\n\n"
        "When the user asks a question, you MUST:\n"
        "1) Use the 'knowledge_base_query' tool to retrieve relevant passages.\n"
        "2) Base your answer ONLY on those passages. If something is not clearly "
        "stated in the passages, you must say 'not mentioned in the documentation'.\n\n"
        "OUTPUT FORMAT (max 5 bullets):\n"
        "- Vulnerability: <short name>\n"
        "  Why risky: <explanation, explicitly tied to the quoted text>\n"
        "  Mitigation: <high-level, non-actionable mitigation>\n"
        "  Reference: \"<short excerpt copied from the retrieved passage>\"\n\n"
        "If you cannot find any vulnerabilities, reply exactly:\n"
        "'No vulnerabilities found in the provided documentation.'"
    )

    # 🧠 Create the SimpleAgent (note: first 4 args are positional)
    rag_agent = SimpleAgent(
        llm,
        planner,
        executor,
        working_memory,
        role_description=rag_system_prompt,
    )

    logger.info("RAG Agent created with re-ranked retriever.")


    questions = [
        "List all network security weaknesses, default configurations, and password risks in CLICK PLC systems."

    ]
 

    for q in questions:
        print(f"\n👤 You: {q}")
        try:
            # 1) Run the ReAct RAG agent (this will do tools + retrieval)
            resp = await rag_agent.arun(q)

            # 2) Ask the LLM to turn the agent output into clean bullet points
            summary_prompt = (
                "You are a cybersecurity analyst. Based ONLY on the text below, "
                "summarize the network security weaknesses, default configuration "
                "risks, and password risks in CLICK PLC systems.\n\n"
                "Return 3–5 bullet points. For each bullet, include:\n"
                "- Vulnerability: <short name>\n"
                "- Why risky: <1–2 sentences>\n"
                "- Mitigation: <high-level defensive idea, no exploit steps>\n"
                "- Steps to exploit these vulnerabilities: <1–2 sentences>\n\n"
                "If something is not clearly mentioned in the text, do NOT invent it.\n\n"
                f"--- BEGIN TEXT ---\n{resp}\n--- END TEXT ---"
            )

            summary = await llm.ainvoke([
                ChatMessage(role="system", content="You are a precise, concise cybersecurity analyst."),
                ChatMessage(role="user", content=summary_prompt),
            ])

            # 3) Print just the cleaned-up summary
            if hasattr(summary, "content"):
                final_text = summary.content
            else:
                final_text = str(summary)

            print("\n===== RAG Vulnerability Summary =====")
            print(final_text)

            # (Optional) If you still want to see the raw agent trace, uncomment:
            # print("\n----- Raw agent output (debug) -----")
            # print(resp)

        except Exception as e:
            logger.error(f"Agent error for question '{q}': {e}", exc_info=True)
            print("🤖 Agent: I encountered an error and couldn't process your request.")

 
    # remove created faiss directory
    try:
        if index_dir.exists() and index_dir.is_dir():
            shutil.rmtree(index_dir)
            logger.info(f"Cleaned up FAISS store directory: {index_dir}")
    except Exception as e:
        logger.warning(f"Could not remove FAISS store directory {index_dir}: {e}")
 
if __name__ == "__main__":
    
    asyncio.run(main())