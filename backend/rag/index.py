"""Local vector index of ATT&CK techniques: python -m backend.rag.index builds it.

Everything runs on this machine. The model is the file fetched and hash-checked by
backend.rag.fetch, and it's locked to the CPU provider, because onnxruntime also offers
AzureExecutionProvider, which runs remotely.
"""

import sys
from dataclasses import dataclass
from functools import lru_cache

import chromadb
from chromadb.config import Settings
from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

from backend.rag.attack_data import (
    ATTACK_VERSION,
    DATA_DIR,
    MODEL_DIR,
    MODEL_NAME,
    STIX_SHA256,
    AttackData,
    load_attack_data,
)
from backend.rag.validator import check_technique_id

CHROMA_DIR = DATA_DIR / "chroma"
COLLECTION = "attack_techniques"
BATCH_SIZE = 128
DEFAULT_RESULTS = 5
MAX_QUERY_CHARS = 512
MODEL_FILES = (
    "config.json",
    "model.onnx",
    "special_tokens_map.json",
    "tokenizer_config.json",
    "tokenizer.json",
    "vocab.txt",
)
CPU_ONLY = ["CPUExecutionProvider"]

# Searches for an alert come from these fixed words and never from telemetry, so a
# file name can't choose what the model gets to read.
ZONE_QUERIES = {
    "documents": "ransomware encrypts or destroys user files",
    "persistence": "persistence through registry run keys or startup folders",
    "lsass": "process reads LSASS memory to dump credentials",
    "network": "command and control or tool download over the network",
}
EVENT_QUERIES = {
    "file_scan": "malicious file on disk that is packed or obfuscated",
    "process_start": "suspicious process execution",
    "process_access": "process opens another process to read its memory",
}


class LocalMiniLM(ONNXMiniLM_L6_V2):
    DOWNLOAD_PATH = MODEL_DIR


@dataclass(frozen=True)
class SearchResult:
    id: str
    name: str
    distance: float
    document: str


def embedding_model() -> LocalMiniLM:
    """Stops here if the model is missing, because the parent class would quietly download it."""
    folder = MODEL_DIR / LocalMiniLM.EXTRACTED_FOLDER_NAME
    missing = [name for name in MODEL_FILES if not (folder / name).is_file()]
    if missing:
        raise FileNotFoundError(f"model files {missing} are missing. Run: uv run python -m backend.rag.fetch")
    return LocalMiniLM(preferred_providers=CPU_ONLY)


def client() -> chromadb.api.ClientAPI:
    return chromadb.PersistentClient(path=str(CHROMA_DIR), settings=Settings(anonymized_telemetry=False))


def index_metadata() -> dict[str, str]:
    return {"attack_version": ATTACK_VERSION, "stix_sha256": STIX_SHA256, "model": MODEL_NAME}


def build_index(data: AttackData) -> int:
    """Rebuilds from nothing. Embeds the short text, and stores the full document."""
    model = embedding_model()
    store = client()
    if COLLECTION in [collection.name for collection in store.list_collections()]:
        store.delete_collection(COLLECTION)
    collection = store.create_collection(
        COLLECTION,
        configuration={"hnsw": {"space": "cosine"}},
        metadata=index_metadata(),
        embedding_function=None,
    )
    techniques = sorted(data.techniques.values(), key=lambda technique: technique.id)
    for start in range(0, len(techniques), BATCH_SIZE):
        batch = techniques[start : start + BATCH_SIZE]
        collection.add(
            ids=[technique.id for technique in batch],
            embeddings=model([technique.embedding_text for technique in batch]),
            documents=[technique.document for technique in batch],
            metadatas=[
                {
                    "name": technique.name,
                    "tactics": ", ".join(technique.tactics),
                    "platforms": ", ".join(technique.platforms),
                    "windows": technique.windows,
                    "subtechnique": technique.is_subtechnique,
                }
                for technique in batch
            ],
        )
    return collection.count()


@lru_cache(maxsize=1)
def open_index() -> tuple:
    """A stale index would ground reports on data other than the pinned file, so it's refused."""
    collection = client().get_collection(COLLECTION, embedding_function=None)
    metadata = collection.metadata or {}
    expected = index_metadata()
    if {key: metadata.get(key) for key in expected} != expected:
        raise ValueError(f"index was built from {metadata}. Run: uv run python -m backend.rag.index")
    return collection, embedding_model()


def search(query: str, k: int = DEFAULT_RESULTS, windows_only: bool = True) -> list[SearchResult]:
    """Windows techniques by default, because ThreatPulse runs only on Windows."""
    query = query.strip()[:MAX_QUERY_CHARS]
    if not query:
        raise ValueError("empty query")
    collection, model = open_index()
    results = collection.query(
        query_embeddings=model([query]),
        n_results=k,
        where={"windows": True} if windows_only else None,
    )
    return [
        SearchResult(identifier, metadata["name"], distance, document)
        for identifier, metadata, distance, document in zip(
            results["ids"][0],
            results["metadatas"][0],
            results["distances"][0],
            results["documents"][0],
        )
    ]


def alert_query(alert: dict) -> str | None:
    """Only fixed text chosen by the alert's own enum fields."""
    return ZONE_QUERIES.get(alert["object"]["zone"]) or EVENT_QUERIES.get(alert["event_type"])


def reference_for_alert(
    alert: dict, data: AttackData | None = None, search_extra: int = 3, searcher=search
) -> list[dict]:
    """The alert's own techniques first, using the replacement for a revoked ID, then the
    closest matches for its zone. Returns what the prompt's reference block needs."""
    data = data or load_attack_data()
    chosen: dict[str, str] = {}
    for technique_id in alert["technique_ids"]:
        check = check_technique_id(technique_id, data)
        final = check.id if check.valid else check.replacement
        if final in data.techniques:
            chosen[final] = data.techniques[final].document
    query = alert_query(alert)
    if query and search_extra > 0:
        for result in searcher(query, k=search_extra):
            chosen.setdefault(result.id, result.document)
    return [
        {"id": technique_id, "name": data.techniques[technique_id].name, "text": document}
        for technique_id, document in chosen.items()
        if technique_id in data.techniques
    ]


def main() -> int:
    data = load_attack_data()
    count = build_index(data)
    print(f"Indexed {count} of {len(data.techniques)} techniques from ATT&CK {ATTACK_VERSION}")
    return 0 if count == len(data.techniques) else 1


if __name__ == "__main__":
    sys.exit(main())
