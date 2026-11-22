"""Advisory retrieval — Chroma RAG with keyword fallback.

Index build: run scripts/build_index.py once after fetch_advisories.py.
Search at triage time: search_advisories loads the existing index (never rebuilds).
If the index is missing, falls back to keyword matching over raw advisory JSON files.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

ROOT           = Path(__file__).resolve().parent.parent.parent
ADVISORIES_DIR = ROOT / "data" / "advisories"
CHROMA_DIR     = ROOT / "data" / "chroma"

_log = logging.getLogger(__name__)

# ── Reference labelling ───────────────────────────────────────────────────────
# Vendor domains are per-product, not global.  Call label_ref with the
# vendor_domains set derived from the CVE's CPE data via vendor_domains_for_cpe.

_DISTRO_DOMAINS: frozenset[str] = frozenset({
    "access.redhat.com",
    "bugzilla.redhat.com",
    "redhat.com",
    "ubuntu.com",
    "usn.ubuntu.com",
    "debian.org",
    "lists.debian.org",
    "suse.com",
    "opensuse.org",
    "security.netapp.com",
    "netapp.com",
    "cert-portal.siemens.com",
    "lists.fedoraproject.org",
    "fedoraproject.org",
    "oracle.com",
})

_EXPLOIT_DOMAINS: frozenset[str] = frozenset({
    "packetstormsecurity.com",
    "exploit-db.com",
})

# Maps CPE product/vendor tokens to the vendor's official advisory domains.
# The key is a substring that appears in the CPE vendor or product field (lowercase).
_PRODUCT_VENDOR_MAP: dict[str, frozenset[str]] = {
    "jenkins":    frozenset({"jenkins.io"}),
    "log4j":      frozenset({"logging.apache.org", "apache.org"}),
    "apache":     frozenset({"logging.apache.org", "apache.org"}),
    "nginx":      frozenset({"nginx.org", "mailman.nginx.org", "f5.com", "my.f5.com"}),
    "f5":         frozenset({"f5.com", "my.f5.com", "nginx.org"}),
    "openssh":    frozenset({"openssh.com"}),
    "postgresql": frozenset({"postgresql.org"}),
    "citrix":     frozenset({"citrix.com", "support.citrix.com"}),
}


def vendor_domains_for_cpe(cpe_products: frozenset[str]) -> frozenset[str]:
    """
    Return the set of vendor advisory domains for the given CPE product/vendor tokens.

    cpe_products — lowercase product and vendor strings from the CPE, e.g.
                   frozenset({"jenkins"}) or frozenset({"apache", "log4j"}).
    """
    domains: set[str] = set()
    for token in cpe_products:
        t = token.lower()
        for key, dset in _PRODUCT_VENDOR_MAP.items():
            if key in t or t in key:
                domains.update(dset)
    return frozenset(domains)


def label_ref(url: str, vendor_domains: frozenset[str] = frozenset()) -> str:
    """
    Classify a reference URL: vendor / distro / exploit / other.

    vendor_domains — domains to treat as 'vendor' for this specific CVE.
                     Derive with vendor_domains_for_cpe; defaults to empty (no vendor match).
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
    except Exception:
        return "other"

    if host in _EXPLOIT_DOMAINS:
        return "exploit"

    if host == "github.com":
        path = parsed.path.lower()
        for segment in path.strip("/").split("/"):
            parts = re.split(r"[-_.]", segment)
            if "poc" in parts or "exploit" in parts:
                return "exploit"
        return "other"

    if vendor_domains:
        if host in vendor_domains:
            return "vendor"
        if any(host.endswith("." + d) for d in vendor_domains):
            return "vendor"

    if host in _DISTRO_DOMAINS:
        return "distro"
    if any(host.endswith("." + d) for d in _DISTRO_DOMAINS):
        return "distro"

    return "other"


# ── Chunking ──────────────────────────────────────────────────────────────────

def _chunk_text(text: str, max_chars: int = 800, overlap: int = 100) -> list[str]:
    """
    Slide a window across the full text, producing chunks of max_chars characters
    with overlap characters shared between consecutive chunks.

    For a 10 000-char text: step=700, chunks start at 0, 700, 1400, … → ~15 chunks.
    """
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]
    step = max_chars - overlap
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start += step
    return chunks


# ── Index building ─────────────────────────────────────────────────────────────

def build_advisory_index(
    advisories_dir: Path = ADVISORIES_DIR,
    chroma_dir: Path = CHROMA_DIR,
) -> dict:
    """
    Build (or rebuild) the Chroma vector index from data/advisories/.
    Run once after fetch_advisories.py; not called during normal triage.
    Only quality_ok=True files are indexed.
    """
    import chromadb

    chroma_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(chroma_dir))

    try:
        client.delete_collection("advisories")
    except Exception:
        pass
    collection = client.create_collection("advisories")

    ids_all: list[str]    = []
    docs_all: list[str]   = []
    metas_all: list[dict] = []
    files_indexed = 0

    for cve_dir in sorted(advisories_dir.iterdir()):
        if not cve_dir.is_dir():
            continue
        cve_id = cve_dir.name
        for advisory_file in sorted(cve_dir.glob("*.json")):
            advisory = json.loads(advisory_file.read_text())
            if advisory.get("quality_ok") is not True:
                continue
            text = advisory.get("text", "")
            if not text:
                continue
            n = int(advisory_file.stem)
            file_chunks = _chunk_text(text)
            print(f"  {cve_id}/{n}: {len(text):,} chars → {len(file_chunks)} chunks")
            files_indexed += 1
            for idx, chunk in enumerate(file_chunks):
                chunk_id = f"{cve_id}_{n}_{idx}"
                ids_all.append(chunk_id)
                docs_all.append(chunk)
                metas_all.append({
                    "cve":      cve_id,
                    "url":      advisory.get("url", ""),
                    "domain":   advisory.get("domain", ""),
                    "label":    advisory.get("label", "other"),
                    "chunk_id": chunk_id,
                })

    print(f"Total: {len(ids_all)} chunks from {files_indexed} files")

    BATCH = 100
    for i in range(0, len(ids_all), BATCH):
        collection.add(
            ids=ids_all[i : i + BATCH],
            documents=docs_all[i : i + BATCH],
            metadatas=metas_all[i : i + BATCH],
        )

    return {"added": len(ids_all), "collection": "advisories", "files": files_indexed}


# ── Testing hooks ─────────────────────────────────────────────────────────────

_test_collection = None   # injected fake collection (or None = use default path)
_test_force_missing = False  # True forces keyword fallback, skipping Chroma entirely


def _set_index_for_testing(collection=None, force_missing: bool = False) -> None:
    """Inject a fake Chroma collection or force keyword fallback for tests."""
    global _test_collection, _test_force_missing
    _test_collection = collection
    _test_force_missing = force_missing


# ── Keyword fallback ──────────────────────────────────────────────────────────

def _keyword_fallback(
    cve_id: str,
    query: str,
    k: int,
    advisories_dir: Path,
) -> dict:
    cve_dir = advisories_dir / cve_id
    if not cve_dir.exists():
        return {"cve_id": cve_id, "query": query, "chunks": [], "source": "keyword_fallback"}

    query_words = set(re.findall(r"\w+", query.lower()))
    scored: list[tuple[float, dict]] = []

    for advisory_file in sorted(cve_dir.glob("*.json")):
        advisory = json.loads(advisory_file.read_text())
        if advisory.get("quality_ok") is not True:
            continue
        text = advisory.get("text", "")
        if not text:
            continue
        words = set(re.findall(r"\w+", text.lower()))
        score = len(query_words & words) / max(len(query_words), 1)
        n = int(advisory_file.stem)
        scored.append((score, {
            "chunk_id": f"{cve_id}_{n}_0",
            "url":      advisory.get("url", ""),
            "domain":   advisory.get("domain", ""),
            "label":    advisory.get("label", "other"),
            "text":     text[:800],
        }))

    scored.sort(key=lambda x: -x[0])
    return {
        "cve_id":  cve_id,
        "query":   query,
        "chunks":  [c for _, c in scored[:k]],
        "source":  "keyword_fallback",
    }


# ── Search ────────────────────────────────────────────────────────────────────

def search_advisories(
    cve_id: str,
    query: str,
    k: int = 5,
    advisories_dir: Path = ADVISORIES_DIR,
    chroma_dir: Path = CHROMA_DIR,
) -> dict:
    """
    Search the advisory index for chunks relevant to a query, filtered to cve_id.
    Falls back to keyword matching if the Chroma index is unavailable.
    """
    if _test_force_missing:
        return _keyword_fallback(cve_id, query, k, advisories_dir)

    collection = _test_collection
    if collection is None:
        try:
            import chromadb
            client = chromadb.PersistentClient(path=str(chroma_dir))
            collection = client.get_collection("advisories")
        except Exception as exc:
            _log.warning("Advisory index not available (%s); using keyword fallback.", exc)
            return _keyword_fallback(cve_id, query, k, advisories_dir)

    try:
        results = collection.query(
            query_texts=[query],
            n_results=k,
            where={"cve": {"$eq": cve_id}},
        )
    except Exception as exc:
        _log.warning("Chroma query failed (%s); using keyword fallback.", exc)
        return _keyword_fallback(cve_id, query, k, advisories_dir)

    chunks: list[dict] = []
    if results.get("ids") and results["ids"][0]:
        for i, chunk_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i]
            text = results["documents"][0][i]
            chunks.append({
                "chunk_id": chunk_id,
                "url":      meta.get("url", ""),
                "domain":   meta.get("domain", ""),
                "label":    meta.get("label", "other"),
                "text":     text,
            })

    return {"cve_id": cve_id, "query": query, "chunks": chunks, "source": "chroma"}
