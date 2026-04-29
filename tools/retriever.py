import faiss, pickle
from sentence_transformers import SentenceTransformer

_model = None
_index = None
_chunks = None

def _load():
    global _model, _index, _chunks
    if _model is None:
        _model = SentenceTransformer('all-MiniLM-L6-v2')
        _index = faiss.read_index('knowledge/index.faiss')
        with open('knowledge/chunks.pkl', 'rb') as f:
            _chunks = pickle.load(f)['chunks']

def search_exploits(query: str) -> str:
    """Search the exploit knowledge base. Input: service name and version."""
    _load()
    emb = _model.encode([query]).astype('float32')
    _, idxs = _index.search(emb, 5)
    results = [_chunks[i][:400] for i in idxs[0] if i < len(_chunks)]
    return '\n\n---\n\n'.join(results)
