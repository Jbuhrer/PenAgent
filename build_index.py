import glob, csv, pickle, os
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

MODEL_NAME = 'all-MiniLM-L6-v2'
INDEX_PATH = 'knowledge/index.faiss'
CHUNKS_PATH = 'knowledge/chunks.pkl'

def chunk_text(text, size=300):
    words = text.split()
    return [' '.join(words[i:i+size]) for i in range(0, len(words), size)]

def build():
    os.makedirs('knowledge', exist_ok=True)
    chunks, sources = [], []

    print("[*] Loading PayloadsAllTheThings...")
    for f in glob.glob('data/PATT/**/*.md', recursive=True):
        try:
            text = open(f, errors='ignore').read()
            for c in chunk_text(text):
                chunks.append(c)
                sources.append(f)
        except:
            pass

    print("[*] Loading ExploitDB...")
    with open('data/exploitdb.csv', errors='ignore') as f:
        for row in csv.DictReader(f):
            text = f"{row.get('description','')} {row.get('platform','')}"
            chunks.append(text)
            sources.append('exploitdb')

    print(f"[*] Total chunks: {len(chunks)}")
    print("[*] Embedding... (this takes a few minutes)")

    model = SentenceTransformer(MODEL_NAME)
    embeddings = model.encode(chunks, show_progress_bar=True,
                              batch_size=64).astype('float32')

    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)
    faiss.write_index(index, INDEX_PATH)

    with open(CHUNKS_PATH, 'wb') as f:
        pickle.dump({'chunks': chunks, 'sources': sources}, f)

    print(f"[+] Done. Index has {index.ntotal} vectors saved to {INDEX_PATH}")

if __name__ == '__main__':
    build()
