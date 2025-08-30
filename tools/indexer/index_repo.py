#!/usr/bin/env python3
import os, json, argparse, hashlib, pathlib
from tree_sitter_languages import get_parser
import numpy as np
try:
    import faiss  # type: ignore
except Exception:
    faiss = None

SUPPORTED = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'tsx',
    '.jsx': 'tsx', '.go': 'go', '.java': 'java', '.rb': 'ruby', '.rs': 'rust'
}

def chunk_source(src: str, max_lines: int = 80):
    lines = src.splitlines()
    for i in range(0, len(lines), max_lines):
        piece = "\n".join(lines[i:i+max_lines])
        if piece.strip():
            yield piece, (i, min(i+max_lines, len(lines)))

def embed(text: str) -> np.ndarray:
    # offline-friendly faux embedding (hash seeded gaussian) – replace with OpenAI if desired
    h = hashlib.sha256(text.encode('utf-8')).digest()
    seed = int.from_bytes(h[:8], 'little')
    rng = np.random.default_rng(seed)
    v = rng.standard_normal(768).astype('float32')
    v /= (np.linalg.norm(v) + 1e-9)
    return v

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', default='.', help='path to repo to index')
    ap.add_argument('--out', default='data/index', help='output dir')
    args = ap.parse_args()

    root = pathlib.Path(args.repo).resolve()
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    records, vectors = [], []

    for p in root.rglob('*'):
        if not p.is_file():
            continue
        if any(s in str(p) for s in ['.git/', 'node_modules/', 'dist/', 'build/', '.venv/']):
            continue
        ext = p.suffix.lower()
        if ext not in SUPPORTED:
            continue
        try:
            parser = get_parser(SUPPORTED[ext])
        except Exception:
            continue
        src = p.read_text(errors='ignore')
        parser.parse(bytes(src, 'utf-8'))  # parse to validate
        for chunk, (lo, hi) in chunk_source(src):
            rec = {'path': str(p.relative_to(root)), 'span_lines': [lo, hi], 'lang': SUPPORTED[ext], 'preview': chunk[:2000]}
            records.append(rec)
            vectors.append(embed(chunk))

    if not records:
        print("No indexable files found.")
        return

    vecs = np.vstack(vectors).astype('float32')
    index_path = out / 'faiss.index'
    meta_path = out / 'records.json'

    if faiss is not None:
        index = faiss.IndexFlatIP(vecs.shape[1])
        index.add(vecs)
        faiss.write_index(index, str(index_path))
    else:
        np.save(out / 'vectors.npy', vecs)

    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2)

    print(f"Indexed {len(records)} chunks into {out}")

if __name__ == '__main__':
    main()
