#!/usr/bin/env python3
"""Model loader — runs INSIDE the sandbox."""
import sys
import os
import time
import json

def load_pickle(path):
    import pickle
    with open(path, 'rb') as f:
        return pickle.load(f)

def load_pytorch(path):
    import torch
    return torch.load(path, map_location='cpu', weights_only=False)

def detect_and_load(path):
    ext = os.path.splitext(path)[1].lower()
    loaders = {
        '.pkl': load_pickle,
        '.pickle': load_pickle,
        '.pt': load_pytorch,
        '.pth': load_pytorch,
    }
    loader = loaders.get(ext, load_pickle)

    start = time.monotonic()
    model = loader(path)
    elapsed = time.monotonic() - start

    result = {
        "status": "success",
        "format": ext,
        "load_time_ms": round(elapsed * 1000, 2),
        "model_size_bytes": os.path.getsize(path),
    }
    print(json.dumps(result))
    return model

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: load_model.py <model_path>", file=sys.stderr)
        sys.exit(1)
    try:
        detect_and_load(sys.argv[1])
    except SystemExit:
        raise
    except Exception as e:
        print(json.dumps({"status": "error", "error": str(e)}),
              file=sys.stderr)
        sys.exit(1)
