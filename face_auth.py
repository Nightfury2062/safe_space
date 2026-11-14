"""
face_auth.py - Deep Learning Face Recognition pipeline and secure biometric storage for SafeSpace.

Pipeline:
1. Capture video frame via OpenCV
2. Detect & align face using RetinaFace (InsightFace buffalo_sc)
3. Extract 512-d ArcFace normalized embedding
4. Perform liveness checks (framing, single-face validation, score confidence)
5. Compare live embedding with enrolled reference embedding via Cosine Similarity (dot product)
6. Secure storage: Biometric wrap key (BK) and reference embedding are encrypted
   with Windows DPAPI (CryptProtectData) and tied to the user's OS account.
"""

import ctypes
from ctypes import wintypes
import json
import os
import sys
import numpy as np

# Lazy load InsightFace / cv2 so app startup is instant
_engine_instance = None


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def dpapi_encrypt(data: bytes, description: str = "SafeSpace Face ID") -> bytes:
    """Encrypts bytes using Windows DPAPI, binding ciphertext to current Windows user."""
    b_in = (ctypes.c_byte * len(data))(*data)
    blob_in = DATA_BLOB(len(data), b_in)
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), description, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise OSError("Windows DPAPI CryptProtectData failed.")
    res = bytes(ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_byte * blob_out.cbData)).contents)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return res


def dpapi_decrypt(data: bytes) -> bytes:
    """Decrypts bytes using Windows DPAPI."""
    b_in = (ctypes.c_byte * len(data))(*data)
    blob_in = DATA_BLOB(len(data), b_in)
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise OSError("Windows DPAPI CryptUnprotectData failed.")
    res = bytes(ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_byte * blob_out.cbData)).contents)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return res


class FaceAuthEngine:
    def __init__(self, threshold: float = 0.62):
        self.threshold = threshold
        from insightface.app import FaceAnalysis
        # buffalo_sc: highly optimized lightweight model suitable for real-time CPU execution
        self.app = FaceAnalysis(name="buffalo_sc", providers=["CPUExecutionProvider"])
        self.app.prepare(ctx_id=0, det_size=(320, 320))

    def process_frame(self, frame: np.ndarray) -> dict:
        """
        Analyzes a single video frame.
        Returns:
            {
                "ok": bool,
                "msg": str,
                "bbox": [x1, y1, x2, y2] | None,
                "embedding": np.ndarray | None,
                "score": float
            }
        """
        faces = self.app.get(frame)
        if len(faces) == 0:
            return {"ok": False, "msg": "No face detected. Center your face in the camera.", "bbox": None, "embedding": None, "score": 0.0}
        if len(faces) > 1:
            return {"ok": False, "msg": "Multiple faces detected. Ensure only you are in frame.", "bbox": None, "embedding": None, "score": 0.0}

        face = faces[0]
        bbox = [int(v) for v in face.bbox]
        score = float(face.det_score)

        if score < 0.65:
            return {"ok": False, "msg": "Face low confidence. Improve lighting.", "bbox": bbox, "embedding": None, "score": score}

        # Check face size in frame (must not be too far away)
        w = bbox[2] - bbox[0]
        h = bbox[3] - bbox[1]
        if w < 75 or h < 75:
            return {"ok": False, "msg": "Move a bit closer to the camera.", "bbox": bbox, "embedding": None, "score": score}

        emb = face.embedding
        norm_emb = emb / np.linalg.norm(emb)
        return {
            "ok": True,
            "msg": "Face detected",
            "bbox": bbox,
            "embedding": norm_emb,
            "score": score,
        }

    def verify(self, live_emb: np.ndarray, ref_emb: np.ndarray) -> tuple[bool, float]:
        """Calculates cosine similarity between live and reference embedding."""
        sim = float(np.dot(live_emb, ref_emb))
        return (sim >= self.threshold), sim


def get_engine() -> FaceAuthEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = FaceAuthEngine()
    return _engine_instance


# ---------------------------------------------------------------- Secure Profile Store
def _profile_path(vault_path: str) -> str:
    base, _ = os.path.splitext(os.path.abspath(vault_path))
    return base + ".faceid"


def has_biometric_profile(vault_path: str) -> bool:
    return os.path.exists(_profile_path(vault_path))


def save_biometric_profile(vault_path: str, biometric_key: bytes, embedding: np.ndarray) -> None:
    """Encrypts BK and embedding with DPAPI and stores to disk."""
    data = {
        "version": 1,
        "biometric_key_hex": biometric_key.hex(),
        "embedding": embedding.tolist(),
    }
    raw = json.dumps(data).encode("utf-8")
    enc = dpapi_encrypt(raw, description="SafeSpace Biometric Profile")
    p = _profile_path(vault_path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(enc)


def load_biometric_profile(vault_path: str) -> tuple[bytes, np.ndarray] | None:
    """Loads and decrypts BK and embedding using DPAPI."""
    p = _profile_path(vault_path)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "rb") as f:
            enc = f.read()
        raw = dpapi_decrypt(enc)
        data = json.loads(raw.decode("utf-8"))
        bio_key = bytes.fromhex(data["biometric_key_hex"])
        emb = np.array(data["embedding"], dtype=np.float32)
        return bio_key, emb
    except Exception:
        return None


def delete_biometric_profile(vault_path: str) -> None:
    p = _profile_path(vault_path)
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass



def get_engine() -> FaceAuthEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = FaceAuthEngine()
    return _engine_instance


# ---------------------------------------------------------------- Secure Profile Store
def _profile_path(vault_path: str) -> str:
    base, _ = os.path.splitext(os.path.abspath(vault_path))
    return base + ".faceid"


def has_biometric_profile(vault_path: str) -> bool:
    return os.path.exists(_profile_path(vault_path))


def save_biometric_profile(vault_path: str, biometric_key: bytes, embedding: np.ndarray) -> None:
    """Encrypts BK and embedding with DPAPI and stores to disk."""
    data = {
        "version": 1,
        "biometric_key_hex": biometric_key.hex(),
        "embedding": embedding.tolist(),
    }
    raw = json.dumps(data).encode("utf-8")
    enc = dpapi_encrypt(raw, description="SafeSpace Biometric Profile")
    p = _profile_path(vault_path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(enc)


def load_biometric_profile(vault_path: str) -> tuple[bytes, np.ndarray] | None:
    """Loads and decrypts BK and embedding using DPAPI."""
    p = _profile_path(vault_path)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "rb") as f:
            enc = f.read()
        raw = dpapi_decrypt(enc)
        data = json.loads(raw.decode("utf-8"))
        bio_key = bytes.fromhex(data["biometric_key_hex"])
        emb = np.array(data["embedding"], dtype=np.float32)
        return bio_key, emb
    except Exception:
        return None


def delete_biometric_profile(vault_path: str) -> None:
    p = _profile_path(vault_path)
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass