"""
passgen.py - PassGen (random passwords / passphrases) and a plain-language strength check.
"""

import math
import re
import secrets
import string

AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*-_=+?"

# Short word list for passphrases (easy to type, no homophones). Extend freely.
WORDS = """
apple river candle orbit maple tiger pencil cloud harbor violet rocket meadow
silver garden puzzle lantern copper falcon bridge pepper canyon velvet anchor
marble summit thunder willow cactus breeze nickel galaxy pebble saddle walnut
jungle oyster rubber quartz meteor parrot tunnel cobalt dragon ember fossil
glacier hammock island jigsaw kettle lemon mango napkin olive panda quiver
raven shovel tomato umbrella vapor wizard yogurt zebra button cherry dolphin
""".split()

COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "111111",
    "letmein", "welcome", "monkey", "dragon", "iloveyou", "admin", "login",
    "princess", "sunshine", "football", "master", "passw0rd", "password1",
    "qwerty123", "1q2w3e4r", "000000", "trustno1", "baseball", "shadow",
}


def generate_password(length=16, upper=True, lower=True, digits=True, symbols=True,
                      avoid_ambiguous=True) -> str:
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        pools.append(string.ascii_lowercase)
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    length = max(length, len(pools))
    # One character from each chosen group, the rest from all of them, then shuffle.
    chars = [secrets.choice(p) for p in pools]
    everything = "".join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def generate_passphrase(words=4, separator="-", capitalize=True, add_number=True) -> str:
    picked = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        picked = [w.capitalize() for w in picked]
    if add_number:
        picked.append(str(secrets.randbelow(90) + 10))
    return separator.join(picked)


# ---------------------------------------------------------------- strength
LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


def _has_sequence(pw: str, run=4) -> bool:
    low = pw.lower()
    for seq in (string.ascii_lowercase, string.digits, "qwertyuiop", "asdfghjkl", "zxcvbnm"):
        for i in range(len(seq) - run + 1):
            if seq[i:i + run] in low or seq[i:i + run][::-1] in low:
                return True
    return False


def strength(pw: str) -> tuple[int, str, str]:
    """Returns (score 0-4, label, one-line advice)."""
    if not pw:
        return 0, LABELS[0], "Enter a password."
    base = pw.lower().rstrip("0123456789!@#$%^&*")
    if pw.lower() in COMMON or base in COMMON:
        return 0, LABELS[0], "This is one of the most commonly used passwords."

    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 33
    unique = len(set(pw))
    bits = min(len(pw), unique * 2) * math.log2(max(pool, 2))

    words = [w for w in WORDS if w in pw.lower()]
    if len(words) >= 3:                       # passphrases: count words, not characters
        bits = max(bits * 0.6, len(words) * math.log2(len(WORDS)) + 10)
    if _has_sequence(pw):
        bits -= 15
    if unique <= 3:
        bits = min(bits, 20)
    if len(pw) <= 12 and re.fullmatch(r"[A-Za-z]+[0-9]{1,4}[!@#$?.]?", pw):
        bits = min(bits, 35)                  # "Summer2024!" style: word + year

    if bits < 28:
        score = 0
    elif bits < 40:
        score = 1
    elif bits < 60:
        score = 2
    elif bits < 80:
        score = 3
    else:
        score = 4

    if score >= 3:
        advice = "Hard to guess."
    elif len(pw) < 12:
        advice = "Too short. Use at least 12 characters, or let PassGen make one."
    elif _has_sequence(pw):
        advice = "Contains an easy pattern like 1234 or qwerty."
    else:
        advice = "Mix in more character types, or make it longer."
    return score, LABELS[score], advice


def is_weak(score: int) -> bool:
    return score <= 1
