"""
app.py - SafeSpace desktop password manager (Tkinter UI).

    python app.py                 # your real vault (%APPDATA%\\SafeSpace\\vault.json)
    python app.py --demo          # fresh sample vault for usability sessions
    python app.py --vault FILE    # use a specific vault file

Requires: pip install argon2-cffi pynacl cryptography
"""

import argparse
import json
import math
import os
import secrets
import shutil
import sys
import threading
import time
import tkinter as tk
import webbrowser
from contextlib import contextmanager
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk
import tkinter.font as tkfont

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageTk

import face_auth
import passgen
from open_locker_demo import WrongPinOrTampered
from vault import Vault, WrongMasterPassword, default_vault_path, read_import_csv

# Global rate limiting state (Argon2id DoS mitigation)
_failed_attempts = 0
_cooldown_until = 0.0

APP = "SafeSpace"
VERSION = "0.1"
NOTICE = "Course prototype (Usable Security, IIIT Delhi). Not audited: do not store real passwords."
CATEGORIES = ["Email", "Social", "Banking", "Shopping", "Work", "Entertainment", "Other"]
PROTECTION_POINTS = [
    "They stay on this computer. Nothing is sent over the internet.",
    "They are locked (encrypted) with your master password. Without it, the vault file is unreadable.",
    "Nobody, including the SafeSpace team, can see them or reset your master password for you.",
]
MIN_PIN = 6            # minimum length of an entry's "Extra lock" PIN (digits only)
ATTENTION = "Needs attention"
ALL = "All items"

METER = ["#ef4444", "#f97316", "#eab308", "#10b981", "#059669"]

def _detect_font() -> str:
    try:
        fams = set(tkfont.families())
        for f in ("Segoe UI Variable Text", "Segoe UI", "SF Pro Text", "Inter", "Helvetica"):
            if f in fams:
                return f
    except Exception:
        pass
    return "Segoe UI"

FONT = _detect_font()

# Modern, clean color themes (Slate & Blue palette). apply_theme() copies one of these
# into module-level variables so screens and dialogs pick up the new colors dynamically.
THEMES = {
    "light": dict(
        BG="#f8fafc",               # Clean slate-50 background
        CARD="#ffffff",             # Pure white elevated card
        LINE="#e2e8f0",             # Slate-200 clean 1px border
        LINE_SUBTLE="#f1f5f9",      # Slate-100 very soft divider
        TEXT="#0f172a",             # Slate-900 deep charcoal
        MUTED="#64748b",            # Slate-500 refined secondary grey
        PRIMARY="#2563eb",          # Modern Blue-600 (vibrant accent)
        PRIMARY_DARK="#1d4ed8",     # Blue-700 active/pressed
        PRIMARY_OFF="#93c5fd",      # Blue-300 disabled
        PRIMARY_LIGHT="#eff6ff",    # Blue-50 soft selection highlight
        WARN_BG="#fffbeb",          # Amber-50 notice pill/banner
        WARN_FG="#b45309",          # Amber-700 readable amber text
        WARN_BORDER="#fde68a",      # Amber-200 subtle border
        BAD_FG="#ef4444",           # Rose-500 clean modern danger
        BAD_BG="#fef2f2",           # Rose-50
        GOOD_FG="#10b981",          # Emerald-500 crisp security green
        GOOD_BG="#ecfdf5",          # Emerald-50
        FIELD="#ffffff",            # Pure white input background
        FIELD_RO="#f8fafc",         # Soft slate-50 readonly/input container (replaces dirty grey)
        HEAD_BG="#f8fafc",          # Slate-50 table header
        HOVER="#f1f5f9",            # Slate-100 interactive hover
        PRESSED="#e2e8f0",          # Slate-200 interactive pressed
        TROUGH="#e2e8f0",           # Slate-200 progress bar trough
        ACCENT="#3b82f6",           # Blue-500
    ),
    "dark": dict(
        BG="#0f172a",               # Slate-900 deep midnight
        CARD="#1e293b",             # Slate-800 elevated dark card
        LINE="#334155",             # Slate-700 subtle border
        LINE_SUBTLE="#1e293b",      # Slate-800
        TEXT="#f8fafc",             # Slate-50 bright crisp white text
        MUTED="#94a3b8",            # Slate-400 clean secondary text
        PRIMARY="#3b82f6",          # Blue-500 vibrant blue
        PRIMARY_DARK="#2563eb",     # Blue-600 pressed
        PRIMARY_OFF="#1d4ed8",      # Blue-800 disabled
        PRIMARY_LIGHT="#1e3a8a",    # Dark blue selection
        WARN_BG="#451a03",          # Amber-950
        WARN_FG="#fde68a",          # Amber-200
        WARN_BORDER="#78350f",      # Amber-900
        BAD_FG="#f87171",           # Red-400
        BAD_BG="#450a0a",           # Red-950
        GOOD_FG="#34d399",          # Emerald-400
        GOOD_BG="#064e3b",          # Emerald-950
        FIELD="#0f172a",            # Deep input field
        FIELD_RO="#1e293b",         # Elevated card readonly
        HEAD_BG="#1e293b",          # Matching dark table header
        HOVER="#334155",            # Slate-700 hover
        PRESSED="#475569",          # Slate-600 pressed
        TROUGH="#334155",           # Slate-700
        ACCENT="#60a5fa",           # Blue-400
    ),
}
THEME_NAMES = {"light": "Light", "dark": "Dark"}
THEME = "light"
BG = CARD = LINE = LINE_SUBTLE = TEXT = MUTED = PRIMARY = PRIMARY_DARK = PRIMARY_OFF = PRIMARY_LIGHT = ""
WARN_BG = WARN_FG = WARN_BORDER = BAD_FG = BAD_BG = GOOD_FG = GOOD_BG = ""
FIELD = FIELD_RO = HEAD_BG = HOVER = PRESSED = TROUGH = ACCENT = ""


def apply_theme(name: str) -> None:
    global THEME
    THEME = name if name in THEMES else "light"
    globals().update(THEMES[THEME])


apply_theme("light")

# Text size: fs() scales every font size, px() the layout sizes given in pixels
# (row height, panel width, wrapping). Screens are rebuilt after a change.
TEXT_SIZES = {"normal": ("Normal", 1.0), "large": ("Large", 1.2), "xlarge": ("Extra large", 1.4)}
TEXT_SIZE, SCALE = "normal", 1.0


def apply_text_size(name: str) -> None:
    global TEXT_SIZE, SCALE
    TEXT_SIZE = name if name in TEXT_SIZES else "normal"
    SCALE = TEXT_SIZES[TEXT_SIZE][1]


def px(n: int) -> int:
    """A pixel size scaled to the chosen text size."""
    return int(round(n * SCALE))


def fs(n: int) -> int:
    """A font point size scaled to the chosen text size."""
    return int(round(n * SCALE))


# ---------------------------------------------------------------- helpers
@contextmanager
def busy(widget):
    top = widget.winfo_toplevel()
    top.config(cursor="watch")
    top.update_idletasks()
    try:
        yield
    finally:
        top.config(cursor="")


def fmt_date(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M") if ts else "unknown"


_SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "gen", "firm", "ind", "nic"}


def site_key(url: str) -> str:
    """Main site of a URL, used to group logins: 'https://mail.google.com/x' -> 'google.com',
    'amazon.co.in' -> 'amazon.co.in'. Returns '' when there is no website."""
    host = url.strip().lower().split("://", 1)[-1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1].split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2 or all(p.isdigit() for p in parts):
        return host
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


_BASE_FONT_SIZES = {}


def setup_styles(root: tk.Tk) -> None:
    s = ttk.Style(root)
    # Tk's built-in fonts (used by the PIN / master-password prompts) follow the text size too.
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
        f = tkfont.nametofont(name)
        _BASE_FONT_SIZES.setdefault(name, f.cget("size"))
        f.configure(size=int(round(_BASE_FONT_SIZES[name] * SCALE)), family=FONT)
    s.theme_use("clam")
    root.configure(bg=BG)

    # Base styling
    s.configure(".", background=BG, foreground=TEXT, font=(FONT, fs(10)), fieldbackground=FIELD)

    # Standard clean button
    s.configure("TButton", relief="flat", borderwidth=1, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE,
                background=CARD, foreground=TEXT, font=(FONT, fs(10)), padding=(px(12), px(6)))
    s.map("TButton",
          background=[("disabled", FIELD_RO), ("pressed", PRESSED), ("active", HOVER)],
          bordercolor=[("disabled", LINE), ("active", PRIMARY)],
          foreground=[("disabled", MUTED)])

    # Primary accent button (vibrant modern blue)
    s.configure("Primary.TButton", relief="flat", borderwidth=0, bordercolor=PRIMARY, lightcolor=PRIMARY, darkcolor=PRIMARY,
                background=PRIMARY, foreground="#ffffff", padding=(px(14), px(7)),
                font=(FONT, fs(10), "bold"))
    s.map("Primary.TButton",
          background=[("disabled", PRIMARY_OFF), ("pressed", PRIMARY_DARK), ("active", PRIMARY_DARK)],
          foreground=[("disabled", "#ffffff")])

    # Small action button (for Copy, Open, etc.)
    s.configure("Small.TButton", relief="flat", borderwidth=1, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE,
                background=CARD, foreground=TEXT, font=(FONT, fs(9)), padding=(px(8), px(3)))
    s.map("Small.TButton",
          background=[("disabled", FIELD_RO), ("pressed", PRESSED), ("active", HOVER)],
          bordercolor=[("active", PRIMARY)])

    # Danger button
    s.configure("Danger.TButton", relief="flat", borderwidth=1, bordercolor=BAD_FG, lightcolor=BAD_FG, darkcolor=BAD_FG,
                background=CARD, foreground=BAD_FG, font=(FONT, fs(10)), padding=(px(12), px(6)))
    s.map("Danger.TButton",
          background=[("active", BAD_BG), ("pressed", BAD_BG)],
          bordercolor=[("active", BAD_FG)])

    # Link button
    s.configure("Link.TButton", foreground=PRIMARY, background=CARD, borderwidth=0, padding=0,
                font=(FONT, fs(10)))
    s.map("Link.TButton", background=[("active", CARD)], foreground=[("active", PRIMARY_DARK)])

    # Menu button (for "⋯")
    s.configure("More.TMenubutton", font=(FONT, fs(12), "bold"), padding=(px(8), px(2)),
                relief="flat", borderwidth=1, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE,
                background=CARD, foreground=MUTED)
    s.map("More.TMenubutton",
          background=[("active", HOVER), ("pressed", PRESSED)],
          bordercolor=[("active", PRIMARY)],
          foreground=[("active", TEXT)])

    # Entry fields
    s.configure("TEntry", relief="flat", borderwidth=1, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE,
                padding=(px(8), px(6)), fieldbackground=FIELD, insertcolor=PRIMARY)
    s.map("TEntry",
          bordercolor=[("focus", PRIMARY)],
          lightcolor=[("focus", PRIMARY)],
          darkcolor=[("focus", PRIMARY)])

    # Borderless search entry
    s.configure("Search.TEntry", relief="flat", borderwidth=0, bordercolor=FIELD, lightcolor=FIELD, darkcolor=FIELD,
                padding=(px(4), px(4)), fieldbackground=FIELD, insertcolor=PRIMARY)

    # Combobox
    s.configure("TCombobox", relief="flat", borderwidth=1, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE,
                padding=(px(6), px(5)), arrowsize=px(12), arrowcolor=MUTED, insertcolor=PRIMARY)
    s.map("TCombobox",
          bordercolor=[("focus", PRIMARY)],
          lightcolor=[("focus", PRIMARY)],
          darkcolor=[("focus", PRIMARY)],
          fieldbackground=[("readonly", "focus", PRIMARY_LIGHT), ("readonly", FIELD_RO)],
          foreground=[("readonly", "focus", PRIMARY)],
          background=[("active", HOVER)])
    root.option_add("*TCombobox*Listbox.background", FIELD)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.font", (FONT, fs(10)))
    root.option_add("*TCombobox*Listbox.selectBackground", PRIMARY)
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

    # Frames and Labels
    s.configure("Card.TFrame", background=CARD)
    s.configure("Card.TLabel", background=CARD, foreground=TEXT)
    s.configure("Muted.TLabel", foreground=MUTED, background=BG)
    s.configure("CardMuted.TLabel", background=CARD, foreground=MUTED)
    s.configure("Title.TLabel", font=(FONT, fs(20), "bold"), background=BG, foreground=TEXT)
    s.configure("H2.TLabel", font=(FONT, fs(12), "bold"), background=CARD, foreground=TEXT)
    s.configure("Big.TLabel", font=(FONT, fs(15), "bold"), background=CARD, foreground=TEXT)
    s.configure("Mono.TLabel", font=("Consolas", fs(13)), background=CARD, foreground=TEXT)

    # Header and Warning
    s.configure("Header.TFrame", background=CARD)
    s.configure("Warn.TFrame", background=WARN_BG)
    s.configure("Warn.TLabel", background=WARN_BG, foreground=WARN_FG, font=(FONT, fs(10), "bold"))
    s.configure("WarnMuted.TLabel", background=WARN_BG, foreground=WARN_FG, font=(FONT, fs(9)))

    # Checks and Radios
    s.configure("TCheckbutton", background=CARD, foreground=TEXT, font=(FONT, fs(10)))
    s.configure("TRadiobutton", background=CARD, foreground=TEXT, font=(FONT, fs(10)))

    # Treeview (Modern list layout)
    s.configure("Treeview", rowheight=px(42), font=(FONT, fs(10)),
                background=CARD, fieldbackground=CARD, foreground=TEXT,
                relief="flat", borderwidth=0, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE)
    s.map("Treeview",
          background=[("selected", PRIMARY_LIGHT)],
          foreground=[("selected", PRIMARY)])

    s.configure("Treeview.Heading", relief="flat", borderwidth=0,
                bordercolor=LINE, lightcolor=LINE, darkcolor=LINE,
                background=HEAD_BG, foreground=TEXT, font=(FONT, fs(9), "bold"),
                padding=(px(12), px(10)))
    s.map("Treeview.Heading",
          background=[("active", HOVER)],
          relief=[("active", "flat"), ("pressed", "flat")])

    # Scales and Progressbars
    s.configure("Horizontal.TScale", background=CARD)
    s.configure("Horizontal.TProgressbar", relief="flat", borderwidth=0, troughcolor=TROUGH,
                bordercolor=TROUGH, lightcolor=TROUGH, darkcolor=TROUGH)
    s.configure("Vertical.TScrollbar", relief="flat", borderwidth=0,
                troughcolor=BG, background=LINE, arrowcolor=MUTED, bordercolor=BG, lightcolor=BG, darkcolor=BG)
    s.map("Vertical.TScrollbar", background=[("active", MUTED)])
    for i, c in enumerate(METER):
        s.configure(f"M{i}.Horizontal.TProgressbar", background=c, troughcolor=TROUGH,
                    bordercolor=TROUGH, lightcolor=c, darkcolor=c)


# ---------------------------------------------------------------- modern curved UI helpers
def _get_parent_bg(parent, fallback=None):
    """Safely get the background color of a parent widget, handling ttk widgets."""
    try:
        return parent.cget("bg")
    except Exception:
        try:
            return parent.cget("background")
        except Exception:
            return fallback or BG

_img_cache = {}
_emoji_img_cache = {}

def get_emoji_icon(emoji: str, size=16):
    """Render crisp, consistent Segoe UI Emoji icons across Windows Tkinter."""
    key = (emoji, size)
    if key in _emoji_img_cache:
        return _emoji_img_cache[key]
    scale = 3
    ssize = size * scale
    img = Image.new("RGBA", (ssize, ssize), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("seguiemj.ttf", int(size * scale * 0.92))
        draw.text((0, 0), emoji, font=font, embedded_color=True)
    except Exception:
        try:
            font = ImageFont.truetype("segoeui.ttf", int(size * scale * 0.85))
            draw.text((0, 0), emoji, font=font, fill="#475569")
        except Exception:
            font = ImageFont.load_default()
            draw.text((0, 0), emoji, font=font, fill="#475569")
    res = ImageTk.PhotoImage(img.resize((size, size), Image.Resampling.LANCZOS))
    _emoji_img_cache[key] = res
    return res

def get_rounded_rect_img(w, h, r, fill, outline=None, width=1):
    w, h = max(1, int(w)), max(1, int(h))
    r = max(1, min(int(r), w // 2, h // 2))
    key = (w, h, r, fill, outline, width)
    if key in _img_cache:
        return _img_cache[key]
    scale = 3
    sw, sh = w * scale, h * scale
    sr = max(1, r * scale)
    sow = width * scale if outline else 0
    img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, sw - 1, sh - 1], radius=sr, fill=fill, outline=outline, width=sow)
    res = ImageTk.PhotoImage(img.resize((w, h), Image.Resampling.LANCZOS))
    _img_cache[key] = res
    return res


_avatar_cache = {}

def get_service_avatar(name="", size=32, radius=8):
    name = (name or "?").strip()
    letter = name[0].upper()
    # Clean neutral monochrome palette (black / dark charcoal text on crisp slate background)
    bg_color = "#f1f5f9" if THEME == "light" else "#334155"
    fg_color = "#0f172a" if THEME == "light" else "#f8fafc"
    border_color = "#cbd5e1" if THEME == "light" else "#475569"
    key = (letter, bg_color, fg_color, border_color, size, radius)
    if key in _avatar_cache:
        return _avatar_cache[key]
    scale = 3
    ssize = size * scale
    sradius = radius * scale
    img = Image.new("RGBA", (ssize, ssize), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, ssize - 1, ssize - 1], radius=sradius, fill=bg_color, outline=border_color, width=max(1, int(1 * scale)))
    try:
        font = ImageFont.truetype("segoeuib.ttf", int(13 * scale))
    except Exception:
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), letter, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((ssize - tw) // 2, (ssize - th) // 2 - int(2 * scale)), letter, fill=fg_color, font=font)
    res = ImageTk.PhotoImage(img.resize((size, size), Image.Resampling.LANCZOS))
    _avatar_cache[key] = res
    return res


class RoundedCard(tk.Canvas):
    """A smooth anti-aliased container card with curved corners and clean border."""

    def __init__(self, parent, bg_color=None, border_color=None, radius=14, border_width=1, auto_height=False, **kw):
        c_bg = _get_parent_bg(parent, BG)
        super().__init__(parent, highlightthickness=0, bg=c_bg, **kw)
        self.card_bg = bg_color or CARD
        self.border_color = border_color or LINE
        self.radius = radius
        self.border_width = border_width
        self.auto_height = auto_height
        self.inner = tk.Frame(self, bg=self.card_bg)
        self._win_id = self.create_window(0, 0, window=self.inner, anchor="nw")
        self.bind("<Configure>", self._on_resize)
        if self.auto_height:
            self.inner.bind("<Configure>", self._on_inner_config)

    def _on_inner_config(self, event=None):
        req_h = self.inner.winfo_reqheight()
        pad = max(6, self.radius // 2)
        target_h = req_h + pad * 2
        if abs(self.winfo_height() - target_h) > 2:
            self.config(height=target_h)

    def _on_resize(self, event):
        w, h = event.width, event.height
        if w < 5 or h < 5:
            return
        img = get_rounded_rect_img(w, h, self.radius, self.card_bg, self.border_color, self.border_width)
        self.delete("bg_rect")
        self.create_image(0, 0, image=img, anchor="nw", tags="bg_rect")
        self.tag_lower("bg_rect")
        pad = max(6, self.radius // 2)
        self.coords(self._win_id, pad, pad)
        if self.auto_height:
            self.itemconfigure(self._win_id, width=max(1, w - pad * 2))
        else:
            self.itemconfigure(self._win_id, width=max(1, w - pad * 2), height=max(1, h - pad * 2))


class PillButton(tk.Canvas):
    """Clickable curved capsule button for category filters and quick actions."""

    def __init__(self, parent, text, command=None, is_active=False,
                 active_bg=None, active_fg="#ffffff",
                 inactive_bg=None, inactive_fg=None, border_color=None,
                 font=None, padx=12, pady=5, **kw):
        c_bg = _get_parent_bg(parent, CARD)
        super().__init__(parent, highlightthickness=0, bg=c_bg, **kw)
        self.text = text
        self.command = command
        self.is_active = is_active
        self.is_hovered = False
        self.active_bg = active_bg or "#0f172a"
        self.active_fg = active_fg
        self.inactive_bg = inactive_bg or FIELD_RO
        self.inactive_fg = inactive_fg or TEXT
        self.border_color = border_color or LINE
        self.font = font or (FONT, fs(9), "bold")
        self.padx = padx
        self.pady = pady
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.render()

    def _on_enter(self, e):
        self.config(cursor="hand2")
        if not self.is_active:
            self.is_hovered = True
            self.render()

    def _on_leave(self, e):
        if not self.is_active:
            self.is_hovered = False
            self.render()

    def set_active(self, active):
        if self.is_active != active:
            self.is_active = active
            self.is_hovered = False
            self.render()

    def render(self):
        self.delete("all")
        t_id = self.create_text(0, 0, text=self.text, font=self.font, anchor="nw")
        bbox = self.bbox(t_id)
        self.delete(t_id)
        tw = (bbox[2] - bbox[0]) if bbox else 30
        th = (bbox[3] - bbox[1]) if bbox else 14
        w = max(36, tw + self.padx * 2)
        h = max(24, th + self.pady * 2)
        self.config(width=w, height=h)

        if self.is_active:
            fill = self.active_bg
            fg = self.active_fg
            outline = None
        elif self.is_hovered:
            fill = HOVER
            fg = self.inactive_fg
            outline = self.border_color
        else:
            fill = self.inactive_bg
            fg = self.inactive_fg
            outline = self.border_color

        img = get_rounded_rect_img(w, h, h // 2, fill, outline, 1)
        self.create_image(0, 0, image=img, anchor="nw")
        self.create_text(w // 2, h // 2, text=self.text, font=self.font, fill=fg, anchor="center")

    def _on_click(self, e):
        if self.command:
            self.command()


CAT_ICONS = {
    "All items": "🗂️",
    "Needs attention": "⚠️",
    "Email": "✉️",
    "Social": "💬",
    "Banking": "🏦",
    "Shopping": "🛍️",
    "Work": "💼",
    "Entertainment": "🎬",
    "Other": "📦",
}


class CurvedNavRow(tk.Canvas):
    """An individual curved pill row in the sidebar navigation."""

    def __init__(self, parent, icon="", name="", count="", is_active=False,
                 active_bg=None, active_fg="#ffffff", hover_bg=None,
                 text_fg=None, font=None, on_click=None):
        h = px(32)
        c_bg = _get_parent_bg(parent, CARD)
        super().__init__(parent, height=h, highlightthickness=0, bg=c_bg)
        self.icon = icon
        self.name = name
        self.count = count
        self.is_active = is_active
        self.is_hovered = False
        self.active_bg = active_bg or "#0f172a"
        self.active_fg = active_fg
        self.hover_bg = hover_bg or HOVER
        self.text_fg = text_fg or TEXT
        self.custom_fg = None
        self.font = font or (FONT, fs(10))
        self.on_click = on_click
        self._icon_img = None
        self.bind("<Configure>", self._render)
        self.bind("<Button-1>", lambda e: self.on_click() if self.on_click else None)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, e):
        self.config(cursor="hand2")
        if not self.is_active:
            self.is_hovered = True
            self._render()

    def _on_leave(self, e):
        if not self.is_active:
            self.is_hovered = False
            self._render()

    def set_active(self, active):
        if self.is_active != active:
            self.is_active = active
            self.is_hovered = False
            self._render()

    def _render(self, event=None):
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 10 or h < 10:
            return
        self.delete("all")
        r = min(px(14), h // 2)

        if self.is_active:
            bg_img = get_rounded_rect_img(w, h, r, self.active_bg)
            self.create_image(0, 0, image=bg_img, anchor="nw")
            fg = self.active_fg
            font = (FONT, fs(10), "bold")
            count_bg = "#334155" if THEME == "light" else "#475569"
            count_fg = "#ffffff"
        elif self.is_hovered:
            bg_img = get_rounded_rect_img(w, h, r, self.hover_bg)
            self.create_image(0, 0, image=bg_img, anchor="nw")
            fg = self.custom_fg or self.text_fg
            font = (FONT, fs(10))
            count_bg = LINE
            count_fg = TEXT
        else:
            fg = self.custom_fg or self.text_fg
            font = (FONT, fs(10))
            count_bg = FIELD_RO
            count_fg = MUTED

        # Render emoji icon as a high-DPI Pillow image so it never displays as black/white wireframe
        text_x = px(12)
        if self.icon:
            self._icon_img = get_emoji_icon(self.icon, size=px(16))
            self.create_image(px(12), h // 2, image=self._icon_img, anchor="w")
            text_x = px(36)

        self.create_text(text_x, h // 2, text=self.name, font=font, fill=fg, anchor="w")

        if self.count:
            cw, ch = px(24), px(18)
            cx, cy = w - cw - px(10), (h - ch) // 2
            count_img = get_rounded_rect_img(cw, ch, ch // 2, count_bg)
            self.create_image(cx, cy, image=count_img, anchor="nw")
            self.create_text(cx + cw // 2, cy + ch // 2, text=self.count,
                             font=(FONT, fs(8), "bold"), fill=count_fg, anchor="center")


class CurvedNavList(tk.Frame):
    """Curved sidebar navigation list with tk.Listbox drop-in API compatibility."""

    def __init__(self, parent, bg=None, active_bg=None, active_fg="#ffffff",
                 hover_bg=None, text_fg=None, font=None, **kw):
        c_bg = bg or CARD
        super().__init__(parent, bg=c_bg, **kw)
        self.rows = []
        self.selected_idx = None
        self.active_bg = active_bg or "#0f172a"
        self.active_fg = active_fg
        self.hover_bg = hover_bg or HOVER
        self.text_fg = text_fg or TEXT
        self.font = font or (FONT, fs(10))
        self._callbacks = []

    def bind(self, sequence, func, add=None):
        if sequence == "<<ListboxSelect>>":
            self._callbacks.append(func)
        else:
            super().bind(sequence, func, add=add)

    def curselection(self):
        return (self.selected_idx,) if self.selected_idx is not None else ()

    def selection_set(self, idx):
        if 0 <= idx < len(self.rows):
            self.selected_idx = idx
            self._update_visuals()

    def delete(self, start, end=None):
        self.rows.clear()
        self.selected_idx = None
        for w in self.winfo_children():
            w.destroy()

    def insert(self, pos, text):
        idx = len(self.rows)
        clean_text = text.strip()
        icon = ""
        count_str = ""
        name = clean_text
        if "(" in clean_text and clean_text.endswith(")"):
            name_part, count_part = clean_text.rsplit("(", 1)
            name = name_part.strip()
            count_str = count_part.rstrip(")").strip()
            if name.startswith("⚠") or "Needs attention" in name:
                name = "Needs attention"
                icon = "⚠️"
        if not icon:
            icon = CAT_ICONS.get(name, "📦")

        row = CurvedNavRow(
            self,
            icon=icon,
            name=name,
            count=count_str,
            is_active=(idx == self.selected_idx),
            active_bg=self.active_bg,
            active_fg=self.active_fg,
            hover_bg=self.hover_bg,
            text_fg=self.text_fg,
            font=self.font,
            on_click=lambda i=idx: self._select_row(i),
        )
        row.pack(fill="x", pady=px(2))
        self.rows.append(row)

    def itemconfigure(self, idx, **kw):
        if idx == "end":
            idx = len(self.rows) - 1
        if 0 <= idx < len(self.rows):
            if "foreground" in kw:
                self.rows[idx].custom_fg = kw["foreground"]
                self.rows[idx]._render()

    def _select_row(self, idx):
        self.selected_idx = idx
        self._update_visuals()
        for cb in self._callbacks:
            cb(None)

    def _update_visuals(self):
        for i, row in enumerate(self.rows):
            row.set_active(i == self.selected_idx)


class Dialog(tk.Toplevel):
    """Modal window centred on its parent."""

    def __init__(self, parent, title, scroll=False):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=CARD)
        self.transient(parent.winfo_toplevel())
        self.resizable(False, False)
        self._canvas = None
        if scroll:      # body sits in a canvas so a tall dialog (e.g. with large text) can scroll
            self._canvas = tk.Canvas(self, bg=CARD, highlightthickness=0)
            self._sb = ttk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
            self._canvas.configure(yscrollcommand=self._sb.set)
            self._sb.pack(side="right", fill="y")
            self._canvas.pack(side="left", fill="both", expand=True)
            self.body = ttk.Frame(self._canvas, style="Card.TFrame", padding=20)
            self._canvas.create_window(0, 0, window=self.body, anchor="nw")
            self.bind("<MouseWheel>", lambda e: self._canvas.yview_scroll(-e.delta // 120, "units"))
        else:
            self.body = ttk.Frame(self, style="Card.TFrame", padding=20)
            self.body.pack(fill="both", expand=True)
        self.bind("<Escape>", lambda e: self.destroy())

    def show(self):
        self.update_idletasks()
        if self._canvas:
            w, h = self.body.winfo_reqwidth(), self.body.winfo_reqheight()
            max_h = self.winfo_screenheight() - 140
            self._canvas.configure(width=w, height=min(h, max_h), scrollregion=(0, 0, w, h))
            if h <= max_h:
                self._sb.pack_forget()
            self.update_idletasks()
        p = self.master.winfo_toplevel()
        x = p.winfo_rootx() + (p.winfo_width() - self.winfo_reqwidth()) // 2
        y = p.winfo_rooty() + (p.winfo_height() - self.winfo_reqheight()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        prev = self.grab_current()
        self.grab_set()
        self.focus_set()
        self.wait_window()
        try:
            if prev is not None and prev.winfo_exists():
                prev.grab_set()
        except tk.TclError:
            pass


class StrengthMeter(ttk.Frame):
    """Coloured bar + label + advice, bound to a StringVar."""

    def __init__(self, parent, var: tk.StringVar, style="Card"):
        super().__init__(parent, style=f"{style}.TFrame")
        self.bar = ttk.Progressbar(self, maximum=4, length=220, style="M0.Horizontal.TProgressbar")
        self.bar.grid(row=0, column=0, sticky="w")
        self.label = ttk.Label(self, style=f"{style}.TLabel", font=(FONT, fs(10), "bold"))
        self.label.grid(row=0, column=1, padx=10, sticky="w")
        self.advice = ttk.Label(self, style=f"{style}Muted.TLabel", wraplength=px(380))
        self.advice.grid(row=1, column=0, columnspan=2, sticky="w")
        self.var = var
        var.trace_add("write", lambda *a: self.refresh())
        self.refresh()

    def refresh(self):
        pw = self.var.get()
        score, label, advice = passgen.strength(pw)
        self.bar.configure(value=score + 1 if pw else 0, style=f"M{score}.Horizontal.TProgressbar")
        self.label.configure(text=label if pw else "", foreground=METER[score])
        self.advice.configure(text=advice if pw else "")
        self.score = score if pw else -1


class PasswordField(ttk.Frame):
    """Masked entry with a Show/Hide toggle."""

    def __init__(self, parent, var, width=34):
        super().__init__(parent, style="Card.TFrame")
        self.entry = ttk.Entry(self, textvariable=var, show="•", width=width, font=(FONT, fs(11)))
        self.entry.pack(side="left", fill="x", expand=True)
        self.btn = ttk.Button(self, text="Show", width=6, command=self.toggle)
        self.btn.pack(side="left", padx=(6, 0))

    def toggle(self):
        hidden = self.entry.cget("show") == "•"
        self.entry.configure(show="" if hidden else "•")
        self.btn.configure(text="Hide" if hidden else "Show")


class NewMasterForm(ttk.Frame):
    """Master password + confirmation with live strength feedback."""

    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.pw, self.pw2 = tk.StringVar(), tk.StringVar()
        ttk.Label(self, text="Master password", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        self.field = PasswordField(self, self.pw)
        self.field.grid(row=1, column=0, sticky="we", pady=(2, 6))
        self.meter = StrengthMeter(self, self.pw)
        self.meter.grid(row=2, column=0, sticky="w", pady=(0, 10))
        ttk.Label(self, text="Type it again", style="Card.TLabel").grid(row=3, column=0, sticky="w")
        PasswordField(self, self.pw2).grid(row=4, column=0, sticky="we", pady=(2, 0))
        ttk.Label(self, style="CardMuted.TLabel", wraplength=px(400),
                  text="Tip: a short sentence you'll remember works well, e.g. "
                       "“my cat sleeps on the blue sofa”.").grid(row=5, column=0, sticky="w", pady=(8, 0))

    def focus(self):
        self.field.entry.focus_set()

    def validate(self, parent) -> str | None:
        pw = self.pw.get()
        if len(pw) < 10 or self.meter.score < 2:
            messagebox.showwarning(APP, "Please choose a stronger master password (at least 10 characters "
                                        "and rated Fair or better). It protects everything else.", parent=parent)
            return None
        if pw != self.pw2.get():
            messagebox.showwarning(APP, "The two passwords don't match.", parent=parent)
            return None
        return pw


def show_recovery_key(parent, key: str) -> None:
    """Shows a recovery key once; the user must confirm they stored it."""
    d = Dialog(parent, "Your recovery key")
    d.protocol("WM_DELETE_WINDOW", lambda: None)       # must use the button
    d.unbind("<Escape>")
    b = d.body
    ttk.Label(b, text="Save your recovery key", style="Big.TLabel").pack(anchor="w")
    ttk.Label(b, style="Card.TLabel", wraplength=px(460), justify="left",
              text="If you ever forget your master password, this key is the only way to get "
                   "back into SafeSpace. Nobody, including the SafeSpace team, can reset it for you.\n\n"
                   "Write it down or save it somewhere safe that isn't this computer.").pack(anchor="w", pady=(6, 12))
    box = tk.Frame(b, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(16), pady=px(12))
    box.pack(fill="x")
    ttk.Label(box, text=key, style="Mono.TLabel", background=FIELD_RO).pack()
    row = ttk.Frame(b, style="Card.TFrame")
    row.pack(fill="x", pady=12)

    def copy():
        d.clipboard_clear()
        d.clipboard_append(key)

    def save():
        f = filedialog.asksaveasfilename(parent=d, title="Save recovery key", defaultextension=".txt",
                                         initialfile="SafeSpace-recovery-key.txt")
        if f:
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(f"SafeSpace recovery key\n\n{key}\n\nCreated {fmt_date(int(time.time()))}\n"
                         "Keep this somewhere safe. Anyone with this key and your vault file can open it.\n")

    ttk.Button(row, text="Copy", command=copy).pack(side="left")
    ttk.Button(row, text="Save to file…", command=save).pack(side="left", padx=6)
    ok = tk.BooleanVar()
    cont = ttk.Button(b, text="Continue", style="Primary.TButton", state="disabled", command=d.destroy)
    ttk.Checkbutton(b, text="I have stored my recovery key somewhere safe", variable=ok,
                    command=lambda: cont.configure(state="normal" if ok.get() else "disabled")).pack(anchor="w", pady=(10, 0))
    cont.pack(anchor="e", pady=(14, 0))
    d.show()


# ---------------------------------------------------------------- PassGen
class PassGenDialog(Dialog):
    """Standalone (offers 'Save as new login') or picker (offers 'Use this password')."""

    def __init__(self, app, parent, on_use=None):
        super().__init__(parent, "PassGen — password generator")
        self.app, self.on_use = app, on_use
        b = self.body
        ttk.Label(b, text="PassGen", style="Big.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(b, text="Makes a strong, random password so you don't have to invent one.",
                  style="CardMuted.TLabel").grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))

        self.result = tk.StringVar()
        out = tk.Frame(b, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(12), pady=px(10))
        out.grid(row=2, column=0, columnspan=3, sticky="we")
        ttk.Label(out, textvariable=self.result, style="Mono.TLabel", background=FIELD_RO, width=34).pack(side="left")
        ttk.Button(out, text="↻ New", command=self.generate).pack(side="right")
        self.meter = StrengthMeter(b, self.result)
        self.meter.grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 12))

        self.mode = tk.StringVar(value="chars")
        ttk.Radiobutton(b, text="Random characters", value="chars", variable=self.mode,
                        command=self.layout).grid(row=4, column=0, sticky="w")
        ttk.Radiobutton(b, text="Memorable words", value="words", variable=self.mode,
                        command=self.layout).grid(row=4, column=1, sticky="w")

        self.opts = ttk.Frame(b, style="Card.TFrame")
        self.opts.grid(row=5, column=0, columnspan=3, sticky="we", pady=8)
        self.length, self.words = tk.IntVar(value=16), tk.IntVar(value=4)
        self.flags = {k: tk.BooleanVar(value=True) for k in ("upper", "lower", "digits", "symbols", "avoid")}

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.grid(row=6, column=0, columnspan=3, sticky="e", pady=(10, 0))
        if on_use:
            ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
            ttk.Button(btns, text="Use this password", style="Primary.TButton",
                       command=self.use).pack(side="right", padx=6)
        else:
            ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")
            ttk.Button(btns, text="Save as new login…", style="Primary.TButton",
                       command=self.save_new).pack(side="right", padx=6)
            ttk.Button(btns, text="Copy", command=self.copy).pack(side="right")
        self.layout()

    def layout(self):
        for w in self.opts.winfo_children():
            w.destroy()
        o = self.opts
        self.count_lbl = ttk.Label(o, style="Card.TLabel", width=10)
        self.count_lbl.grid(row=0, column=0, sticky="w")
        if self.mode.get() == "chars":
            ttk.Scale(o, from_=8, to=40, variable=self.length, length=260,
                      command=lambda v: (self.length.set(round(float(v))), self.generate())).grid(
                row=0, column=1, columnspan=2, sticky="w", padx=8)
            names = [("upper", "Capital letters (A-Z)"), ("lower", "Small letters (a-z)"),
                     ("digits", "Numbers (0-9)"), ("symbols", "Symbols (!@#$)"),
                     ("avoid", "Avoid look-alikes (l, 1, O, 0)")]
            for i, (k, t) in enumerate(names):
                ttk.Checkbutton(o, text=t, variable=self.flags[k], command=self.generate).grid(
                    row=1 + i // 2, column=i % 2, sticky="w", pady=2, padx=(0, 16))
        else:
            ttk.Scale(o, from_=3, to=8, variable=self.words, length=260,
                      command=lambda v: (self.words.set(round(float(v))), self.generate())).grid(
                row=0, column=1, sticky="w", padx=8)
            ttk.Label(o, text="Easier to type and read out, still hard to guess.",
                      style="CardMuted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w")
        self.generate()

    def generate(self):
        chars = self.mode.get() == "chars"
        self.count_lbl.configure(text=f"Length: {self.length.get()}" if chars else f"Words: {self.words.get()}")
        if chars:
            f = {k: v.get() for k, v in self.flags.items()}
            self.result.set(passgen.generate_password(self.length.get(), f["upper"], f["lower"],
                                                      f["digits"], f["symbols"], f["avoid"]))
        else:
            self.result.set(passgen.generate_passphrase(self.words.get()))

    def copy(self):
        self.app.copy(self.result.get(), "Generated password")

    def use(self):
        self.on_use(self.result.get())
        self.destroy()

    def save_new(self):
        pw = self.result.get()
        self.destroy()
        EntryDialog(self.app, preset_password=pw).show()


# ---------------------------------------------------------------- add / edit entry
class EntryDialog(Dialog):
    def __init__(self, app, lid=None, meta=None, secret=None, pin="", preset_password=""):
        super().__init__(app, "Edit login" if lid else "Add a login")
        self.app, self.lid = app, lid
        meta, secret = meta or {}, secret or {}
        b = self.body
        ttk.Label(b, text="Edit login" if lid else "Save a new login", style="Big.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        self.v = {k: tk.StringVar(value=meta.get(k, "")) for k in ("name", "url", "username")}
        self.v["category"] = tk.StringVar(value=meta.get("category", "Other"))
        self.pw = tk.StringVar(value=secret.get("password", preset_password))

        def row(r, label, hint, widget):
            ttk.Label(b, text=label, style="Card.TLabel", font=(FONT, fs(10), "bold")).grid(
                row=r, column=0, sticky="nw", pady=(6, 0), padx=(0, 14))
            widget.grid(row=r, column=1, sticky="we", pady=(6, 0))
            if hint:
                ttk.Label(b, text=hint, style="CardMuted.TLabel").grid(row=r + 1, column=1, sticky="w")

        name = ttk.Entry(b, textvariable=self.v["name"], width=40, font=(FONT, fs(11)))
        row(1, "Name", "What you'll search for, e.g. Gmail or My bank", name)
        row(3, "Website", "Optional, e.g. mail.google.com", ttk.Entry(b, textvariable=self.v["url"], width=40,
                                                                      font=(FONT, fs(11))))
        row(5, "Username / email", None, ttk.Entry(b, textvariable=self.v["username"], width=40, font=(FONT, fs(11))))

        pwrow = ttk.Frame(b, style="Card.TFrame")
        self.pwfield = PasswordField(pwrow, self.pw, width=28)
        self.pwfield.pack(side="left", fill="x", expand=True)
        ttk.Button(pwrow, text="Generate…", command=self.open_passgen).pack(side="left", padx=(6, 0))
        row(6, "Password", None, pwrow)
        StrengthMeter(b, self.pw).grid(row=7, column=1, sticky="w", pady=(4, 0))

        row(8, "Category", None, ttk.Combobox(b, textvariable=self.v["category"], values=CATEGORIES,
                                              state="readonly", width=20))
        ttk.Label(b, text="Notes", style="Card.TLabel", font=(FONT, fs(10), "bold")).grid(
            row=9, column=0, sticky="nw", pady=(6, 0))
        self.notes = tk.Text(b, width=40, height=3, font=(FONT, fs(10)), relief="flat",
                             highlightbackground=LINE, highlightthickness=1,
                             padx=px(8), pady=px(6), bg=FIELD, fg=TEXT, insertbackground=PRIMARY)
        self.notes.insert("1.0", secret.get("notes", ""))
        self.notes.grid(row=9, column=1, sticky="we", pady=(6, 0))

        # Optional per-entry PIN (the "locker" layer)
        self.use_pin = tk.BooleanVar(value=bool(pin))
        self.pin, self.pin2 = tk.StringVar(value=pin), tk.StringVar(value=pin)
        pinbox = ttk.Frame(b, style="Card.TFrame")
        pinbox.grid(row=10, column=1, sticky="w", pady=(12, 0))
        ttk.Checkbutton(pinbox, text="Extra lock: ask for a PIN before showing this password",
                        variable=self.use_pin, command=self.toggle_pin).pack(anchor="w")
        self.pinfields = ttk.Frame(pinbox, style="Card.TFrame")
        ttk.Label(self.pinfields, text="PIN", style="Card.TLabel").pack(side="left")
        ttk.Entry(self.pinfields, textvariable=self.pin, show="•", width=10).pack(side="left", padx=6)
        ttk.Label(self.pinfields, text="Again", style="Card.TLabel").pack(side="left")
        ttk.Entry(self.pinfields, textvariable=self.pin2, show="•", width=10).pack(side="left", padx=6)
        ttk.Label(self.pinfields, text=f"At least {MIN_PIN} digits", style="CardMuted.TLabel").pack(side="left")
        self.toggle_pin()

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.grid(row=12, column=0, columnspan=2, sticky="e", pady=(18, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Save", style="Primary.TButton", command=self.save).pack(side="right", padx=6)
        self.bind("<Return>", lambda e: self.save() if e.widget is not self.notes else None)
        name.focus_set()

    def toggle_pin(self):
        if self.use_pin.get():
            self.pinfields.pack(anchor="w", pady=(4, 0))
        else:
            self.pinfields.pack_forget()

    def open_passgen(self):
        def use(pw):
            self.pw.set(pw)
            if self.pwfield.entry.cget("show") == "•":
                self.pwfield.toggle()
        PassGenDialog(self.app, self, on_use=use).show()

    def save(self):
        name, pw = self.v["name"].get().strip(), self.pw.get()
        if not name:
            messagebox.showwarning(APP, "Please give this login a name so you can find it later.", parent=self)
            return
        if not pw:
            messagebox.showwarning(APP, "Please enter a password, or click Generate to make one.", parent=self)
            return
        pin = ""
        if self.use_pin.get():
            pin = self.pin.get()
            if len(pin) < MIN_PIN or not pin.isdigit():
                messagebox.showwarning(APP, f"The PIN needs at least {MIN_PIN} digits (numbers only).",
                                       parent=self)
                return
            if pin != self.pin2.get():
                messagebox.showwarning(APP, "The two PINs don't match.", parent=self)
                return
        score = passgen.strength(pw)[0]
        meta = {"name": name, "url": self.v["url"].get().strip(), "username": self.v["username"].get().strip(),
                "category": self.v["category"].get() or "Other", "strength": score,
                "fp": self.app.vault.fingerprint(pw)}
        secret = {"password": pw, "notes": self.notes.get("1.0", "end").strip()}
        with busy(self):
            if self.lid:
                lid = self.app.vault.update_item(self.lid, meta, secret, pin)
            else:
                lid = self.app.vault.add_item(meta, secret, pin)
        self.destroy()
        self.app.home.refresh(select=lid)
        self.app.status(f"“{name}” saved.")


# ---------------------------------------------------------------- export / import / account
class ExportDialog(Dialog):
    def __init__(self, app):
        super().__init__(app, "Export")
        self.app = app
        b = self.body
        ttk.Label(b, text="Export your logins", style="Big.TLabel").pack(anchor="w")
        self.kind = tk.StringVar(value="backup")
        for val, title, desc in [
            ("backup", "Encrypted backup (recommended)",
             "A locked copy of your vault. Still needs your master password or recovery key to open."),
            ("csv", "Spreadsheet file (CSV), not encrypted",
             "For moving to another password manager. Anyone who gets this file can read every password. "
             "Entries with an extra PIN are left out."),
        ]:
            ttk.Radiobutton(b, text=title, value=val, variable=self.kind).pack(anchor="w", pady=(12, 0))
            ttk.Label(b, text=desc, style="CardMuted.TLabel", wraplength=px(420)).pack(anchor="w", padx=(22, 0))
        btns = ttk.Frame(b, style="Card.TFrame")
        btns.pack(fill="x", pady=(18, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Export…", style="Primary.TButton", command=self.go).pack(side="right", padx=6)

    def go(self):
        v = self.app.vault
        stamp = datetime.now().strftime("%Y-%m-%d")
        if self.kind.get() == "backup":
            f = filedialog.asksaveasfilename(parent=self, defaultextension=".safespace",
                                             initialfile=f"SafeSpace-backup-{stamp}.safespace",
                                             filetypes=[("SafeSpace backup", "*.safespace")])
            if f:
                v.export_backup(f)
                self.destroy()
                self.app.status("Encrypted backup saved.")
            return
        if not self.app.confirm_master(self, "Exporting unencrypted passwords. Enter your master password to continue."):
            return
        f = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                         initialfile=f"SafeSpace-export-{stamp}.csv", filetypes=[("CSV", "*.csv")])
        if not f:
            return
        with busy(self):
            done, skipped = v.export_csv(f)
        msg = f"Exported {done} logins."
        if skipped:
            msg += f" {skipped} with an extra PIN were left out."
        messagebox.showinfo(APP, msg + "\n\nThis file is NOT encrypted. Delete it once you've finished with it.",
                            parent=self)
        self.destroy()


def do_import(app):
    f = filedialog.askopenfilename(parent=app, title="Import logins from a CSV file",
                                   filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not f:
        return
    try:
        rows = read_import_csv(f)
    except (ValueError, UnicodeDecodeError, OSError) as e:
        messagebox.showerror(APP, f"Couldn't read that file.\n\n{e}", parent=app)
        return
    if not rows:
        messagebox.showinfo(APP, "No logins with passwords were found in that file.", parent=app)
        return
    existing = {(m["name"].lower(), m.get("username", "").lower()) for m in app.vault.items.values()}
    new = [r for r in rows if (r["name"].lower(), r["username"].lower()) not in existing]
    dupes = len(rows) - len(new)
    q = f"Found {len(rows)} logins in this file."
    if dupes:
        q += f"\n{dupes} already exist in SafeSpace and will be skipped."
    if not new:
        messagebox.showinfo(APP, q, parent=app)
        return
    if not messagebox.askyesno(APP, q + f"\n\nImport {len(new)} logins now?", parent=app):
        return
    with busy(app):
        for i, r in enumerate(new, 1):
            app.status(f"Importing {i} of {len(new)}…")
            app.update_idletasks()
            cat = next((c for c in CATEGORIES if c.lower() == r["category"].lower()), "Other")
            meta = {"name": r["name"], "url": r["url"], "username": r["username"], "category": cat,
                    "strength": passgen.strength(r["password"])[0], "fp": app.vault.fingerprint(r["password"])}
            app.vault.add_item(meta, {"password": r["password"], "notes": r["notes"]})
    app.home.refresh()
    app.status(f"Imported {len(new)} logins.")
    if messagebox.askyesno(APP, f"Imported {len(new)} logins.\n\nThe file you imported from is not encrypted. "
                                "Delete it now?", parent=app):
        try:
            os.remove(f)
            app.status(f"Imported {len(new)} logins and deleted the unencrypted file.")
        except OSError as e:
            messagebox.showerror(APP, f"Couldn't delete the file: {e}", parent=app)


class FaceEnrollDialog(Dialog):
    """Camera modal to capture reference face embeddings and set up Face ID."""

    def __init__(self, parent, vault):
        super().__init__(parent, "Enroll Face ID")
        self.vault = vault
        self.cap = None
        self._job = None
        self.samples = []
        self.needed = 5
        self.success = False

        b = self.body
        ttk.Label(b, text="Set up Face ID", style="H2.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(b, text="Look directly at the camera with good lighting. Hold still while SafeSpace captures your face profile.",
                  style="CardMuted.TLabel", wraplength=px(380)).pack(anchor="w", pady=(0, 10))

        self.canvas = tk.Canvas(b, width=360, height=270, bg="#1a1d24", highlightthickness=0)
        self.canvas.pack(pady=(0, 10))

        self.progress = ttk.Progressbar(b, maximum=self.needed, length=360)
        self.progress.pack(pady=(0, 8))

        self.status_lbl = ttk.Label(b, text="Starting camera...", style="Card.TLabel", font=(FONT, fs(10), "bold"))
        self.status_lbl.pack(anchor="center", pady=(0, 12))

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")

        self.bind("<Destroy>", self._cleanup)
        self.after(50, self._start_camera)

    def _start_camera(self):
        try:
            backend = face_auth.get_camera_backend()
            self.cap = cv2.VideoCapture(0, backend)
            if not self.cap or not self.cap.isOpened():
                self.cap = cv2.VideoCapture(0)
            if not self.cap or not self.cap.isOpened():
                self.status_lbl.configure(text="Could not open camera. Please check your webcam.", foreground=BAD_FG)
                return
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self._tick()
        except Exception as e:
            self._stop_camera()
            self.status_lbl.configure(text=f"Camera error: {e}", foreground=BAD_FG)

    def _tick(self):
        if not self.cap or not self.cap.isOpened():
            return
        ret, frame = self.cap.read()
        if not ret or frame is None:
            self._job = self.after(30, self._tick)
            return

        frame = cv2.flip(frame, 1)
        engine = face_auth.get_engine()
        res = engine.process_frame(frame)

        display_frame = frame.copy()
        if res["ok"]:
            bbox = res["bbox"]
            if res["pose"] != "CENTER":
                cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 180, 255), 2)
                self.status_lbl.configure(text="Please face directly forward at the camera.", foreground=WARN_FG)
            else:
                cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 220, 100), 2)
                self.samples.append(res["embedding"])
                self.progress.configure(value=len(self.samples))
                self.status_lbl.configure(
                    text=f"Face detected! Hold still... ({len(self.samples)}/{self.needed})",
                    foreground=GOOD_FG,
                )
                if len(self.samples) >= self.needed:
                    self._render(display_frame)
                    self._stop_camera()
                    self.after(300, self._finish_enrollment)
                    return
        else:
            if res.get("bbox"):
                bbox = res["bbox"]
                cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 180, 255), 2)
            self.status_lbl.configure(text=res["msg"], foreground=WARN_FG)

        self._render(display_frame)
        self._job = self.after(35, self._tick)

    def _render(self, display_frame):
        rgb = cv2.cvtColor(display_frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(rgb).resize((360, 270), Image.Resampling.BILINEAR)
        self._photo = ImageTk.PhotoImage(image=img)
        self.canvas.delete("all")
        self.canvas.create_image(180, 135, image=self._photo)

    def _finish_enrollment(self):
        avg_emb = np.mean(self.samples, axis=0)
        avg_emb /= np.linalg.norm(avg_emb)

        bio_key = secrets.token_bytes(32)
        with busy(self):
            self.vault.enable_biometric(bio_key)
            face_auth.save_biometric_profile(self.vault.path, bio_key, avg_emb)

        self.success = True
        messagebox.showinfo(APP, "Face ID enrolled successfully!\nYou can now use face recognition to unlock your vault.",
                            parent=self.master)
        self.destroy()

    def _stop_camera(self):
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
            self._job = None
        if self.cap:
            try:
                self.cap.release()
            except Exception:
                pass
            self.cap = None

    def _cleanup(self, event=None):
        if event is None or event.widget == self:
            self._stop_camera()

    def destroy(self):
        try:
            self._stop_camera()
        finally:
            super().destroy()


class FaceUnlockDialog(Dialog):
    """Camera modal to scan face, verify active liveness, and unlock vault."""

    STATE_IDENTIFY = 0   # Step 1: Matching face embedding with reference
    STATE_CHALLENGE = 1  # Step 2: Waiting for user to turn head left
    STATE_SUCCESS = 2    # Step 3: Verified, releasing key

    def __init__(self, app):
        super().__init__(app, "Unlock with Face ID")
        self.app = app
        self.vault = None
        self.cap = None
        self._job = None
        self.state = self.STATE_IDENTIFY
        self.attempts = 0
        self.max_attempts = 150
        self.challenge_start_frame = 0
        self.start_time = None
        self.failed_face_attempts = 0
        self.fallback_reason = ""

        profile = face_auth.load_biometric_profile(app.vault_path)
        if not profile:
            messagebox.showerror(APP, "Biometric profile is missing or damaged. Use master password.", parent=app)
            self.after(50, self.destroy)
            return

        self.bio_key, self.ref_emb = profile

        b = self.body
        ttk.Label(b, text="Face ID Unlock", style="H2.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(b, text="Look directly at the camera to begin.", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 10))

        self.canvas = tk.Canvas(b, width=360, height=270, bg="#1a1d24", highlightthickness=0)
        self.canvas.pack(pady=(0, 10))

        self.status_lbl = ttk.Label(b, text="Starting camera...", style="Card.TLabel", font=(FONT, fs(10), "bold"))
        self.status_lbl.pack(anchor="center", pady=(0, 12))

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Use Master Password", command=self._fallback_to_password).pack(side="right")

        self.bind("<Destroy>", self._cleanup)
        self.after(50, self._start_camera)

    def _fallback_to_password(self):
        self._stop_camera()
        self.destroy()

    def _start_camera(self):
        try:
            backend = face_auth.get_camera_backend()
            self.cap = cv2.VideoCapture(0, backend)
            if not self.cap or not self.cap.isOpened():
                self.cap = cv2.VideoCapture(0)
            if not self.cap or not self.cap.isOpened():
                self.status_lbl.configure(text="Webcam not detected. Use master password.", foreground=BAD_FG)
                self.fallback_reason = "Webcam not detected. Please use master password."
                self.after(1000, self._fallback_to_password)
                return
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self.start_time = time.time()
            self._tick()
        except Exception as e:
            self._stop_camera()
            self.status_lbl.configure(text=f"Camera error: {e}", foreground=BAD_FG)
            self.fallback_reason = f"Camera error: {e}"
            self.after(1000, self._fallback_to_password)

    def _tick(self):
        if not self.cap or not self.cap.isOpened():
            return

        # 10-second timeout enforcement (Hardware starvation & DoS prevention)
        if self.start_time and (time.time() - self.start_time) >= 10.0:
            self.status_lbl.configure(text="Face verification timed out (10s). Switching to password...", foreground=BAD_FG)
            self.fallback_reason = "Face verification timed out (10s limit). Please use master password."
            self._stop_camera()
            self.after(800, self._fallback_to_password)
            return

        try:
            ret, frame = self.cap.read()
        except Exception:
            self._stop_camera()
            self._fallback_to_password()
            return

        if not ret or frame is None:
            self._job = self.after(30, self._tick)
            return

        self.attempts += 1
        frame = cv2.flip(frame, 1)
        engine = face_auth.get_engine()
        res = engine.process_frame(frame)

        display_frame = frame.copy()
        h, w, _ = display_frame.shape

        if self.state == self.STATE_IDENTIFY:
            if res["ok"]:
                matched, sim = engine.verify(res["embedding"], self.ref_emb)
                bbox = res["bbox"]
                if matched:
                    if res["pose"] == "CENTER":
                        cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 220, 100), 2)
                        self.state = self.STATE_CHALLENGE
                        self.challenge_start_frame = self.attempts
                        self.status_lbl.configure(
                            text="👤 Face recognized! Now turn your head slightly LEFT ←",
                            foreground=PRIMARY,
                        )
                    else:
                        cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 180, 255), 2)
                        self.status_lbl.configure(text="Please face forward first...", foreground=WARN_FG)
                else:
                    self.failed_face_attempts += 1
                    cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 100, 255), 2)
                    if self.failed_face_attempts >= 3:
                        self.status_lbl.configure(
                            text="Face verification failed (3 attempts). Switching to password...",
                            foreground=BAD_FG,
                        )
                        self.fallback_reason = "Face not recognized after 3 attempts. Please enter master password."
                        self._render(display_frame)
                        self._stop_camera()
                        self.after(800, self._fallback_to_password)
                        return
                    else:
                        self.status_lbl.configure(
                            text=f"Face not recognized ({int(sim*100)}% match). Attempt {self.failed_face_attempts}/3",
                            foreground=BAD_FG,
                        )
            else:
                if res.get("bbox"):
                    bbox = res["bbox"]
                    cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 180, 255), 2)
                self.status_lbl.configure(text=res["msg"], foreground=WARN_FG)

        elif self.state == self.STATE_CHALLENGE:
            # Active liveness: draw guidance arrow and check 3D head yaw
            cv2.arrowedLine(display_frame, (int(w * 0.70), int(h * 0.16)), (int(w * 0.30), int(h * 0.16)), (0, 220, 255), 3, tipLength=0.3)
            cv2.putText(display_frame, "TURN HEAD LEFT", (int(w * 0.28), int(h * 0.11)), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 220, 255), 2)

            if res["ok"] and res.get("bbox"):
                bbox = res["bbox"]
                if res["pose"] == "LEFT":
                    # Liveness verified!
                    cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 220, 100), 3)
                    self.status_lbl.configure(text="✓ Liveness verified! Unlocking...", foreground=GOOD_FG)
                    self.state = self.STATE_SUCCESS
                    self._render(display_frame)
                    self._stop_camera()
                    self.after(300, self._unlock_vault)
                    return
                else:
                    cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 220, 255), 2)
                    self.status_lbl.configure(
                        text="Turn your head slightly LEFT ← to verify liveness",
                        foreground=PRIMARY,
                    )

            # If ~3.5 seconds elapse in challenge state without a genuine head turn
            if self.attempts - self.challenge_start_frame > 75:
                self.failed_face_attempts += 1
                if self.failed_face_attempts >= 3:
                    self.status_lbl.configure(
                        text="Liveness check failed (3 attempts). Switching to password...",
                        foreground=BAD_FG,
                    )
                    self.fallback_reason = "Liveness check failed. Please enter master password."
                    self._stop_camera()
                    self.after(800, self._fallback_to_password)
                    return
                else:
                    self.state = self.STATE_IDENTIFY
                    self.status_lbl.configure(
                        text=f"Liveness check incomplete ({self.failed_face_attempts}/3). Face forward...",
                        foreground=WARN_FG,
                    )

        self._render(display_frame)

        if self.attempts >= self.max_attempts:
            self.status_lbl.configure(text="Face verification timed out. Please enter master password.", foreground=BAD_FG)
            self.fallback_reason = "Face verification timed out. Please enter master password."
            self._stop_camera()
            self.after(800, self._fallback_to_password)
            return

        self._job = self.after(35, self._tick)

    def _render(self, display_frame):
        rgb = cv2.cvtColor(display_frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(rgb).resize((360, 270), Image.Resampling.BILINEAR)
        self._photo = ImageTk.PhotoImage(image=img)
        self.canvas.delete("all")
        self.canvas.create_image(180, 135, image=self._photo)

    def _unlock_vault(self):
        try:
            with busy(self.app):
                self.vault = Vault.unlock_with_biometric(self.app.vault_path, self.bio_key)
            self.destroy()
        except WrongMasterPassword:
            messagebox.showerror(APP, "Biometric authentication failed or vault file tampered.", parent=self.app)
            self.destroy()

    def _stop_camera(self):
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
            self._job = None
        if self.cap:
            try:
                self.cap.release()
            except Exception:
                pass
            self.cap = None

    def _cleanup(self, event=None):
        if event is None or event.widget == self:
            self._stop_camera()

    def destroy(self):
        try:
            self._stop_camera()
        finally:
            super().destroy()


class AccountDialog(Dialog):
    def __init__(self, app):
        super().__init__(app, "Account & security", scroll=True)
        self.app = app
        v = app.vault
        b = self.body
        ttk.Label(b, text="Account & security", style="Big.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")

        def section(r, title, text):
            tk.Frame(b, bg=LINE, height=1).grid(row=r, column=0, columnspan=2, sticky="we", pady=px(14))
            ttk.Label(b, text=title, font=(FONT, fs(12), "bold"), style="Card.TLabel").grid(row=r + 1, column=0, columnspan=2, sticky="w")
            if text:
                ttk.Label(b, text=text, style="CardMuted.TLabel", wraplength=px(480), justify="left").grid(
                    row=r + 2, column=0, columnspan=2, sticky="w", pady=(2, 6))

        section(1, "How your vault is protected",
                f"Your {len(v.items)} logins are stored only on this computer, encrypted "
                "(XChaCha20-Poly1305). Your master password is never saved; it is stretched with "
                "Argon2id to make guessing slow. Nothing is sent over the internet.\n"
                f"Vault file: {os.path.abspath(v.path)}")

        section(4, "Master password", "Change the password you use to open SafeSpace.")
        ttk.Button(b, text="Change master password…", command=self.change_master).grid(row=7, column=0, sticky="w")

        section(8, "If you lose access",
                "If you forget your master password, your recovery key is the only way back in. "
                "SafeSpace cannot reset it for you.\n"
                f"Current recovery key created: {fmt_date(v.recovery_created)}")
        rec_frame = ttk.Frame(b, style="Card.TFrame")
        rec_frame.grid(row=11, column=0, columnspan=2, sticky="w")
        ttk.Button(rec_frame, text="Create a new recovery key…", command=self.new_recovery).pack(side="left")
        if os.path.exists(v.path + ".bak"):
            ttk.Button(rec_frame, text="Restore from backup (.bak)…", command=self.restore_backup).pack(side="left", padx=8)

        section(12, "Settings", "")
        self.autolock = tk.StringVar(value=self._autolock_label(v.settings.get("autolock_min", 5)))
        r = ttk.Frame(b, style="Card.TFrame")
        r.grid(row=15, column=0, columnspan=2, sticky="w")
        ttk.Label(r, text="Lock SafeSpace after", style="Card.TLabel").pack(side="left")
        cb = ttk.Combobox(r, textvariable=self.autolock, state="readonly", width=16,
                          values=["1 minute", "5 minutes", "15 minutes", "30 minutes", "Never"])
        cb.pack(side="left", padx=6)
        ttk.Label(r, text="of inactivity", style="Card.TLabel").pack(side="left")
        cb.bind("<<ComboboxSelected>>", self.set_autolock)
        r2 = ttk.Frame(b, style="Card.TFrame")
        r2.grid(row=16, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(r2, text="Clear copied passwords after", style="Card.TLabel").pack(side="left")
        self.clip = tk.StringVar(value=f"{v.settings.get('clip_clear_s', 30)} seconds")
        cb2 = ttk.Combobox(r2, textvariable=self.clip, state="readonly", width=12,
                           values=["15 seconds", "30 seconds", "60 seconds", "120 seconds"])
        cb2.pack(side="left", padx=6)
        cb2.bind("<<ComboboxSelected>>",
                 lambda e: v.set_setting("clip_clear_s", int(self.clip.get().split()[0])))
        r3 = ttk.Frame(b, style="Card.TFrame")
        r3.grid(row=17, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(r3, text="Appearance", style="Card.TLabel").pack(side="left")
        self.theme = tk.StringVar(value=THEME_NAMES[THEME])
        cb3 = ttk.Combobox(r3, textvariable=self.theme, state="readonly", width=12,
                           values=list(THEME_NAMES.values()))
        cb3.pack(side="left", padx=6)
        cb3.bind("<<ComboboxSelected>>", self.set_theme)
        ttk.Label(r3, text="Text size", style="Card.TLabel").pack(side="left", padx=(12, 0))
        self.text_size = tk.StringVar(value=TEXT_SIZES[TEXT_SIZE][0])
        cb4 = ttk.Combobox(r3, textvariable=self.text_size, state="readonly", width=12,
                           values=[label for label, _ in TEXT_SIZES.values()])
        cb4.pack(side="left", padx=6)
        cb4.bind("<<ComboboxSelected>>", self.set_text_size)

        section(18, "Face ID (Biometric Unlock)",
                "Unlock your vault using facial recognition on this computer. "
                "SafeSpace never saves your image; only an encrypted mathematical template is stored with Windows DPAPI.")
        self.face_status_lbl = ttk.Label(b, text="", style="Card.TLabel")
        self.face_status_lbl.grid(row=21, column=0, columnspan=2, sticky="w", pady=(2, 6))
        self.face_btn_frame = ttk.Frame(b, style="Card.TFrame")
        self.face_btn_frame.grid(row=22, column=0, columnspan=2, sticky="w")
        self._refresh_face_section()

        section(23, "Delete account",
                "Permanently erases your vault from this computer. Make an encrypted backup (Export) first "
                "if you might need your passwords again. This cannot be undone.")
        ttk.Button(b, text="Delete account and all data…", style="Danger.TButton",
                   command=self.delete_account).grid(row=26, column=0, sticky="w")

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.grid(row=27, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Lock now", command=lambda: (self.destroy(), app.lock())).pack(side="right", padx=6)

    @staticmethod
    def _autolock_label(m):
        return "Never" if not m else f"{m} minute" + ("s" if m != 1 else "")

    def set_autolock(self, _e=None):
        t = self.autolock.get()
        self.app.vault.set_setting("autolock_min", 0 if t == "Never" else int(t.split()[0]))

    def set_theme(self, _e=None):
        name = next(k for k, label in THEME_NAMES.items() if label == self.theme.get())
        if name == THEME:
            return
        self.app.vault.set_setting("theme", name)
        self.destroy()                     # widgets keep their old colours, so rebuild the screen
        self.app.set_appearance(theme=name)

    def set_text_size(self, _e=None):
        name = next(k for k, (label, _) in TEXT_SIZES.items() if label == self.text_size.get())
        if name == TEXT_SIZE:
            return
        self.app.vault.set_setting("text_size", name)
        self.destroy()
        self.app.set_appearance(text_size=name)

    def change_master(self):
        if not self.app.confirm_master(self, "Enter your current master password."):
            return
        d = Dialog(self, "Change master password")
        form = NewMasterForm(d.body)
        form.pack()

        def go():
            pw = form.validate(d)
            if pw:
                with busy(d):
                    self.app.vault.change_master_password(pw)
                d.destroy()
                messagebox.showinfo(APP, "Master password changed. Use the new one next time you unlock.",
                                    parent=self)
        ttk.Button(d.body, text="Change password", style="Primary.TButton", command=go).pack(anchor="e", pady=(14, 0))
        form.focus()
        d.show()

    def new_recovery(self):
        if not messagebox.askyesno(APP, "Create a new recovery key?\n\nYour old recovery key will stop working.",
                                   parent=self):
            return
        if not self.app.confirm_master(self, "Enter your master password to create a new recovery key."):
            return
        key = self.app.vault.reset_recovery_key()
        show_recovery_key(self, key)
        self.destroy()

    def restore_backup(self):
        bak = self.app.vault.path + ".bak"
        if not os.path.exists(bak):
            messagebox.showinfo(APP, "No backup file found.", parent=self)
            return
        if not messagebox.askyesno(
            APP,
            "Restore vault from the last known good backup (.bak)?\n\nAny changes made since the last backup snapshot will be rolled back.",
            parent=self,
            icon="warning"
        ):
            return
        if not self.app.confirm_master(self, "Enter your master password to authorize restoring backup."):
            return
        try:
            with busy(self):
                Vault.restore_backup(self.app.vault.path)
            messagebox.showinfo(APP, "Vault restored from backup snapshot successfully. SafeSpace will now lock so you can log into the restored vault.", parent=self)
            self.destroy()
            self.app.lock()
        except Exception as e:
            messagebox.showerror(APP, f"Failed to restore backup: {e}", parent=self)

    def _refresh_face_section(self):
        for w in self.face_btn_frame.winfo_children():
            w.destroy()
        v = self.app.vault
        active = v.has_biometric and face_auth.has_biometric_profile(v.path)
        if active:
            self.face_status_lbl.configure(text="✓ Face ID is active for this vault on this computer.", foreground=GOOD_FG)
            ttk.Button(self.face_btn_frame, text="Re-enroll Face…", command=self.enroll_face).pack(side="left", padx=(0, 8))
            ttk.Button(self.face_btn_frame, text="Disable Face ID", style="Danger.TButton", command=self.disable_face).pack(side="left")
        else:
            self.face_status_lbl.configure(text="Face ID is not set up.", foreground=MUTED)
            ttk.Button(self.face_btn_frame, text="Set up Face ID…", style="Primary.TButton", command=self.enroll_face).pack(side="left")

    def enroll_face(self):
        if not self.app.confirm_master(self, "Enter your master password to configure Face ID."):
            return
        dlg = FaceEnrollDialog(self, self.app.vault)
        dlg.show()
        self._refresh_face_section()

    def disable_face(self):
        if not messagebox.askyesno(APP, "Disable Face ID for this vault?\n\nYou will need to use your master password to unlock.", parent=self):
            return
        if not self.app.confirm_master(self, "Enter your master password to disable Face ID."):
            return
        self.app.vault.disable_biometric()
        face_auth.delete_biometric_profile(self.app.vault.path)
        self._refresh_face_section()
        messagebox.showinfo(APP, "Face ID has been disabled.", parent=self)

    def delete_account(self):
        typed = simpledialog.askstring(APP, "This permanently deletes all your saved logins.\n\n"
                                            "Type DELETE to confirm:", parent=self)
        if typed != "DELETE":
            return
        if not self.app.confirm_master(self, "Enter your master password to delete your account."):
            return
        self.app.vault.delete_vault_file()
        self.app.vault = None
        self.destroy()
        messagebox.showinfo(APP, "Your SafeSpace account and vault were deleted.", parent=self.app)
        self.app.show(SetupScreen)


# ---------------------------------------------------------------- screens
class SetupScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        card = tk.Frame(self, bg=CARD, highlightbackground=LINE, highlightthickness=1, padx=px(36), pady=px(32))
        card.place(relx=0.5, rely=0.45, anchor="center")

        logo_row = tk.Frame(card, bg=CARD)
        logo_row.pack(anchor="w", pady=(0, px(4)))
        tk.Label(logo_row, text="🔒", font=(FONT, fs(20)), bg=CARD).pack(side="left", padx=(0, px(8)))
        tk.Label(logo_row, text="Welcome to SafeSpace", font=(FONT, fs(18), "bold"), bg=CARD, fg=TEXT).pack(side="left")

        ttk.Label(card, style="CardMuted.TLabel", wraplength=px(420), justify="left",
                  text="SafeSpace remembers your passwords in an encrypted vault on this computer. "
                       "You only need to remember one password: your master password.").pack(anchor="w", pady=(px(4), px(12)))

        box = tk.Frame(card, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(14), pady=px(10))
        box.pack(fill="x", pady=(0, px(12)))
        tk.Label(box, text="🛡️  How your passwords are protected", font=(FONT, fs(10), "bold"), bg=FIELD_RO, fg=TEXT).pack(anchor="w", pady=(0, px(4)))
        for line in PROTECTION_POINTS:
            tk.Label(box, text="•  " + line, font=(FONT, fs(9)), bg=FIELD_RO, fg=MUTED, wraplength=px(400),
                     justify="left").pack(anchor="w", pady=(px(2), 0))

        warn_pill = tk.Frame(card, bg=WARN_BG, highlightbackground=WARN_BORDER, highlightthickness=1, padx=px(10), pady=px(6))
        warn_pill.pack(fill="x", pady=(0, px(14)))
        tk.Label(warn_pill, text="⚠ " + NOTICE, font=(FONT, fs(9)), bg=WARN_BG, fg=WARN_FG, wraplength=px(400),
                 justify="left").pack(anchor="w")

        self.form = NewMasterForm(card)
        self.form.pack(anchor="w")
        ttk.Label(card, style="CardMuted.TLabel", wraplength=px(420),
                  text="Next you'll get a recovery key in case you ever forget it.").pack(anchor="w", pady=(px(12), 0))
        ttk.Button(card, text="Create my vault", style="Primary.TButton", command=self.create).pack(anchor="e",
                                                                                                    pady=(px(16), 0))
        app.bind("<Return>", lambda e: self.create())
        self.form.focus()

    def create(self):
        pw = self.form.validate(self.app)
        if not pw:
            return
        with busy(self):
            vault, key = Vault.create(self.app.vault_path, pw)
        self.app.unbind("<Return>")
        self.app.vault = vault
        show_recovery_key(self.app, key)
        self.app.show(HomeScreen)


class UnlockScreen(ttk.Frame):
    def __init__(self, app, message=""):
        super().__init__(app)
        self.app = app
        card = tk.Frame(self, bg=CARD, highlightbackground=LINE, highlightthickness=1, padx=px(36), pady=px(32))
        card.place(relx=0.5, rely=0.42, anchor="center")

        logo_row = tk.Frame(card, bg=CARD)
        logo_row.pack(anchor="w", pady=(0, px(2)))
        tk.Label(logo_row, text="🔒", font=(FONT, fs(22)), bg=CARD).pack(side="left", padx=(0, px(8)))
        tk.Label(logo_row, text="SafeSpace", font=(FONT, fs(20), "bold"), bg=CARD, fg=TEXT).pack(side="left")

        ttk.Label(card, text="Unlock your vault to view passwords.", style="CardMuted.TLabel").pack(anchor="w",
                                                                                               pady=(px(2), px(16)))
        if message:
            ttk.Label(card, text=message, style="CardMuted.TLabel").pack(anchor="w", pady=(0, px(10)))

        self.can_face = Vault.is_biometric_enabled(self.app.vault_path) and face_auth.has_biometric_profile(self.app.vault_path)
        if self.can_face:
            ttk.Button(card, text="👤  Unlock with Face ID", style="Primary.TButton",
                       command=self.unlock_face).pack(fill="x", pady=(0, px(12)))
            sep_row = tk.Frame(card, bg=CARD)
            sep_row.pack(fill="x", pady=(0, px(12)))
            tk.Frame(sep_row, bg=LINE, height=1).pack(side="left", fill="x", expand=True)
            tk.Label(sep_row, text="  or enter master password  ", font=(FONT, fs(9)), bg=CARD, fg=MUTED).pack(side="left")
            tk.Frame(sep_row, bg=LINE, height=1).pack(side="left", fill="x", expand=True)

        self.pw = tk.StringVar()
        field = PasswordField(card, self.pw, width=30)
        field.pack(fill="x")
        self.err = ttk.Label(card, text="", style="Card.TLabel", foreground=BAD_FG)
        self.err.pack(anchor="w", pady=(px(4), 0))
        btn_style = "TButton" if self.can_face else "Primary.TButton"
        self._unlocking = False
        self.unlock_btn = ttk.Button(card, text="Unlock with Password", style=btn_style, command=self.unlock)
        self.unlock_btn.pack(fill="x", pady=(px(10), 0))
        ttk.Button(card, text="Forgot your master password?", style="Link.TButton",
                   command=self.recover).pack(anchor="w", pady=(px(14), 0))
        if app.demo_hint:
            hint_box = tk.Frame(card, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(10), pady=px(6))
            hint_box.pack(fill="x", pady=(px(14), 0))
            tk.Label(hint_box, text="💡 " + app.demo_hint, font=(FONT, fs(9)), bg=FIELD_RO, fg=MUTED, wraplength=px(320), justify="left").pack(anchor="w")
        app.bind("<Return>", lambda e: self.unlock())
        field.entry.focus_set()

        if time.time() < _cooldown_until:
            self._start_cooldown_timer(int(math.ceil(_cooldown_until - time.time())))

    def unlock_face(self):
        self.err.configure(text="")
        dlg = FaceUnlockDialog(self.app)
        dlg.show()
        if dlg.vault:
            self.app.unbind("<Return>")
            self.app.vault = dlg.vault
            self.app.show(HomeScreen)
        elif dlg.fallback_reason:
            self.err.configure(text=dlg.fallback_reason)

    def _start_cooldown_timer(self, delay):
        if hasattr(self, "unlock_btn") and self.unlock_btn.winfo_exists():
            self.unlock_btn.configure(state="disabled")
        self._tick_cooldown()

    def _tick_cooldown(self):
        now = time.time()
        if now < _cooldown_until:
            secs = int(math.ceil(_cooldown_until - now))
            self.err.configure(
                text=f"Too many failed attempts. Rate limited for security.\nPlease wait {secs} second{'s' if secs != 1 else ''} before trying again."
            )
            self.after(1000, self._tick_cooldown)
        else:
            self.err.configure(text="Cooldown expired. You may enter your master password.")
            if hasattr(self, "unlock_btn") and self.unlock_btn.winfo_exists():
                self.unlock_btn.configure(state="normal")

    def unlock(self):
        global _failed_attempts, _cooldown_until
        now = time.time()
        if now < _cooldown_until:
            secs = int(math.ceil(_cooldown_until - now))
            self.err.configure(text=f"Too many failed attempts. Please wait {secs}s before trying again.")
            return

        if self._unlocking:
            return
        self._unlocking = True
        self.unlock_btn.configure(state="disabled")
        self.update_idletasks()

        try:
            with busy(self):
                vault = Vault.unlock(self.app.vault_path, self.pw.get())
            # Successful authentication resets failed attempts counter
            _failed_attempts = 0
            _cooldown_until = 0.0
            self.app.unbind("<Return>")
            self.app.vault = vault
            self.app.show(HomeScreen)
            return
        except WrongMasterPassword:
            _failed_attempts += 1
            self.pw.set("")
            delay = 0
            if _failed_attempts == 4:
                delay = 5
            elif _failed_attempts == 5:
                delay = 15
            elif _failed_attempts >= 6:
                delay = 60

            if delay > 0:
                _cooldown_until = time.time() + delay
                self._start_cooldown_timer(delay)
            else:
                self.err.configure(
                    text=f"That master password didn't work. Check Caps Lock and try again. ({_failed_attempts}/3 attempts before delay)"
                )
        except (json.JSONDecodeError, ValueError) as e:
            bak_path = self.app.vault_path + ".bak"
            if os.path.exists(bak_path):
                if messagebox.askyesno(
                    APP,
                    f"Vault file appears to be corrupted or invalid:\n{e}\n\nA backup copy (.bak) exists. Would you like to restore from the backup snapshot?",
                    parent=self.app,
                    icon="warning"
                ):
                    try:
                        shutil.copy2(bak_path, self.app.vault_path)
                        messagebox.showinfo(APP, "Vault restored from backup snapshot. Please enter your master password.", parent=self.app)
                        self.err.configure(text="Vault restored from backup snapshot.")
                        return
                    except Exception as restore_err:
                        messagebox.showerror(APP, f"Failed to restore backup: {restore_err}", parent=self.app)
                        return
            self.err.configure(text=str(e))
        finally:
            self._unlocking = False
            if time.time() >= _cooldown_until and hasattr(self, "unlock_btn") and self.unlock_btn.winfo_exists():
                self.unlock_btn.configure(state="normal")

    def recover(self):
        key = simpledialog.askstring("Recover access",
                                     "Enter the recovery key you saved when you created SafeSpace\n"
                                     "(e.g. ABCD-EFGH-...):", parent=self.app)
        if not key:
            return
        try:
            with busy(self):
                vault = Vault.unlock_with_recovery(self.app.vault_path, key)
        except WrongMasterPassword:
            messagebox.showerror(APP, "That recovery key didn't work.", parent=self.app)
            return
        d = Dialog(self.app, "Choose a new master password")
        ttk.Label(d.body, text="Recovery key accepted. Choose a new master password.",
                  style="H2.TLabel").pack(anchor="w", pady=(0, 10))
        form = NewMasterForm(d.body)
        form.pack()
        done = {}

        def go():
            pw = form.validate(d)
            if pw:
                with busy(d):
                    vault.change_master_password(pw)
                done["ok"] = True
                d.destroy()
        ttk.Button(d.body, text="Save new password", style="Primary.TButton", command=go).pack(anchor="e",
                                                                                                pady=(14, 0))
        form.focus()
        d.show()
        if not done:
            vault.lock()
            return
        # The old recovery key has been used; issue a fresh one.
        show_recovery_key(self.app, vault.reset_recovery_key())
        self.app.unbind("<Return>")
        self.app.vault = vault
        self.app.show(HomeScreen)


class HomeScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        app.home = self
        self.filter = ALL
        self.selected = None
        self.revealed = None           # (lid, secret, pin) for the selected entry only
        self.collapsed = set()         # website groups the user has folded up
        self._tree_avatars = {}
        self._detail_avatar = None

        self._banner_dismissed = False

        # Top Header Bar with clean border and action pills
        self.hdr_wrap = tk.Frame(self, bg=CARD)
        self.hdr_wrap.pack(fill="x")
        hdr = tk.Frame(self.hdr_wrap, bg=CARD, padx=px(20), pady=px(10))
        hdr.pack(fill="x")

        # Logo with modern mode badge
        logo_box = tk.Frame(hdr, bg=CARD)
        logo_box.pack(side="left")
        tk.Label(logo_box, text="🔒", font=(FONT, fs(14)), bg=CARD).pack(side="left", padx=(0, px(6)))
        tk.Label(logo_box, text="SafeSpace", font=(FONT, fs(15), "bold"), bg=CARD, fg=TEXT).pack(side="left")

        # Mode Badge (Demo or Active)
        b_text = "DEMO VAULT" if self.app.demo_hint else "ACTIVE VAULT"
        b_bg = PRIMARY_LIGHT if self.app.demo_hint else "#f0fdf4"
        b_fg = PRIMARY if self.app.demo_hint else "#16a34a"
        b_border = PRIMARY_OFF if self.app.demo_hint else "#bbf7d0"
        badge = tk.Frame(logo_box, bg=b_bg, highlightbackground=b_border, highlightthickness=1, padx=px(8), pady=px(2))
        badge.pack(side="left", padx=(px(12), 0))
        tk.Label(badge, text=b_text, font=(FONT, fs(8), "bold"), bg=b_bg, fg=b_fg).pack()

        # Top Action Buttons
        ttk.Button(hdr, text="⚙ Account", command=lambda: AccountDialog(app).show()).pack(side="right")
        ttk.Button(hdr, text="Export", command=lambda: ExportDialog(app).show()).pack(side="right", padx=(px(4), px(2)))
        ttk.Button(hdr, text="Import", command=lambda: do_import(app)).pack(side="right", padx=px(2))
        ttk.Button(hdr, text="PassGen", command=lambda: PassGenDialog(app, app).show()).pack(side="right", padx=(px(4), px(2)))
        ttk.Button(hdr, text="+ Add New Item", style="Primary.TButton",
                   command=lambda: EntryDialog(app).show()).pack(side="right", padx=(0, px(4)))

        # 1px border under header
        self.sep = tk.Frame(self.hdr_wrap, bg=LINE, height=1)
        self.sep.pack(fill="x")

        # Warning banner (Curved banner, packed only when needed)
        self.banner = RoundedCard(self, bg_color=WARN_BG, border_color=WARN_BORDER, radius=10, height=px(44))
        b_in = self.banner.inner
        b_in.configure(bg=WARN_BG)
        tk.Label(b_in, text="⚠️", font=(FONT, fs(10)), bg=WARN_BG).pack(side="left", padx=(px(10), px(4)))
        self.banner_text = tk.Label(b_in, font=(FONT, fs(9), "bold"), bg=WARN_BG, fg=WARN_FG)
        self.banner_text.pack(side="left")

        # Right actions: Review them button and close button (✕)
        close_btn = tk.Label(b_in, text="✕", font=(FONT, fs(10), "bold"), bg=WARN_BG, fg=WARN_FG, cursor="hand2", padx=px(6), pady=px(2))
        close_btn.pack(side="right", padx=(px(4), px(10)))
        close_btn.bind("<Button-1>", lambda e: self.dismiss_banner())
        close_btn.bind("<Enter>", lambda e: close_btn.configure(fg=TEXT))
        close_btn.bind("<Leave>", lambda e: close_btn.configure(fg=WARN_FG))

        ttk.Button(b_in, text="Review them →", command=lambda: self.set_filter(ATTENTION),
                   style="Small.TButton").pack(side="right", padx=(0, px(6)))

        # Main Body Frame
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=px(16), pady=px(10))
        self.body = body

        # Left Sidebar (Nav + Tools + Settings)
        side = tk.Frame(body, bg=BG, width=px(220))
        side.pack(side="left", fill="y", padx=(0, px(16)))
        side.pack_propagate(False)

        # 1. VAULT ITEMS
        tk.Label(side, text="VAULT ITEMS", font=(FONT, fs(10), "bold"), bg=BG, fg="#334155" if THEME == "light" else "#cbd5e1").pack(anchor="w", padx=px(10), pady=(px(4), px(8)))
        self.cats = CurvedNavList(side, bg=BG, active_bg="#0f172a" if THEME == "light" else "#334155")
        self.cats.pack(fill="x")
        self.cats.bind("<<ListboxSelect>>", self._on_cat)

        # 2. TOOLS AND SAFETY
        tk.Label(side, text="TOOLS AND SAFETY", font=(FONT, fs(10), "bold"), bg=BG, fg="#334155" if THEME == "light" else "#cbd5e1").pack(anchor="w", padx=px(10), pady=(px(18), px(8)))
        CurvedNavRow(side, icon="🔑", name="Password Generator", hover_bg=HOVER, text_fg=TEXT,
                     on_click=lambda: PassGenDialog(self.app, self.app).show()).pack(fill="x", pady=px(2))
        CurvedNavRow(side, icon="🛡️", name="Security Audit", hover_bg=HOVER, text_fg=TEXT,
                     on_click=lambda: self.set_filter(ATTENTION)).pack(fill="x", pady=px(2))
        CurvedNavRow(side, icon="🔒", name="Lock Vault", hover_bg=HOVER, text_fg=TEXT,
                     on_click=self.app.lock).pack(fill="x", pady=px(2))

        # 3. SETTINGS
        tk.Label(side, text="SETTINGS", font=(FONT, fs(10), "bold"), bg=BG, fg="#334155" if THEME == "light" else "#cbd5e1").pack(anchor="w", padx=px(10), pady=(px(18), px(8)))
        CurvedNavRow(side, icon="⚙️", name="Account & Settings", hover_bg=HOVER, text_fg=TEXT,
                     on_click=lambda: AccountDialog(self.app).show()).pack(fill="x", pady=px(2))

        # Right Main Content Area
        main_area = tk.Frame(body, bg=BG)
        main_area.pack(side="left", fill="both", expand=True)

        # Greeting Banner Row
        greet_row = tk.Frame(main_area, bg=BG)
        greet_row.pack(fill="x", pady=(0, px(8)))
        greet_left = tk.Frame(greet_row, bg=BG)
        greet_left.pack(side="left")
        tk.Label(greet_left, text="DASHBOARD", font=(FONT, fs(10), "bold"), bg=BG, fg="#334155" if THEME == "light" else "#cbd5e1").pack(anchor="w")
        tk.Label(greet_left, text="Good morning, Vault Master", font=(FONT, fs(16), "bold"), bg=BG, fg=TEXT).pack(anchor="w")

        greet_right = tk.Frame(greet_row, bg=BG)
        greet_right.pack(side="right", anchor="e")
        self.stats_pill = tk.Label(greet_right, font=(FONT, fs(8), "bold"), bg=CARD, fg=MUTED,
                                   highlightbackground=LINE, highlightthickness=1, padx=px(10), pady=px(3))
        self.stats_pill.pack(side="right")

        # Curved Search & Filter Banner (spacious, modern, prominent bar)
        self.scard = RoundedCard(main_area, radius=14, height=px(58))
        self.scard.pack(fill="x", pady=(0, px(12)))
        self.scard.pack_propagate(False)

        # Search Entry on Left (bigger padding and text)
        sbox = tk.Frame(self.scard.inner, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(14), pady=px(6))
        sbox.pack(side="left", fill="x", expand=True, padx=(px(10), px(14)), pady=px(7))
        tk.Label(sbox, text="🔍", font=(FONT, fs(12)), bg=FIELD_RO, fg=MUTED).pack(side="left")
        self.q = tk.StringVar()
        self.search = tk.Entry(sbox, textvariable=self.q, font=(FONT, fs(11)), bg=FIELD_RO, fg=TEXT,
                               relief="flat", borderwidth=0, insertbackground=PRIMARY)
        self.search.pack(side="left", fill="x", expand=True, padx=(px(8), 0))
        self._placeholder()

        # Horizontal Category Filter Pills on Right
        self.pills_container = tk.Frame(self.scard.inner, bg=CARD)
        self.pills_container.pack(side="right", padx=(0, px(10)), pady=px(7))

        # Main Items Area (Table Card + Detail Card)
        content_row = tk.Frame(main_area, bg=BG)
        content_row.pack(fill="both", expand=True)

        # Center Table Card
        table_card = RoundedCard(content_row, radius=12)
        table_card.pack(side="left", fill="both", expand=True, padx=(0, px(10)))

        tbl_hdr = tk.Frame(table_card.inner, bg=CARD)
        tbl_hdr.pack(fill="x", padx=px(12), pady=(px(8), px(6)))
        self.list_title = tk.Label(tbl_hdr, font=(FONT, fs(10), "bold"), bg=CARD, fg=TEXT)
        self.list_title.pack(side="left")

        tk.Frame(table_card.inner, bg=LINE, height=1).pack(fill="x")

        tree_box = tk.Frame(table_card.inner, bg=CARD)
        tree_box.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(tree_box, columns=("user", "site", "strength"), selectmode="browse")
        for col, text, w in [("#0", "ITEM & TITLE", 180), ("user", "USERNAME / IDENTIFIER", 170),
                             ("site", "WEBSITE", 130), ("strength", "PASSWORD", 110)]:
            self.tree.heading(col, text=text, anchor="w")
            self.tree.column(col, width=px(w), minwidth=px(60), anchor="w", stretch=col != "strength")

        # High contrast alternating row styling and crisp black text
        row_even_bg = "#ffffff" if THEME == "light" else "#1e293b"
        row_odd_bg = "#edf2f7" if THEME == "light" else "#0b1220"  # Noticeable contrast row separation
        self.tree.tag_configure("row_even", background=row_even_bg, foreground=TEXT)
        self.tree.tag_configure("row_odd", background=row_odd_bg, foreground=TEXT)
        self.tree.tag_configure("group", foreground=TEXT, font=(FONT, fs(9), "bold"),
                                background="#e2e8f0" if THEME == "light" else "#0f172a")

        sb = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<<TreeviewOpen>>", lambda e: self.collapsed.discard(self.tree.focus()))
        self.tree.bind("<<TreeviewClose>>", lambda e: self.collapsed.add(self.tree.focus()))
        self.tree.bind("<Double-1>", lambda e: self.edit())
        self.tree.bind("<Button-3>", self._context)
        self.empty = ttk.Label(tree_box, style="CardMuted.TLabel", justify="center", font=(FONT, fs(11)))

        # Right Detail Card
        self.detail_card = RoundedCard(content_row, radius=12, width=px(330))
        self.detail_card.pack(side="right", fill="y")
        self.detail_card.pack_propagate(False)
        self.detail = self.detail_card.inner

        # Bottom Feature Cards Row
        bot_row = tk.Frame(main_area, bg=BG, height=px(86))
        bot_row.pack(fill="x", pady=(px(10), 0))
        bot_row.pack_propagate(False)

        # 1. Quick Password Generator Card
        self.pwgen_card = RoundedCard(bot_row, radius=12)
        self.pwgen_card.pack(side="left", fill="both", expand=True, padx=(0, px(10)))
        p_in = self.pwgen_card.inner

        p_top = tk.Frame(p_in, bg=CARD)
        p_top.pack(fill="x", padx=px(10), pady=(px(6), px(2)))
        tk.Label(p_top, text="🔑", font=(FONT, fs(11)), bg=CARD).pack(side="left", padx=(0, px(4)))
        tk.Label(p_top, text="Password Generator", font=(FONT, fs(9), "bold"), bg=CARD, fg=TEXT).pack(side="left")
        tk.Label(p_top, text="— Random credentials in 1 click",
                 font=(FONT, fs(8)), bg=CARD, fg=MUTED).pack(side="left", padx=(px(6), 0))

        p_row = tk.Frame(p_in, bg=CARD)
        p_row.pack(fill="x", padx=px(10), pady=(px(2), px(6)))

        self._quick_pw = tk.StringVar(value=passgen.generate_password(16))
        pw_box = tk.Frame(p_row, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(8), pady=px(3))
        pw_box.pack(side="left", fill="x", expand=True)
        self.quick_pw_entry = tk.Entry(pw_box, textvariable=self._quick_pw, font=("Consolas", fs(9), "bold"),
                                       bg=FIELD_RO, fg=PRIMARY, relief="flat", borderwidth=0, state="readonly")
        self.quick_pw_entry.pack(side="left", fill="x", expand=True)

        ttk.Button(p_row, text="Copy", command=self._copy_quick_pw, style="Small.TButton").pack(side="left", padx=(px(6), 0))
        ttk.Button(p_row, text="↻ New", command=self._new_quick_pw, style="Small.TButton").pack(side="left", padx=(px(4), 0))
        ttk.Button(p_row, text="+ New Login", command=self._create_with_quick_pw, style="Small.TButton").pack(side="left", padx=(px(4), 0))

        # 2. Vault Health Score Card
        self.health_card = RoundedCard(bot_row, radius=12)
        self.health_card.pack(side="right", fill="both", expand=True)
        h_in = self.health_card.inner

        h_top = tk.Frame(h_in, bg=CARD)
        h_top.pack(fill="x", padx=px(10), pady=(px(6), px(2)))
        tk.Label(h_top, text="🛡️", font=(FONT, fs(11)), bg=CARD).pack(side="left", padx=(0, px(4)))
        tk.Label(h_top, text="Vault Health Score", font=(FONT, fs(9), "bold"), bg=CARD, fg=TEXT).pack(side="left")
        self.health_score_badge = tk.Label(h_top, font=(FONT, fs(8), "bold"), bg=CARD)
        self.health_score_badge.pack(side="right")

        h_row = tk.Frame(h_in, bg=CARD)
        h_row.pack(fill="x", padx=px(10), pady=(px(2), px(6)))
        self.health_desc = tk.Label(h_row, font=(FONT, fs(8)), bg=CARD, fg=MUTED)
        self.health_desc.pack(side="left")

        self.health_btn = ttk.Button(h_row, text="Review weak passwords →",
                                     command=lambda: self.set_filter(ATTENTION), style="Small.TButton")
        self.health_btn.pack(side="right")

        self.q.trace_add("write", lambda *a: self.refresh())
        self.refresh()

    def _copy_quick_pw(self):
        pw = self._quick_pw.get()
        if pw:
            self.app.copy(pw, "Generated password")

    def _new_quick_pw(self):
        self._quick_pw.set(passgen.generate_password(16))

    def _create_with_quick_pw(self):
        EntryDialog(self.app, preset_password=self._quick_pw.get()).show()

    # ---- search placeholder
    def _placeholder(self):
        ph = "Filter by name, username, or URL..."
        self.search.insert(0, ph)
        self.search.configure(fg=MUTED)
        self._ph_on = True

        def fin(_):
            if getattr(self, "_ph_on", False):
                self._ph_on = False
                self.search.delete(0, "end")
                self.search.configure(fg=TEXT)

        def fout(_):
            if not self.search.get():
                self._ph_on = True
                self.search.insert(0, ph)
                self.search.configure(fg=MUTED)
        self.search.bind("<FocusIn>", fin)
        self.search.bind("<FocusOut>", fout)

    def query(self) -> str:
        return "" if getattr(self, "_ph_on", False) else self.q.get().strip().lower()

    def dismiss_banner(self):
        self._banner_dismissed = True
        self.banner.pack_forget()

    # ---- data
    def attention_ids(self) -> set:
        v = self.app.vault
        return {lid for lid, m in v.items.items() if passgen.is_weak(m.get("strength", 4))}

    def set_filter(self, f):
        self.filter = f
        self.refresh()

    def _on_cat(self, _e):
        sel = self.cats.curselection()
        if sel:
            self.filter = self._cat_keys[sel[0]]
            self.refresh(keep_cat=True)

    def refresh(self, select=None, keep_cat=False):
        v = self.app.vault
        if v is None:
            return
        attention = self.attention_ids()

        # Warning banner
        if attention and not self._banner_dismissed:
            n = len(attention)
            self.banner_text.configure(
                text=f"{n} of your saved passwords {'are' if n != 1 else 'is'} weak. Review and update them to keep accounts secure.")
            self.banner.pack(fill="x", padx=px(16), pady=(px(8), 0), after=self.hdr_wrap)
        else:
            self.banner.pack_forget()
            if self.filter == ATTENTION and not attention:
                self.filter = ALL

        # Stats pill in greeting row
        total = len(v.items)
        weak_n = len(attention)
        self.stats_pill.configure(text=f"{total} items in vault · {weak_n} need attention")

        # Sidebar category counts
        counts = {c: 0 for c in CATEGORIES}
        for m in v.items.values():
            counts[m.get("category", "Other")] = counts.get(m.get("category", "Other"), 0) + 1
        self._cat_keys = [ALL] + ([ATTENTION] if attention else []) + [c for c in CATEGORIES if counts.get(c)]
        if self.filter not in self._cat_keys:
            self.filter = ALL
        if not keep_cat:
            self.cats.delete(0, "end")
            for k in self._cat_keys:
                n = len(v.items) if k == ALL else len(attention) if k == ATTENTION else counts[k]
                icon = "⚠️" if k == ATTENTION else ""
                self.cats.insert("end", f"{icon} {k} ({n})")
            if self.filter in self._cat_keys:
                self.cats.selection_set(self._cat_keys.index(self.filter))

        # Horizontal Filter Pills in search card
        for w in self.pills_container.winfo_children():
            w.destroy()

        active_pill_bg = "#0f172a" if THEME == "light" else "#334155"

        p_all = PillButton(self.pills_container, f"All ({total})",
                           command=lambda: self.set_filter(ALL),
                           is_active=(self.filter == ALL),
                           active_bg=active_pill_bg,
                           font=(FONT, fs(10), "bold"),
                           padx=px(14), pady=px(6))
        p_all.pack(side="left", padx=px(3))

        if attention:
            p_att = PillButton(self.pills_container, f"Needs attention ({weak_n})",
                               command=lambda: self.set_filter(ATTENTION),
                               is_active=(self.filter == ATTENTION),
                               active_bg=BAD_FG,
                               inactive_fg=WARN_FG,
                               font=(FONT, fs(10), "bold"),
                               padx=px(14), pady=px(6))
            p_att.pack(side="left", padx=px(3))

        shown_cats = [c for c in CATEGORIES if counts.get(c)][:4]
        for c in shown_cats:
            p_c = PillButton(self.pills_container, f"{c} ({counts[c]})",
                             command=lambda cat=c: self.set_filter(cat),
                             is_active=(self.filter == c),
                             active_bg=active_pill_bg,
                             font=(FONT, fs(10), "bold"),
                             padx=px(14), pady=px(6))
            p_c.pack(side="left", padx=px(3))

        # Bottom Feature Card: Vault Health Score
        if total == 0:
            pct = 100
        else:
            pct = max(0, int(((total - weak_n) / total) * 100))

        if pct >= 90:
            self.health_score_badge.configure(text=f"{pct}%  Optimal", fg="#059669")
            self.health_desc.configure(text="All passwords meet high security standards.")
            self.health_btn.configure(text="Run security check →")
        else:
            self.health_score_badge.configure(text=f"{pct}%  Needs Attention", fg=BAD_FG)
            self.health_desc.configure(text=f"{weak_n} weak password{'s' if weak_n != 1 else ''} detected. Keep accounts secure.")
            self.health_btn.configure(text="Review weak passwords →")

        # List rows
        q = self.query()
        rows = []
        for lid, m in v.items.items():
            if self.filter == ATTENTION and lid not in attention:
                continue
            if self.filter not in (ALL, ATTENTION) and m.get("category") != self.filter:
                continue
            hay = " ".join([m["name"], m.get("url", ""), m.get("username", ""), m.get("category", "")]).lower()
            if q and q not in hay:
                continue
            rows.append((lid, m))
        rows.sort(key=lambda r: r[1]["name"].lower())

        self.tree.delete(*self.tree.get_children())
        self._tree_avatars = {}

        sites = {lid: site_key(m.get("url", "")) for lid, m in rows}
        per_site = {}
        for s in sites.values():
            if s:
                per_site[s] = per_site.get(s, 0) + 1

        for idx, (lid, m) in enumerate(rows):
            parent = ""
            s = sites[lid]
            if per_site.get(s, 0) > 1:
                parent = "grp:" + s
                if not self.tree.exists(parent):
                    grp_av = get_service_avatar(s, size=20, radius=5)
                    self._tree_avatars[parent] = grp_av
                    self.tree.insert("", "end", iid=parent, text=f"  🌐  {s}", image=grp_av,
                                     values=(f"{per_site[s]} logins", "", ""),
                                     open=parent not in self.collapsed, tags=("group",))
            score = m.get("strength", 4)
            if passgen.is_weak(score):
                st = "⚠️ " + passgen.LABELS[score]
            elif score >= 4:
                st = "✓ " + passgen.LABELS[score]
            else:
                st = passgen.LABELS[score]
            name = m["name"] + ("  🔑" if m.get("has_pin") else "")
            av = get_service_avatar(m["name"], size=20, radius=5)
            self._tree_avatars[lid] = av
            row_stripe = "row_even" if idx % 2 == 0 else "row_odd"
            self.tree.insert(parent, "end", iid=lid, text="  " + name, image=av,
                             values=(m.get("username", ""), m.get("url", ""), st),
                             tags=(row_stripe,))

        self.list_title.configure(text=f"{self.filter}  ·  {len(rows)} shown")

        if not v.items:
            self.empty.configure(text="No logins saved yet.\n\nClick “+ Add New Item” to save your first one,\n"
                                      "or Import them from another app.")
            self.empty.place(relx=0.5, rely=0.4, anchor="center")
        elif not rows:
            self.empty.configure(text="Nothing matches your search.")
            self.empty.place(relx=0.5, rely=0.4, anchor="center")
        else:
            self.empty.place_forget()

        target = select or self.selected
        if target and self.tree.exists(target):
            self.collapsed.discard(self.tree.parent(target))
            self.tree.selection_set(target)
            self.tree.see(target)
        else:
            self.selected = None
            self.revealed = None
            self.show_detail()

    # ---- selection & detail
    def _on_select(self, _e=None):
        sel = self.tree.selection()
        lid = sel[0] if sel else None
        if lid not in self.app.vault.items:          # a website group row, not a login
            lid = None
        if lid != self.selected:
            self.revealed = None
        self.selected = lid
        self.show_detail()

    def show_detail(self):
        d = self.detail
        for w in d.winfo_children():
            w.destroy()
        v = self.app.vault
        if not self.selected or self.selected not in v.items:
            empty_frame = tk.Frame(d, bg=CARD, padx=px(16), pady=px(36))
            empty_frame.pack(fill="both", expand=True)
            tk.Label(empty_frame, text="🔑", font=(FONT, fs(26)), bg=CARD).pack(pady=(0, px(10)))
            tk.Label(empty_frame, text="Select an item", font=(FONT, fs(12), "bold"), bg=CARD, fg=TEXT).pack()
            tk.Label(empty_frame, text="Click a login from the list to view its credentials, copy passwords, or edit details.",
                     font=(FONT, fs(9)), bg=CARD, fg=MUTED, wraplength=px(240), justify="center").pack(pady=(px(6), 0))
            return

        lid, m = self.selected, v.items[self.selected]
        sec = self.revealed[1] if self.revealed and self.revealed[0] == lid else None

        pad_wrap = tk.Frame(d, bg=CARD, padx=px(14), pady=px(12))
        pad_wrap.pack(fill="both", expand=True)

        # Header: Avatar + Title + Edit & Menu buttons
        top = tk.Frame(pad_wrap, bg=CARD)
        top.pack(fill="x")

        avatar = get_service_avatar(m["name"], size=36, radius=8)
        self._detail_avatar = avatar
        tk.Label(top, image=avatar, bg=CARD).pack(side="left", padx=(0, px(8)))

        info_box = tk.Frame(top, bg=CARD)
        info_box.pack(side="left", fill="x", expand=True)
        tk.Label(info_box, text=m["name"], font=(FONT, fs(12), "bold"), bg=CARD, fg=TEXT,
                 wraplength=px(150), justify="left").pack(anchor="w")
        if m.get("url"):
            tk.Label(info_box, text=m["url"], font=(FONT, fs(8)), bg=CARD, fg=MUTED,
                     wraplength=px(150), justify="left").pack(anchor="w")

        more = ttk.Menubutton(top, text="⋯", width=3, style="More.TMenubutton")
        more.pack(side="right")
        more["menu"] = self._menu(more, lid)
        ttk.Button(top, text="✎ Edit", command=self.edit, style="Small.TButton").pack(side="right", padx=(0, px(4)))

        # Category and lock pill badges
        pill_row = tk.Frame(pad_wrap, bg=CARD)
        pill_row.pack(anchor="w", pady=(px(8), px(12)))
        cat_badge = tk.Frame(pill_row, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(8), pady=px(2))
        cat_badge.pack(side="left")
        tk.Label(cat_badge, text=m.get("category", "Other"), font=(FONT, fs(8), "bold"), bg=FIELD_RO, fg=MUTED).pack()
        if m.get("has_pin"):
            pin_badge = tk.Frame(pill_row, bg=PRIMARY_LIGHT, highlightbackground=PRIMARY_OFF, highlightthickness=1, padx=px(8), pady=px(2))
            pin_badge.pack(side="left", padx=(px(6), 0))
            tk.Label(pin_badge, text="🔒 PIN Protected", font=(FONT, fs(8), "bold"), bg=PRIMARY_LIGHT, fg=PRIMARY).pack()

        def field(label, value, buttons):
            f_box = tk.Frame(pad_wrap, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(10), pady=px(6))
            f_box.pack(fill="x", pady=(0, px(8)))
            top_r = tk.Frame(f_box, bg=FIELD_RO)
            top_r.pack(fill="x")
            tk.Label(top_r, text=label.upper(), font=(FONT, fs(7), "bold"), bg=FIELD_RO, fg=MUTED).pack(side="left")
            val_r = tk.Frame(f_box, bg=FIELD_RO)
            val_r.pack(fill="x", pady=(px(2), 0))
            tk.Label(val_r, text=value or "—", font=(FONT, fs(9)), bg=FIELD_RO, fg=TEXT, wraplength=px(170), justify="left").pack(side="left")
            for text, cmd in reversed(buttons):
                ttk.Button(val_r, text=text, command=cmd, style="Small.TButton").pack(side="right", padx=(px(4), 0))

        if m.get("url"):
            field("Website", m["url"], [("Open", lambda: self.open_site(m["url"]))])
        field("Username", m.get("username"),
              [("Copy", lambda: self.app.copy(m.get("username", ""), "Username"))] if m.get("username") else [])
        field("Password", sec["password"] if sec else "••••••••••••",
              [("Hide" if sec else "Show", self.toggle_reveal), ("Copy", self.copy_password)])

        score = m.get("strength", 4)
        if passgen.is_weak(score):
            box = tk.Frame(pad_wrap, bg=WARN_BG, highlightbackground=WARN_BORDER, highlightthickness=1, padx=px(10), pady=px(8))
            box.pack(fill="x", pady=(0, px(8)))
            why = f"This password is {passgen.LABELS[score].lower()}."
            tk.Label(box, text="⚠ " + why, font=(FONT, fs(8), "bold"), bg=WARN_BG, fg=WARN_FG, wraplength=px(230), justify="left").pack(anchor="w")
            tk.Label(box, text="Change it on the website, then save the new one here.", font=(FONT, fs(8)),
                     bg=WARN_BG, fg=WARN_FG, wraplength=px(230), justify="left").pack(anchor="w", pady=(px(2), px(6)))
            ttk.Button(box, text="Update password…", command=lambda: self.edit(regenerate=True), style="Small.TButton").pack(anchor="w")
        else:
            meter_box = tk.Frame(pad_wrap, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(10), pady=px(6))
            meter_box.pack(fill="x", pady=(0, px(8)))
            tk.Label(meter_box, text="PASSWORD STRENGTH", font=(FONT, fs(7), "bold"), bg=FIELD_RO, fg=MUTED).pack(anchor="w")
            score_lbl = tk.Label(meter_box, text=passgen.LABELS[score], font=(FONT, fs(9), "bold"), bg=FIELD_RO, fg=METER[score])
            score_lbl.pack(anchor="w", pady=(px(2), 0))

        if sec and sec.get("notes"):
            notes_box = tk.Frame(pad_wrap, bg=FIELD_RO, highlightbackground=LINE, highlightthickness=1, padx=px(10), pady=px(6))
            notes_box.pack(fill="x", pady=(0, px(8)))
            tk.Label(notes_box, text="NOTES", font=(FONT, fs(7), "bold"), bg=FIELD_RO, fg=MUTED).pack(anchor="w")
            tk.Label(notes_box, text=sec["notes"], font=(FONT, fs(8)), bg=FIELD_RO, fg=TEXT, wraplength=px(230), justify="left").pack(anchor="w", pady=(px(2), 0))

        footer = tk.Frame(pad_wrap, bg=CARD)
        footer.pack(side="bottom", fill="x")
        tk.Label(footer, text=f"Last updated {fmt_date(m.get('updated', 0))}", font=(FONT, fs(8)), bg=CARD, fg=MUTED).pack(anchor="w")

    def _menu(self, parent, lid):
        menu = tk.Menu(parent, tearoff=False, font=(FONT, fs(10)), bg=CARD, fg=TEXT,
                       activebackground=PRIMARY, activeforeground="white")
        m = self.app.vault.items[lid]
        menu.add_command(label="Edit", command=self.edit)
        menu.add_command(label="Copy username", command=lambda: self.app.copy(m.get("username", ""), "Username"))
        menu.add_command(label="Copy password", command=self.copy_password)
        if m.get("url"):
            menu.add_command(label="Open website", command=lambda: self.open_site(m["url"]))
        menu.add_separator()
        menu.add_command(label="Delete", foreground=BAD_FG, command=self.delete)
        return menu

    def _context(self, e):
        row = self.tree.identify_row(e.y)
        if row in self.app.vault.items:
            self.tree.selection_set(row)
            self._on_select()
            self._menu(self.tree, row).tk_popup(e.x_root, e.y_root)

    # ---- actions
    def _secret(self):
        """Secret of the selected entry; prompts for the PIN if it has one."""
        if self.revealed and self.revealed[0] == self.selected:
            return self.revealed[1], self.revealed[2]
        sec, pin = self.app.open_item(self.selected)
        if sec is not None:
            self.revealed = (self.selected, sec, pin)
        return sec, pin

    def toggle_reveal(self):
        if self.revealed and self.revealed[0] == self.selected:
            self.revealed = None
        else:
            self._secret()
        self.show_detail()

    def copy_password(self):
        sec, _ = self._secret()
        if sec:
            self.app.copy(sec["password"], "Password")

    def open_site(self, url):
        webbrowser.open(url if "://" in url else "https://" + url)

    def edit(self, regenerate=False):
        if not self.selected:
            return
        sec, pin = self._secret()
        if sec is None:
            return
        dlg = EntryDialog(self.app, self.selected, self.app.vault.items[self.selected], sec, pin)
        if regenerate:
            dlg.after(150, dlg.open_passgen)
        dlg.show()

    def delete(self):
        m = self.app.vault.items[self.selected]
        if messagebox.askyesno(APP, f"Delete “{m['name']}”?\n\nThis can't be undone.", icon="warning",
                               parent=self.app):
            self.app.vault.delete_item(self.selected)
            self.selected = self.revealed = None
            self.refresh()
            self.app.status(f"“{m['name']}” deleted.")



# ---------------------------------------------------------------- app shell
class App(tk.Tk):
    def __init__(self, vault_path, demo_hint=""):
        super().__init__()
        self.title(f"{APP} {VERSION} — course prototype")
        self.geometry("1180x720")
        self.minsize(980, 600)
        apply_theme(Vault.read_setting(vault_path, "theme", "light"))
        apply_text_size(Vault.read_setting(vault_path, "text_size", "normal"))
        setup_styles(self)
        if TEXT_SIZE != "normal":          # bigger text needs a bigger window
            self.state("zoomed")
        self.vault_path, self.demo_hint = vault_path, demo_hint
        self.vault: Vault | None = None
        self.home = None
        self.screen = None
        self._clip = None
        self.last_activity = time.monotonic()

        status_frame = tk.Frame(self, bg=CARD)
        status_frame.pack(side="bottom", fill="x")
        tk.Frame(status_frame, bg=LINE, height=1).pack(fill="x")
        self.statusbar = tk.Label(status_frame, font=(FONT, fs(9)), bg=CARD, fg=MUTED, anchor="w", padx=px(16), pady=px(6))
        self.statusbar.pack(fill="x")
        for ev in ("<Any-KeyPress>", "<Any-Button>", "<Motion>"):
            self.bind_all(ev, self._touch, add="+")
        self.protocol("WM_DELETE_WINDOW", self.quit_app)

        # Pre-warm Deep Learning engine in background (0s delay on Face ID, never touches camera/LED)
        threading.Thread(target=face_auth.prewarm, daemon=True).start()

        self.show(UnlockScreen if Vault.exists(vault_path) else SetupScreen)
        self.after(5000, self._tick)

    def show(self, screen_cls, **kw):
        self.unbind("<Return>")
        if self.screen:
            self.screen.destroy()
        self.home = None
        self.screen = screen_cls(self, **kw)
        self.screen.pack(fill="both", expand=True)
        self.status("")

    def status(self, msg):
        self.statusbar.configure(text=msg or NOTICE)

    def set_appearance(self, theme=None, text_size=None):
        if theme:
            apply_theme(theme)
        if text_size:
            apply_text_size(text_size)
            if TEXT_SIZE != "normal":
                self.state("zoomed")
        setup_styles(self)
        if hasattr(self, "statusbar"):
            self.statusbar.configure(font=(FONT, fs(9)), bg=CARD, fg=MUTED)
            if self.statusbar.master:
                self.statusbar.master.configure(bg=CARD)
        if self.vault:
            self.show(HomeScreen)
        if theme:
            self.status(f"{THEME_NAMES[THEME]} theme on.")
        else:
            self.status(f"Text size: {TEXT_SIZES[TEXT_SIZE][0]}.")

    # ---- security helpers
    def copy(self, text, what):
        self.clipboard_clear()
        self.clipboard_append(text)
        secs = self.vault.settings.get("clip_clear_s", 30) if self.vault else 30
        self.status(f"{what} copied. It will be cleared from the clipboard in {secs} seconds.")
        self._clip = text
        self.after(secs * 1000, lambda: self._clear_clip(text))

    def _clear_clip(self, text):
        if self._clip != text:
            return
        try:
            if self.clipboard_get() == text:
                self.clipboard_clear()
                self.clipboard_append("")
                self.status("Clipboard cleared.")
        except tk.TclError:
            pass
        self._clip = None

    def open_item(self, lid):
        """Decrypts one entry, asking for its PIN when it has one. Returns (secret, pin) or (None, None)."""
        m = self.vault.items[lid]
        for _ in range(5):
            pin = ""
            if m.get("has_pin"):
                pin = simpledialog.askstring("Extra lock", f"“{m['name']}” has an extra lock.\n"
                                                           "Enter its PIN:", show="•", parent=self)
                if pin is None:
                    return None, None
            try:
                with busy(self):
                    return self.vault.reveal(lid, pin), pin
            except WrongPinOrTampered:
                if not m.get("has_pin"):
                    messagebox.showerror(APP, "This entry couldn't be opened. The vault file may be damaged.",
                                         parent=self)
                    return None, None
                messagebox.showerror(APP, "That PIN didn't open this entry. Please try again.", parent=self)
        return None, None

    def confirm_master(self, parent, prompt) -> bool:
        pw = simpledialog.askstring(APP, prompt, show="•", parent=parent)
        if pw is None:
            return False
        try:
            with busy(parent):
                Vault.unlock(self.vault_path, pw).lock()
            return True
        except WrongMasterPassword:
            messagebox.showerror(APP, "That master password didn't work.", parent=parent)
            return False

    def lock(self, message=""):
        for w in self.winfo_children():
            if isinstance(w, tk.Toplevel):
                w.destroy()
        if self.vault:
            self.vault.lock()
        self.vault = None
        self._clear_clip(self._clip)
        self.show(UnlockScreen, message=message)

    def _touch(self, _e=None):
        self.last_activity = time.monotonic()

    def _tick(self):
        if self.vault:
            mins = self.vault.settings.get("autolock_min", 5)
            if mins and time.monotonic() - self.last_activity > mins * 60:
                self.lock(f"Locked after {mins} minute{'s' if mins != 1 else ''} without activity.")
        self.after(5000, self._tick)

    def quit_app(self):
        self._clear_clip(self._clip)
        if self.vault:
            self.vault.lock()
        self.destroy()


# ---------------------------------------------------------------- demo data
DEMO_PASSWORD = "SafeSpace demo 2026"
DEMO_ITEMS = [
    ("Gmail", "mail.google.com", "alex.morgan@gmail.com", "Email", "Tq8#vRz2!mWp4Lx", ""),
    ("Outlook (work)", "outlook.office.com", "a.morgan@contoso.com", "Work", "Summer2024!", ""),
    ("Facebook", "facebook.com", "alex.morgan@gmail.com", "Social", "alex1990", ""),
    ("Instagram", "instagram.com", "alexm_photos", "Social", "Willow-Cactus-Meteor-42", ""),
    ("Instagram (studio)", "instagram.com", "alexm_studio", "Social", "Copper-Lantern-Quiver-63", ""),
    ("HDFC NetBanking", "netbanking.hdfcbank.com", "alexm88", "Banking", "pB7$kd29!Qe#Lm3z", "246810"),
    ("Amazon", "amazon.in", "alex.morgan@gmail.com", "Shopping", "alex1990", ""),
    ("Flipkart", "flipkart.com", "9876543210", "Shopping", "Marble-Ember-Harbor-Violet-17", ""),
    ("Netflix", "netflix.com", "alex.morgan@gmail.com", "Entertainment", "qwerty123", ""),
    ("Spotify", "spotify.com", "alexm", "Entertainment", "Galaxy-Pebble-Saddle-88", ""),
    ("Slack (work)", "contoso.slack.com", "a.morgan@contoso.com", "Work", "h4Z!rT8@wQ2#nV6p", ""),
]


def build_demo_vault(path):
    if os.path.exists(path):
        os.remove(path)
    vault, _ = Vault.create(path, DEMO_PASSWORD)
    for name, url, user, cat, pw, pin in DEMO_ITEMS:
        meta = {"name": name, "url": url, "username": user, "category": cat,
                "strength": passgen.strength(pw)[0], "fp": vault.fingerprint(pw)}
        vault.add_item(meta, {"password": pw, "notes": ""}, pin)
    vault.lock()


def main():
    ap = argparse.ArgumentParser(description="SafeSpace desktop password manager")
    ap.add_argument("--vault", help="path to the vault file")
    ap.add_argument("--demo", action="store_true", help="reset and open a sample vault for usability sessions")
    args = ap.parse_args()
    # Packaged .exe: "SafeSpace-Demo.exe" starts in demo mode, files go next to the exe.
    frozen = getattr(sys, "frozen", False)
    here = os.path.dirname(sys.executable if frozen else os.path.abspath(__file__))
    if frozen and "demo" in os.path.basename(sys.executable).lower():
        args.demo = True
    hint = ""
    path = args.vault or default_vault_path()
    if args.demo:
        path = args.vault or os.path.join(here, "demo_vault.json")
        print("Building demo vault...")
        build_demo_vault(path)
        hint = f"Demo vault — master password: {DEMO_PASSWORD}   (HDFC PIN: 246810)"
    App(path, hint).mainloop()


if __name__ == "__main__":
    main()
