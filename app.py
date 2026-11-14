"""
app.py - SafeSpace desktop password manager (Tkinter UI).

    python app.py                 # your real vault (%APPDATA%\\SafeSpace\\vault.json)
    python app.py --demo          # fresh sample vault for usability sessions
    python app.py --vault FILE    # use a specific vault file

Requires: pip install argon2-cffi pynacl cryptography
"""

import argparse
import os
import secrets
import sys
import time
import tkinter as tk
import webbrowser
from contextlib import contextmanager
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

import cv2
import numpy as np
from PIL import Image, ImageTk

import face_auth
import passgen
from open_locker_demo import WrongPinOrTampered
from vault import Vault, WrongMasterPassword, default_vault_path, read_import_csv

APP = "SafeSpace"
VERSION = "0.1"
NOTICE = "Course prototype (Usable Security, IIIT Delhi). Not audited: do not store real passwords."
CATEGORIES = ["Email", "Social", "Banking", "Shopping", "Work", "Entertainment", "Other"]
ATTENTION = "Needs attention"
ALL = "All items"

BG, CARD, LINE = "#f5f6fa", "#ffffff", "#dde1ea"
TEXT, MUTED = "#1d2433", "#5d6678"
PRIMARY, PRIMARY_DARK = "#2f5bea", "#2447b8"
WARN_BG, WARN_FG, BAD_FG, GOOD_FG = "#fff4d6", "#7a4b00", "#b42318", "#1a7f37"
METER = ["#d92d20", "#f79009", "#eaaa08", "#3fa34d", "#1a7f37"]
FONT = "Segoe UI"


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


def setup_styles(root: tk.Tk) -> None:
    s = ttk.Style(root)
    s.theme_use("clam")
    root.configure(bg=BG)
    s.configure(".", background=BG, foreground=TEXT, font=(FONT, 10))
    s.configure("Card.TFrame", background=CARD)
    s.configure("Card.TLabel", background=CARD)
    s.configure("Muted.TLabel", foreground=MUTED)
    s.configure("CardMuted.TLabel", background=CARD, foreground=MUTED)
    s.configure("Title.TLabel", font=(FONT, 20, "bold"))
    s.configure("H2.TLabel", font=(FONT, 13, "bold"), background=CARD)
    s.configure("Big.TLabel", font=(FONT, 16, "bold"), background=CARD)
    s.configure("Mono.TLabel", font=("Consolas", 15), background=CARD)
    s.configure("TButton", padding=(10, 5))
    s.configure("Primary.TButton", background=PRIMARY, foreground="white", padding=(12, 6),
                font=(FONT, 10, "bold"), bordercolor=PRIMARY)
    s.map("Primary.TButton", background=[("active", PRIMARY_DARK), ("disabled", "#9db0f0")])
    s.configure("Danger.TButton", foreground=BAD_FG)
    s.configure("Link.TButton", foreground=PRIMARY, background=CARD, borderwidth=0, padding=0,
                font=(FONT, 10, "underline"))
    s.map("Link.TButton", background=[("active", CARD)])
    s.configure("More.TMenubutton", font=(FONT, 14, "bold"), padding=(6, 0))
    s.configure("Header.TFrame", background=CARD)
    s.configure("Warn.TFrame", background=WARN_BG)
    s.configure("Warn.TLabel", background=WARN_BG, foreground=WARN_FG, font=(FONT, 10, "bold"))
    s.configure("TCheckbutton", background=CARD)
    s.configure("TRadiobutton", background=CARD)
    s.configure("Treeview", rowheight=30, font=(FONT, 10), background=CARD, fieldbackground=CARD)
    s.configure("Treeview.Heading", font=(FONT, 10, "bold"))
    s.configure("Horizontal.TScale", background=CARD)
    for i, c in enumerate(METER):
        s.configure(f"M{i}.Horizontal.TProgressbar", background=c, troughcolor="#eceef3",
                    bordercolor="#eceef3", lightcolor=c, darkcolor=c)


class Dialog(tk.Toplevel):
    """Modal window centred on its parent."""

    def __init__(self, parent, title):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=CARD)
        self.transient(parent.winfo_toplevel())
        self.resizable(False, False)
        self.body = ttk.Frame(self, style="Card.TFrame", padding=20)
        self.body.pack(fill="both", expand=True)
        self.bind("<Escape>", lambda e: self.destroy())

    def show(self):
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
        self.label = ttk.Label(self, style=f"{style}.TLabel", font=(FONT, 10, "bold"))
        self.label.grid(row=0, column=1, padx=10, sticky="w")
        self.advice = ttk.Label(self, style=f"{style}Muted.TLabel", wraplength=380)
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
        self.entry = ttk.Entry(self, textvariable=var, show="•", width=width, font=(FONT, 11))
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
        ttk.Label(self, style="CardMuted.TLabel", wraplength=400,
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
    ttk.Label(b, style="Card.TLabel", wraplength=460, justify="left",
              text="If you ever forget your master password, this key is the only way to get "
                   "back into SafeSpace. Nobody, including the SafeSpace team, can reset it for you.\n\n"
                   "Write it down or save it somewhere safe that isn't this computer.").pack(anchor="w", pady=(6, 12))
    box = ttk.Frame(b, style="Card.TFrame", padding=12, relief="solid", borderwidth=1)
    box.pack(fill="x")
    ttk.Label(box, text=key, style="Mono.TLabel").pack()
    row = ttk.Frame(b, style="Card.TFrame")
    row.pack(fill="x", pady=10)

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
                    command=lambda: cont.configure(state="normal" if ok.get() else "disabled")).pack(anchor="w")
    cont.pack(anchor="e", pady=(12, 0))
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
        out = ttk.Frame(b, style="Card.TFrame", padding=10, relief="solid", borderwidth=1)
        out.grid(row=2, column=0, columnspan=3, sticky="we")
        ttk.Label(out, textvariable=self.result, style="Mono.TLabel", width=34).pack(side="left")
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
            ttk.Label(b, text=label, style="Card.TLabel", font=(FONT, 10, "bold")).grid(
                row=r, column=0, sticky="nw", pady=(6, 0), padx=(0, 14))
            widget.grid(row=r, column=1, sticky="we", pady=(6, 0))
            if hint:
                ttk.Label(b, text=hint, style="CardMuted.TLabel").grid(row=r + 1, column=1, sticky="w")

        name = ttk.Entry(b, textvariable=self.v["name"], width=40, font=(FONT, 11))
        row(1, "Name", "What you'll search for, e.g. Gmail or My bank", name)
        row(3, "Website", "Optional, e.g. mail.google.com", ttk.Entry(b, textvariable=self.v["url"], width=40,
                                                                      font=(FONT, 11)))
        row(5, "Username / email", None, ttk.Entry(b, textvariable=self.v["username"], width=40, font=(FONT, 11)))

        pwrow = ttk.Frame(b, style="Card.TFrame")
        self.pwfield = PasswordField(pwrow, self.pw, width=28)
        self.pwfield.pack(side="left", fill="x", expand=True)
        ttk.Button(pwrow, text="Generate…", command=self.open_passgen).pack(side="left", padx=(6, 0))
        row(6, "Password", None, pwrow)
        StrengthMeter(b, self.pw).grid(row=7, column=1, sticky="w", pady=(4, 0))

        row(8, "Category", None, ttk.Combobox(b, textvariable=self.v["category"], values=CATEGORIES,
                                              state="readonly", width=20))
        ttk.Label(b, text="Notes", style="Card.TLabel", font=(FONT, 10, "bold")).grid(
            row=9, column=0, sticky="nw", pady=(6, 0))
        self.notes = tk.Text(b, width=40, height=3, font=(FONT, 10), relief="solid", borderwidth=1)
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
            if len(pin) < 4:
                messagebox.showwarning(APP, "The PIN needs at least 4 characters.", parent=self)
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
            ttk.Label(b, text=desc, style="CardMuted.TLabel", wraplength=420).pack(anchor="w", padx=(22, 0))
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
                  style="CardMuted.TLabel", wraplength=380).pack(anchor="w", pady=(0, 10))

        self.canvas = tk.Canvas(b, width=360, height=270, bg="#1a1d24", highlightthickness=0)
        self.canvas.pack(pady=(0, 10))

        self.progress = ttk.Progressbar(b, maximum=self.needed, length=360)
        self.progress.pack(pady=(0, 8))

        self.status_lbl = ttk.Label(b, text="Starting camera...", style="Card.TLabel", font=(FONT, 10, "bold"))
        self.status_lbl.pack(anchor="center", pady=(0, 12))

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")

        self.bind("<Destroy>", self._cleanup)
        self.after(200, self._start_camera)

    def _start_camera(self):
        try:
            self.cap = cv2.VideoCapture(0)
            if not self.cap or not self.cap.isOpened():
                self.status_lbl.configure(text="Could not open camera. Please check your webcam.", foreground=BAD_FG)
                return
            self._tick()
        except Exception as e:
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
        self._job = self.after(40, self._tick)

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
        if event and event.widget == self:
            self._stop_camera()


class FaceUnlockDialog(Dialog):
    """Camera modal to scan face and unlock vault."""

    def __init__(self, app):
        super().__init__(app, "Unlock with Face ID")
        self.app = app
        self.vault = None
        self.cap = None
        self._job = None
        self.attempts = 0
        self.max_attempts = 150

        profile = face_auth.load_biometric_profile(app.vault_path)
        if not profile:
            messagebox.showerror(APP, "Biometric profile is missing or damaged. Use master password.", parent=app)
            self.after(50, self.destroy)
            return

        self.bio_key, self.ref_emb = profile

        b = self.body
        ttk.Label(b, text="Face ID Unlock", style="H2.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(b, text="Look directly at the camera to unlock SafeSpace.", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 10))

        self.canvas = tk.Canvas(b, width=360, height=270, bg="#1a1d24", highlightthickness=0)
        self.canvas.pack(pady=(0, 10))

        self.status_lbl = ttk.Label(b, text="Starting camera...", style="Card.TLabel", font=(FONT, 10, "bold"))
        self.status_lbl.pack(anchor="center", pady=(0, 12))

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Use Master Password", command=self.destroy).pack(side="right")

        self.bind("<Destroy>", self._cleanup)
        self.after(200, self._start_camera)

    def _start_camera(self):
        try:
            self.cap = cv2.VideoCapture(0)
            if not self.cap or not self.cap.isOpened():
                self.status_lbl.configure(text="Webcam not detected. Use master password.", foreground=BAD_FG)
                return
            self._tick()
        except Exception as e:
            self.status_lbl.configure(text=f"Camera error: {e}", foreground=BAD_FG)

    def _tick(self):
        if not self.cap or not self.cap.isOpened():
            return
        ret, frame = self.cap.read()
        if not ret or frame is None:
            self._job = self.after(30, self._tick)
            return

        self.attempts += 1
        frame = cv2.flip(frame, 1)
        engine = face_auth.get_engine()
        res = engine.process_frame(frame)

        display_frame = frame.copy()
        if res["ok"]:
            matched, sim = engine.verify(res["embedding"], self.ref_emb)
            bbox = res["bbox"]
            if matched:
                cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 220, 100), 3)
                self.status_lbl.configure(text=f"Face recognized ({int(sim*100)}% match). Unlocking...", foreground=GOOD_FG)
                self._render(display_frame)
                self._stop_camera()
                self.after(300, self._unlock_vault)
                return
            else:
                cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 100, 255), 2)
                self.status_lbl.configure(text=f"Face not recognized ({int(sim*100)}% match).", foreground=BAD_FG)
        else:
            if res.get("bbox"):
                bbox = res["bbox"]
                cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 180, 255), 2)
            self.status_lbl.configure(text=res["msg"], foreground=WARN_FG)

        self._render(display_frame)

        if self.attempts >= self.max_attempts:
            self.status_lbl.configure(text="Face verification timed out. Please enter master password.", foreground=BAD_FG)
            self._stop_camera()
            return

        self._job = self.after(40, self._tick)

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
        if event and event.widget == self:
            self._stop_camera()


class AccountDialog(Dialog):
    def __init__(self, app):
        super().__init__(app, "Account & security")
        self.app = app
        v = app.vault
        b = self.body
        ttk.Label(b, text="Account & security", style="Big.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")

        def section(r, title, text):
            ttk.Separator(b).grid(row=r, column=0, columnspan=2, sticky="we", pady=12)
            ttk.Label(b, text=title, style="H2.TLabel").grid(row=r + 1, column=0, columnspan=2, sticky="w")
            if text:
                ttk.Label(b, text=text, style="CardMuted.TLabel", wraplength=480, justify="left").grid(
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
        ttk.Button(b, text="Create a new recovery key…", command=self.new_recovery).grid(row=11, column=0, sticky="w")

        section(12, "Security settings", "")
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

        section(17, "Face ID (Biometric Unlock)",
                "Unlock your vault using facial recognition on this computer. "
                "SafeSpace never saves your image; only an encrypted mathematical template is stored with Windows DPAPI.")
        self.face_status_lbl = ttk.Label(b, text="", style="Card.TLabel")
        self.face_status_lbl.grid(row=20, column=0, columnspan=2, sticky="w", pady=(2, 6))
        self.face_btn_frame = ttk.Frame(b, style="Card.TFrame")
        self.face_btn_frame.grid(row=21, column=0, columnspan=2, sticky="w")
        self._refresh_face_section()

        section(22, "Delete account",
                "Permanently erases your vault from this computer. Make an encrypted backup (Export) first "
                "if you might need your passwords again. This cannot be undone.")
        ttk.Button(b, text="Delete account and all data…", style="Danger.TButton",
                   command=self.delete_account).grid(row=25, column=0, sticky="w")

        btns = ttk.Frame(b, style="Card.TFrame")
        btns.grid(row=26, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Lock now", command=lambda: (self.destroy(), app.lock())).pack(side="right", padx=6)

    @staticmethod
    def _autolock_label(m):
        return "Never" if not m else f"{m} minute" + ("s" if m != 1 else "")

    def set_autolock(self, _e=None):
        t = self.autolock.get()
        self.app.vault.set_setting("autolock_min", 0 if t == "Never" else int(t.split()[0]))

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
        card = ttk.Frame(self, style="Card.TFrame", padding=32)
        card.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(card, text="Welcome to SafeSpace", style="Big.TLabel", font=(FONT, 20, "bold")).pack(anchor="w")
        ttk.Label(card, style="Card.TLabel", wraplength=420, justify="left",
                  text="SafeSpace remembers your passwords in an encrypted vault on this computer. "
                       "You only need to remember one password: your master password.").pack(anchor="w", pady=(6, 8))
        ttk.Label(card, text="⚠ " + NOTICE, style="Card.TLabel", foreground=WARN_FG, wraplength=420,
                  justify="left").pack(anchor="w", pady=(0, 14))
        self.form = NewMasterForm(card)
        self.form.pack(anchor="w")
        ttk.Label(card, style="CardMuted.TLabel", wraplength=420,
                  text="Next you'll get a recovery key in case you ever forget it.").pack(anchor="w", pady=(12, 0))
        ttk.Button(card, text="Create my vault", style="Primary.TButton", command=self.create).pack(anchor="e",
                                                                                                    pady=(16, 0))
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
        card = ttk.Frame(self, style="Card.TFrame", padding=32)
        card.place(relx=0.5, rely=0.42, anchor="center")
        ttk.Label(card, text="\U0001F512  SafeSpace", style="Big.TLabel", font=(FONT, 22, "bold")).pack(anchor="w")
        ttk.Label(card, text="Unlock your vault to view passwords.", style="Card.TLabel").pack(anchor="w",
                                                                                               pady=(4, 14))
        if message:
            ttk.Label(card, text=message, style="CardMuted.TLabel").pack(anchor="w", pady=(0, 8))

        self.can_face = Vault.is_biometric_enabled(self.app.vault_path) and face_auth.has_biometric_profile(self.app.vault_path)
        if self.can_face:
            ttk.Button(card, text="👤  Unlock with Face ID", style="Primary.TButton",
                       command=self.unlock_face).pack(fill="x", pady=(0, 10))
            ttk.Label(card, text="— or enter master password —", style="CardMuted.TLabel").pack(anchor="center", pady=(0, 10))

        self.pw = tk.StringVar()
        field = PasswordField(card, self.pw, width=30)
        field.pack(fill="x")
        self.err = ttk.Label(card, text="", style="Card.TLabel", foreground=BAD_FG)
        self.err.pack(anchor="w", pady=(4, 0))
        btn_style = "TButton" if self.can_face else "Primary.TButton"
        ttk.Button(card, text="Unlock with Password", style=btn_style, command=self.unlock).pack(fill="x", pady=(8, 0))
        ttk.Button(card, text="Forgot your master password?", style="Link.TButton",
                   command=self.recover).pack(anchor="w", pady=(14, 0))
        if app.demo_hint:
            ttk.Label(card, text=app.demo_hint, style="CardMuted.TLabel").pack(anchor="w", pady=(14, 0))
        app.bind("<Return>", lambda e: self.unlock())
        field.entry.focus_set()

    def unlock_face(self):
        self.err.configure(text="")
        dlg = FaceUnlockDialog(self.app)
        dlg.show()
        if dlg.vault:
            self.app.unbind("<Return>")
            self.app.vault = dlg.vault
            self.app.show(HomeScreen)

    def unlock(self):
        try:
            with busy(self):
                vault = Vault.unlock(self.app.vault_path, self.pw.get())
        except WrongMasterPassword:
            self.err.configure(text="That master password didn't work. Check Caps Lock and try again.")
            self.pw.set("")
            return
        self.app.unbind("<Return>")
        self.app.vault = vault
        self.app.show(HomeScreen)

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

        # Header
        hdr = ttk.Frame(self, style="Header.TFrame", padding=(16, 10))
        hdr.pack(fill="x")
        ttk.Label(hdr, text="\U0001F512 SafeSpace", style="Big.TLabel").pack(side="left")
        self.q = tk.StringVar()
        sbox = ttk.Frame(hdr, style="Header.TFrame")
        sbox.pack(side="left", padx=24, fill="x", expand=True)
        ttk.Label(sbox, text="\U0001F50D", style="Card.TLabel").pack(side="left")
        self.search = ttk.Entry(sbox, textvariable=self.q, font=(FONT, 11))
        self.search.pack(side="left", fill="x", expand=True, padx=4)
        self._placeholder()
        ttk.Button(hdr, text="⚙ Account", command=lambda: AccountDialog(app).show()).pack(side="right")
        ttk.Button(hdr, text="Export", command=lambda: ExportDialog(app).show()).pack(side="right", padx=4)
        ttk.Button(hdr, text="Import", command=lambda: do_import(app)).pack(side="right")
        ttk.Button(hdr, text="PassGen", command=lambda: PassGenDialog(app, app).show()).pack(side="right", padx=4)
        ttk.Button(hdr, text="+ Add login", style="Primary.TButton",
                   command=lambda: EntryDialog(app).show()).pack(side="right", padx=4)
        self.sep = ttk.Separator(self)
        self.sep.pack(fill="x")

        # Warning banner (packed only when needed)
        self.banner = ttk.Frame(self, style="Warn.TFrame", padding=(16, 8))
        self.banner_text = ttk.Label(self.banner, style="Warn.TLabel")
        self.banner_text.pack(side="left")
        ttk.Button(self.banner, text="Review them", command=lambda: self.set_filter(ATTENTION)).pack(side="left",
                                                                                                    padx=12)

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)
        self.body = body

        # Sidebar
        side = ttk.Frame(body, style="Card.TFrame", padding=8)
        side.pack(side="left", fill="y")
        ttk.Label(side, text="Categories", style="H2.TLabel").pack(anchor="w", padx=4, pady=(0, 6))
        self.cats = tk.Listbox(side, width=24, activestyle="none", borderwidth=0, highlightthickness=0,
                               font=(FONT, 11), exportselection=False, selectbackground=PRIMARY, selectforeground="white", bg=CARD)
        self.cats.pack(fill="y", expand=True)
        self.cats.bind("<<ListboxSelect>>", self._on_cat)

        # List
        mid = ttk.Frame(body, style="Card.TFrame")
        mid.pack(side="left", fill="both", expand=True, padx=12)
        self.list_title = ttk.Label(mid, style="H2.TLabel", padding=(10, 8))
        self.list_title.pack(anchor="w")
        self.tree = ttk.Treeview(mid, columns=("user", "site", "strength"), selectmode="browse")
        for col, text, w in [("#0", "Name", 160), ("user", "Username", 170), ("site", "Website", 120),
                             ("strength", "Password", 105)]:
            self.tree.heading(col, text=text, anchor="w")
            self.tree.column(col, width=w, minwidth=60, anchor="w", stretch=col != "strength")
        self.tree.tag_configure("weak", foreground=BAD_FG)
        self.tree.tag_configure("reused", foreground=WARN_FG)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self.edit())
        self.tree.bind("<Button-3>", self._context)
        self.empty = ttk.Label(mid, style="CardMuted.TLabel", justify="center", font=(FONT, 11))

        # Detail
        self.detail = ttk.Frame(body, style="Card.TFrame", padding=18, width=340)
        self.detail.pack(side="right", fill="y", before=mid)
        self.detail.pack_propagate(False)

        self.q.trace_add("write", lambda *a: self.refresh())
        self.refresh()

    # ---- search placeholder
    def _placeholder(self):
        ph = "Search by name, website or username"
        self.search.insert(0, ph)
        self.search.configure(foreground=MUTED)
        self._ph_on = True

        def fin(_):
            if self._ph_on:
                self._ph_on = False
                self.search.delete(0, "end")
                self.search.configure(foreground=TEXT)

        def fout(_):
            if not self.search.get():
                self._ph_on = True
                self.search.insert(0, ph)
                self.search.configure(foreground=MUTED)
        self.search.bind("<FocusIn>", fin)
        self.search.bind("<FocusOut>", fout)

    def query(self) -> str:
        return "" if self._ph_on else self.q.get().strip().lower()

    # ---- data
    def attention_ids(self) -> set:
        v = self.app.vault
        weak = {lid for lid, m in v.items.items() if passgen.is_weak(m.get("strength", 4))}
        return weak | v.reused_ids()

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
        reused = v.reused_ids()

        # banner
        if attention:
            n = len(attention)
            self.banner_text.configure(
                text=f"⚠  {n} of your saved password{'s are' if n != 1 else ' is'} weak or used more than once.")
            self.banner.pack(fill="x", after=self.sep)
        else:
            self.banner.pack_forget()
            if self.filter == ATTENTION:
                self.filter = ALL

        # sidebar
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
                icon = "⚠ " if k == ATTENTION else ""
                self.cats.insert("end", f"  {icon}{k}  ({n})")
                if k == ATTENTION:
                    self.cats.itemconfigure("end", foreground=WARN_FG)
            self.cats.selection_set(self._cat_keys.index(self.filter))

        # list
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
        for lid, m in rows:
            score = m.get("strength", 4)
            if passgen.is_weak(score):
                st, tag = "⚠ " + passgen.LABELS[score], "weak"
            elif lid in reused:
                st, tag = "⚠ Reused", "reused"
            else:
                st, tag = passgen.LABELS[score], ""
            name = m["name"] + ("  \U0001F511" if m.get("has_pin") else "")
            self.tree.insert("", "end", iid=lid, text=name, values=(m.get("username", ""), m.get("url", ""), st),
                             tags=(tag,))
        self.list_title.configure(text=f"{self.filter}  ·  {len(rows)} shown")

        if not v.items:
            self.empty.configure(text="No logins saved yet.\n\nClick “+ Add login” to save your first one,\n"
                                      "or Import them from another app.")
            self.empty.place(relx=0.5, rely=0.4, anchor="center")
        elif not rows:
            self.empty.configure(text="Nothing matches your search.")
            self.empty.place(relx=0.5, rely=0.4, anchor="center")
        else:
            self.empty.place_forget()

        target = select or (self.selected if self.selected in self.tree.get_children() else None)
        if target and self.tree.exists(target):
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
            ttk.Label(d, text="Select a login to see its details.", style="CardMuted.TLabel",
                      wraplength=290).pack(anchor="w")
            return
        lid, m = self.selected, v.items[self.selected]
        sec = self.revealed[1] if self.revealed and self.revealed[0] == lid else None

        top = ttk.Frame(d, style="Card.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text=m["name"], style="Big.TLabel", wraplength=240).pack(side="left", anchor="w")
        more = ttk.Menubutton(top, text="⋯", width=3, style="More.TMenubutton")
        more.pack(side="right")
        more["menu"] = self._menu(more, lid)
        sub = m.get("category", "Other") + ("   \U0001F511 Extra PIN" if m.get("has_pin") else "")
        ttk.Label(d, text=sub, style="CardMuted.TLabel").pack(anchor="w", pady=(2, 14))

        def field(label, value, buttons):
            ttk.Label(d, text=label, style="CardMuted.TLabel").pack(anchor="w")
            r = ttk.Frame(d, style="Card.TFrame")
            r.pack(fill="x", pady=(0, 10))
            ttk.Label(r, text=value or "—", style="Card.TLabel", font=(FONT, 11), wraplength=180).pack(
                side="left")
            for text, cmd in reversed(buttons):
                ttk.Button(r, text=text, command=cmd, width=6).pack(side="right", padx=(4, 0))

        if m.get("url"):
            field("Website", m["url"], [("Open", lambda: self.open_site(m["url"]))])
        field("Username", m.get("username"),
              [("Copy", lambda: self.app.copy(m.get("username", ""), "Username"))] if m.get("username") else [])
        field("Password", sec["password"] if sec else "•" * 10,
              [("Hide" if sec else "Show", self.toggle_reveal), ("Copy", self.copy_password)])

        score = m.get("strength", 4)
        reused = lid in v.reused_ids()
        if passgen.is_weak(score) or reused:
            box = ttk.Frame(d, style="Warn.TFrame", padding=10)
            box.pack(fill="x", pady=(0, 10))
            why = f"This password is {passgen.LABELS[score].lower()}." if passgen.is_weak(score) else \
                "You use this same password for another login."
            ttk.Label(box, text="⚠ " + why, style="Warn.TLabel", wraplength=250).pack(anchor="w")
            ttk.Label(box, text="Change it on the website, then save the new one here. "
                                "PassGen can make a strong one for you.", background=WARN_BG, foreground=WARN_FG,
                      wraplength=250).pack(anchor="w", pady=(4, 6))
            ttk.Button(box, text="Update password…", command=lambda: self.edit(regenerate=True)).pack(anchor="w")
        else:
            ttk.Label(d, text="Password strength", style="CardMuted.TLabel").pack(anchor="w")
            ttk.Label(d, text=passgen.LABELS[score], style="Card.TLabel", foreground=METER[score],
                      font=(FONT, 10, "bold")).pack(anchor="w", pady=(0, 10))

        if sec and sec.get("notes"):
            ttk.Label(d, text="Notes", style="CardMuted.TLabel").pack(anchor="w")
            ttk.Label(d, text=sec["notes"], style="Card.TLabel", wraplength=290, justify="left").pack(anchor="w",
                                                                                                    pady=(0, 10))
        ttk.Label(d, text=f"Last updated {fmt_date(m.get('updated', 0))}", style="CardMuted.TLabel").pack(
            side="bottom", anchor="w")

    def _menu(self, parent, lid):
        menu = tk.Menu(parent, tearoff=False, font=(FONT, 10))
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
        if row:
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
        setup_styles(self)
        self.vault_path, self.demo_hint = vault_path, demo_hint
        self.vault: Vault | None = None
        self.home = None
        self.screen = None
        self._clip = None
        self.last_activity = time.monotonic()

        self.statusbar = ttk.Label(self, padding=(12, 4), style="Muted.TLabel", anchor="w")
        self.statusbar.pack(side="bottom", fill="x")
        for ev in ("<Any-KeyPress>", "<Any-Button>", "<Motion>"):
            self.bind_all(ev, self._touch, add="+")
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
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
    ("HDFC NetBanking", "netbanking.hdfcbank.com", "alexm88", "Banking", "pB7$kd29!Qe#Lm3z", "1234"),
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
        hint = f"Demo vault — master password: {DEMO_PASSWORD}   (HDFC PIN: 1234)"
    App(path, hint).mainloop()


if __name__ == "__main__":
    main()
