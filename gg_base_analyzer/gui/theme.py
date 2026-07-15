"""GUI 主题 — 深墨 + 青绿（避免通用紫渐变风）。"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

THEME = {
    "bg": "#0f1419",
    "surface": "#1a222c",
    "surface_alt": "#232d3a",
    "border": "#2f3b4a",
    "text": "#e8eef4",
    "text_secondary": "#9aa8b7",
    "text_muted": "#6b7a8a",
    "accent": "#2dd4bf",
    "accent_dim": "#14b8a6",
    "accent_soft": "#134e4a",
    "success": "#34d399",
    "warning": "#fbbf24",
    "danger": "#f87171",
    "header_bg": "#121821",
    "status_bg": "#0a0e12",
    "status_fg": "#8b9aab",
    "input_bg": "#0f1419",
}

FONTS = {
    "title": ("Microsoft YaHei UI", 18, "bold"),
    "subtitle": ("Microsoft YaHei UI", 10),
    "body": ("Microsoft YaHei UI", 10),
    "body_bold": ("Microsoft YaHei UI", 10, "bold"),
    "small": ("Microsoft YaHei UI", 9),
    "mono": ("Cascadia Mono", 10),
}


def apply_theme(root: tk.Misc) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=THEME["bg"])
    bg, surface, text, accent = THEME["bg"], THEME["surface"], THEME["text"], THEME["accent"]

    style.configure(".", background=bg, foreground=text, font=FONTS["body"], borderwidth=0)
    style.configure("TFrame", background=bg)
    style.configure("Surface.TFrame", background=surface)
    style.configure("Header.TFrame", background=THEME["header_bg"])
    style.configure("Title.TLabel", font=FONTS["title"], foreground=text, background=THEME["header_bg"])
    style.configure(
        "Subtitle.TLabel",
        font=FONTS["subtitle"],
        foreground=THEME["text_secondary"],
        background=THEME["header_bg"],
    )
    style.configure("Hint.TLabel", font=FONTS["small"], foreground=THEME["text_muted"], background=bg)
    style.configure("CardTitle.TLabel", font=FONTS["body_bold"], foreground=text, background=surface)

    style.configure(
        "Accent.TButton",
        background=accent,
        foreground="#042f2e",
        padding=(16, 8),
        font=FONTS["body_bold"],
        borderwidth=0,
    )
    style.map("Accent.TButton", background=[("active", THEME["accent_dim"]), ("pressed", THEME["accent_dim"])])

    style.configure(
        "Primary.TButton",
        background=THEME["surface_alt"],
        foreground=text,
        padding=(12, 7),
        font=FONTS["body"],
    )
    style.map("Primary.TButton", background=[("active", THEME["border"])])

    style.configure("TEntry", fieldbackground=THEME["input_bg"], foreground=text, insertcolor=text)
    style.configure("TCombobox", fieldbackground=THEME["input_bg"], foreground=text)
    style.configure("TNotebook", background=bg, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=THEME["surface_alt"],
        foreground=THEME["text_secondary"],
        padding=(18, 10),
        font=FONTS["body"],
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", surface)],
        foreground=[("selected", accent)],
    )
    style.configure("Treeview", background=surface, foreground=text, fieldbackground=surface, rowheight=28)
    style.configure("Treeview.Heading", background=THEME["surface_alt"], foreground=THEME["text_secondary"])
    style.map("Treeview", background=[("selected", THEME["accent_soft"])], foreground=[("selected", text)])
    style.configure("TLabelframe", background=surface, foreground=text)
    style.configure("TLabelframe.Label", background=surface, foreground=accent, font=FONTS["body_bold"])
    style.configure("TCheckbutton", background=bg, foreground=text)
    style.configure("Horizontal.TProgressbar", background=accent, troughcolor=THEME["surface_alt"])
    return style
