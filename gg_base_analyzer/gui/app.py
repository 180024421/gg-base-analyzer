from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from gg_base_analyzer.export import export_all
from gg_base_analyzer.filters import filter_and_rank
from gg_base_analyzer.gui.theme import FONTS, THEME, apply_theme
from gg_base_analyzer.models import AnalyzeConfig, AnalyzeResult
from gg_base_analyzer.online import frida_available, online_search_chains
from gg_base_analyzer.pipeline import analyze_files

OUT_DEFAULT = Path.home() / "Documents" / "gg-base-analyzer" / "out"


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("GG 基址分析器")
        self.geometry("1100x720")
        self.minsize(960, 640)
        apply_theme(self)

        self._files: list[Path] = []
        self._result: AnalyzeResult | None = None
        self.game_var = tk.StringVar(value="game")
        self.package_var = tk.StringVar(value="")
        self.pointer_size_var = tk.IntVar(value=4)
        self.cross_min_var = tk.IntVar(value=2)
        self.address_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="就绪 · 先导入 GG 导出，或使用在线搜链")
        self.progress_var = tk.DoubleVar(value=0)

        self._build()

    def _build(self) -> None:
        header = ttk.Frame(self, style="Header.TFrame", padding=(24, 18))
        header.pack(fill=tk.X)
        ttk.Label(header, text="GG 基址分析器", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            header,
            text="GameGuardian 导出 → 交叉验证 → 稳定基址 · JSON / Frida / Lua",
            style="Subtitle.TLabel",
        ).pack(anchor=tk.W, pady=(4, 0))
        tk.Frame(self, bg=THEME["accent"], height=2).pack(fill=tk.X)

        body = ttk.Frame(self, padding=16)
        body.pack(fill=tk.BOTH, expand=True)

        self.nb = ttk.Notebook(body)
        self.nb.pack(fill=tk.BOTH, expand=True)
        self.tab_offline = ttk.Frame(self.nb, padding=12)
        self.tab_online = ttk.Frame(self.nb, padding=12)
        self.nb.add(self.tab_offline, text="  离线分析  ")
        self.nb.add(self.tab_online, text="  在线搜链  ")

        self._build_offline()
        self._build_online()
        self._build_results(body)
        self._build_status()

    def _build_offline(self) -> None:
        top = ttk.Frame(self.tab_offline)
        top.pack(fill=tk.X)
        ttk.Button(top, text="添加文件", style="Primary.TButton", command=self._add_files).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(top, text="清空", style="Primary.TButton", command=self._clear_files).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(top, text="开始分析", style="Accent.TButton", command=self._run_analyze).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(top, text="导出全部", style="Accent.TButton", command=self._export).pack(side=tk.LEFT)

        opts = ttk.LabelFrame(self.tab_offline, text="参数", padding=12)
        opts.pack(fill=tk.X, pady=12)
        ttk.Label(opts, text="游戏名").grid(row=0, column=0, sticky=tk.W, padx=(0, 6))
        ttk.Entry(opts, textvariable=self.game_var, width=16).grid(row=0, column=1, padx=(0, 16))
        ttk.Label(opts, text="包名").grid(row=0, column=2, sticky=tk.W, padx=(0, 6))
        ttk.Entry(opts, textvariable=self.package_var, width=28).grid(row=0, column=3, padx=(0, 16))
        ttk.Label(opts, text="指针宽度").grid(row=0, column=4, sticky=tk.W, padx=(0, 6))
        ttk.Combobox(
            opts, textvariable=self.pointer_size_var, values=(4, 8), width=5, state="readonly"
        ).grid(row=0, column=5, padx=(0, 16))
        ttk.Label(opts, text="交叉最少文件").grid(row=0, column=6, sticky=tk.W, padx=(0, 6))
        ttk.Spinbox(opts, from_=1, to=5, textvariable=self.cross_min_var, width=5).grid(row=0, column=7)

        ttk.Label(
            self.tab_offline,
            text="支持：GG 地址列表 / 指针路径文本、本工具 JSON。建议导入 2～3 份重启后的指针结果做交叉。",
            style="Hint.TLabel",
        ).pack(anchor=tk.W)

        self.file_list = tk.Listbox(
            self.tab_offline,
            height=8,
            bg=THEME["surface"],
            fg=THEME["text"],
            selectbackground=THEME["accent_soft"],
            font=FONTS["mono"],
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.file_list.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

    def _build_online(self) -> None:
        frida_tip = "已安装" if frida_available() else '未安装（pip install -e ".[online]"）'
        tip = f"在 GG 确认「改了界面会动」后，把地址填到这里。 Frida：{frida_tip}"
        ttk.Label(self.tab_online, text=tip, style="Hint.TLabel").pack(anchor=tk.W)

        form = ttk.LabelFrame(self.tab_online, text="在线搜链", padding=12)
        form.pack(fill=tk.X, pady=12)
        ttk.Label(form, text="包名").grid(row=0, column=0, sticky=tk.W, padx=(0, 6), pady=4)
        ttk.Entry(form, textvariable=self.package_var, width=36).grid(row=0, column=1, sticky=tk.W, pady=4)
        ttk.Label(form, text="生效地址").grid(row=1, column=0, sticky=tk.W, padx=(0, 6), pady=4)
        ttk.Entry(form, textvariable=self.address_var, width=24).grid(row=1, column=1, sticky=tk.W, pady=4)
        ttk.Label(form, text="如 0x7E33D6FC").grid(row=1, column=2, sticky=tk.W, padx=8)

        ttk.Button(
            self.tab_online, text="开始在线搜索", style="Accent.TButton", command=self._run_online
        ).pack(anchor=tk.W, pady=8)
        ttk.Label(
            self.tab_online,
            text="需要：雷电已开 USB 调试 / adb devices 可见，且 frida-server 在模拟器中运行。",
            style="Hint.TLabel",
        ).pack(anchor=tk.W)

    def _build_results(self, parent: ttk.Frame) -> None:
        box = ttk.LabelFrame(parent, text="分析结果", padding=8)
        box.pack(fill=tk.BOTH, expand=True, pady=(12, 0))

        cols = ("score", "name", "chain", "source")
        self.tree = ttk.Treeview(box, columns=cols, show="headings", height=12)
        self.tree.heading("score", text="得分")
        self.tree.heading("name", text="字段")
        self.tree.heading("chain", text="基址链")
        self.tree.heading("source", text="来源")
        self.tree.column("score", width=70, anchor=tk.CENTER)
        self.tree.column("name", width=120)
        self.tree.column("chain", width=520)
        self.tree.column("source", width=140)
        sb = ttk.Scrollbar(box, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_status(self) -> None:
        bar = tk.Frame(self, bg=THEME["status_bg"], height=32)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        tk.Label(
            bar,
            textvariable=self.status_var,
            bg=THEME["status_bg"],
            fg=THEME["status_fg"],
            font=FONTS["small"],
            anchor=tk.W,
            padx=16,
        ).pack(side=tk.LEFT, fill=tk.Y)
        self.pb = ttk.Progressbar(bar, variable=self.progress_var, maximum=100, length=160)
        self.pb.pack(side=tk.RIGHT, padx=16, pady=6)

    def _add_files(self) -> None:
        paths = filedialog.askopenfilenames(
            filetypes=[
                ("GG / JSON", "*.txt *.log *.json *.csv"),
                ("All", "*.*"),
            ]
        )
        for p in paths:
            path = Path(p)
            if path not in self._files:
                self._files.append(path)
                self.file_list.insert(tk.END, str(path))
        self.status_var.set(f"已添加 {len(self._files)} 个文件")

    def _clear_files(self) -> None:
        self._files.clear()
        self.file_list.delete(0, tk.END)

    def _cfg(self) -> AnalyzeConfig:
        return AnalyzeConfig(
            game_name=self.game_var.get().strip() or "game",
            android_package=self.package_var.get().strip(),
            pointer_size=int(self.pointer_size_var.get()),
            cross_min=int(self.cross_min_var.get()),
        ).validate()

    def _fill_tree(self, result: AnalyzeResult) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, c in enumerate(result.chains, 1):
            self.tree.insert(
                "",
                tk.END,
                values=(f"{c.score:.1f}", c.export_name(i), c.display(), c.source),
            )

    def _run_analyze(self) -> None:
        if not self._files:
            messagebox.showwarning("提示", "请先添加 GG 导出文件")
            return
        self.progress_var.set(20)
        self.status_var.set("正在分析…")

        def work() -> None:
            try:
                result = analyze_files([str(p) for p in self._files], self._cfg())
                self.after(0, lambda: self._on_done(result, "离线分析完成"))
            except Exception as e:
                self.after(0, lambda: self._on_fail(e))

        threading.Thread(target=work, daemon=True).start()

    def _run_online(self) -> None:
        pkg = self.package_var.get().strip()
        addr_s = self.address_var.get().strip()
        if not pkg or not addr_s:
            messagebox.showwarning("提示", "请填写包名与生效地址")
            return
        if not frida_available():
            messagebox.showerror("缺少依赖", '请先安装: pip install -e ".[online]"')
            return
        try:
            addr = int(addr_s, 0)
        except ValueError:
            messagebox.showerror("地址无效", addr_s)
            return

        self.progress_var.set(15)
        self.status_var.set("Frida 在线搜索中…")

        def work() -> None:
            try:
                cfg = self._cfg()
                chains = online_search_chains(pkg, addr, cfg)
                ranked = filter_and_rank(chains, cfg)
                result = AnalyzeResult(
                    chains=ranked,
                    meta={"mode": "online", "address": hex(addr), "raw": len(chains)},
                    warnings=[] if ranked else ["未找到候选链"],
                )
                self.after(0, lambda: self._on_done(result, f"在线搜索完成 · 原始 {len(chains)} 条"))
            except Exception as e:
                self.after(0, lambda: self._on_fail(e))

        threading.Thread(target=work, daemon=True).start()

    def _on_done(self, result: AnalyzeResult, msg: str) -> None:
        self._result = result
        self._fill_tree(result)
        self.progress_var.set(100)
        warn = f" · 警告 {len(result.warnings)}" if result.warnings else ""
        self.status_var.set(f"{msg} · {len(result.chains)} 条链{warn}")
        if result.warnings:
            messagebox.showinfo("完成（含警告）", "\n".join(result.warnings[:12]))

    def _on_fail(self, e: Exception) -> None:
        self.progress_var.set(0)
        self.status_var.set("失败")
        messagebox.showerror("错误", str(e))

    def _export(self) -> None:
        if not self._result or not self._result.chains:
            messagebox.showwarning("提示", "没有可导出的链，请先分析")
            return
        folder = filedialog.askdirectory(initialdir=str(OUT_DEFAULT))
        if not folder:
            return
        cfg = self._cfg()
        files = export_all(
            self._result,
            folder,
            game=cfg.game_name,
            package=cfg.android_package or "com.example.game",
        )
        self.status_var.set(f"已导出 {len(files)} 个文件")
        messagebox.showinfo("导出完成", "\n".join(str(p) for p in files))


def run_app() -> None:
    OUT_DEFAULT.mkdir(parents=True, exist_ok=True)
    app = App()
    app.mainloop()
