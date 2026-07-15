# gg-base-analyzer Implementation Plan

> **For agentic workers:** Implement task-by-task; steps use checkbox syntax.

**Goal:** Build a standalone GG export → stable pointer chain analyzer with polished GUI, Frida/Lua/JSON export, and online Frida search (P2).

**Architecture:** Parse GG text/JSON → normalize PointerChain → cross-validate + score → export. Online path: ADB+Frida upward pointer search → same pipeline. Tk GUI with refined theme.

**Tech Stack:** Python 3.11+, tkinter, optional `frida`/`frida-tools`, pytest.

## Global Constraints

- Repo: `E:\xiangmu\gg-base-analyzer`, independent of ce-base-extractor (no imports from it).
- Exports: chains.json + Frida JS + Lua required.
- GUI required, polished visual theme.
- P1 offline + P2 online in this delivery.
- Tests offline with fixtures; online features degrade gracefully if Frida missing.

---

## Task 1: Scaffold + models + parsers

- [ ] pyproject.toml, requirements, README, AGENTS.md
- [ ] models.py, parsers (gg_text, gg_json), fixtures
- [ ] tests for parsers

## Task 2: Filters + pipeline + export

- [ ] scorer, cross_validate, pipeline
- [ ] json / frida / lua / report export
- [ ] CLI `analyze`

## Task 3: Online P2

- [ ] adb helper, frida_search (optional import)
- [ ] CLI `online-search`
- [ ] unit tests with mocks

## Task 4: GUI

- [ ] theme + main window (analyze tab, online tab, results, export)
- [ ] launch scripts

## Task 5: Git + remote

- [ ] git init, initial commit
- [ ] `gh repo create` + push
