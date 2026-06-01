"""Desktop GUI (stdlib tkinter -- no third-party dependencies).

Workflow is review-first by design:
  1. Pick a folder, scan. The scan runs on a background thread so the window
     never freezes, and can be stopped at any time.
  2. Results are grouped THREAT (known-bad) > REVIEW (heuristic) > TEST. Heuristic
     findings are clearly marked "not confirmed -- review".
  3. Quarantine is a deliberate, confirmed action that only MOVES known-bad files
     into a quarantine folder (reversible). It never deletes, never touches
     heuristic-only findings, and never runs anything.
"""

from __future__ import annotations

import queue
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .models import MALWARE, PUP, SUSPICIOUS, TEST, Detection, ScanResult
from .scanner import Scanner

# Row colours per severity.
_SEV_STYLE = {
    MALWARE: ("#b00020", "THREAT"),
    PUP: ("#b00020", "THREAT"),
    SUSPICIOUS: ("#b8860b", "REVIEW"),
    TEST: ("#3a7d3a", "TEST"),
}
_SEV_ORDER = {MALWARE: 0, PUP: 0, SUSPICIOUS: 1, TEST: 2}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Antivirus Scanner v{__version__}  -- read-only, review-first")
        self.geometry("980x620")
        self.minsize(820, 520)

        self._scanner: Scanner | None = None
        self._stop_flag = threading.Event()
        self._worker: threading.Thread | None = None
        self._events: queue.Queue = queue.Queue()
        self._result: ScanResult | None = None
        self._detections_by_iid: dict[str, Detection] = {}

        self._build_ui()
        self.after(100, self._drain_events)

    # -- UI construction ----------------------------------------------------

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Folder or file:").pack(side="left")
        self.path_var = tk.StringVar(value=str(Path.home() / "Downloads"))
        self.path_entry = ttk.Entry(top, textvariable=self.path_var)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Browse...", command=self._browse).pack(side="left")

        opt = ttk.Frame(self)
        opt.pack(fill="x", padx=8)
        self.heur_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Heuristics (entropy / packing / macros / scripts)",
                        variable=self.heur_var).pack(side="left")
        ttk.Label(opt, text="Skip files larger than (MiB):").pack(side="left", padx=(16, 4))
        self.maxmb_var = tk.StringVar(value="200")
        ttk.Entry(opt, textvariable=self.maxmb_var, width=7).pack(side="left")

        self.scan_btn = ttk.Button(opt, text="Scan", command=self._start_scan)
        self.scan_btn.pack(side="right")
        self.stop_btn = ttk.Button(opt, text="Stop", command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="right", padx=6)

        # Progress + status.
        prog = ttk.Frame(self)
        prog.pack(fill="x", **pad)
        self.progress = ttk.Progressbar(prog, mode="indeterminate")
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Idle. Pick a folder and press Scan. "
                                             "Scanning never modifies your files.")
        ttk.Label(prog, textvariable=self.status_var, anchor="w").pack(fill="x", pady=(4, 0))

        # Results table.
        cols = ("severity", "signature", "file", "why")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="extended")
        for c, w, txt in (
            ("severity", 90, "Severity"),
            ("signature", 230, "Detection"),
            ("file", 380, "File"),
            ("why", 480, "Why"),
        ):
            self.tree.heading(c, text=txt)
            self.tree.column(c, width=w, anchor="w")
        self.tree.tag_configure(MALWARE, foreground=_SEV_STYLE[MALWARE][0])
        self.tree.tag_configure(SUSPICIOUS, foreground=_SEV_STYLE[SUSPICIOUS][0])
        self.tree.tag_configure(TEST, foreground=_SEV_STYLE[TEST][0])

        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=6)
        yscroll.pack(side="left", fill="y", pady=6)
        self.tree.bind("<Double-1>", self._show_detail)

        # Bottom action bar.
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", **pad)
        self.summary_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=self.summary_var, anchor="w").pack(side="left")
        self.quar_btn = ttk.Button(bottom, text="Quarantine known-bad...",
                                   command=self._quarantine, state="disabled")
        self.quar_btn.pack(side="right")

    # -- actions ------------------------------------------------------------

    def _browse(self):
        d = filedialog.askdirectory(title="Choose a folder to scan")
        if d:
            self.path_var.set(d)

    def _start_scan(self):
        if self._worker and self._worker.is_alive():
            return
        target = self.path_var.get().strip()
        if not target or not Path(target).exists():
            messagebox.showerror("Not found", "That path does not exist.")
            return
        try:
            max_mb = float(self.maxmb_var.get())
            max_bytes = int(max_mb * 1024 * 1024) if max_mb > 0 else None
        except ValueError:
            max_bytes = None

        # Reset state.
        self.tree.delete(*self.tree.get_children())
        self._detections_by_iid.clear()
        self._result = None
        self._stop_flag.clear()
        self.quar_btn.configure(state="disabled")
        self.summary_var.set("")
        self.progress.start(12)
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        self._scanner = Scanner(max_file_bytes=max_bytes,
                                enable_heuristics=self.heur_var.get())
        self._worker = threading.Thread(
            target=self._scan_worker, args=(target,), daemon=True)
        self._worker.start()

    def _scan_worker(self, target: str):
        counter = {"n": 0}

        def progress(path: Path):
            counter["n"] += 1
            if counter["n"] % 25 == 0:
                self._events.put(("status", f"Scanned {counter['n']:,} files... {path}"))

        try:
            result = self._scanner.scan_path(
                target, progress=progress,
                should_stop=self._stop_flag.is_set)
            self._events.put(("done", result))
        except Exception as e:  # last-resort guard; a scan must never crash the app
            self._events.put(("error", str(e)))

    def _stop_scan(self):
        self._stop_flag.set()
        self.status_var.set("Stopping...")

    def _drain_events(self):
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "status":
                    self.status_var.set(payload)
                elif kind == "done":
                    self._on_done(payload)
                elif kind == "error":
                    self._finish_ui()
                    messagebox.showerror("Scan error", payload)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _on_done(self, result: ScanResult):
        self._result = result
        self._finish_ui()

        ordered = sorted(result.detections, key=lambda d: _SEV_ORDER.get(d.severity, 9))
        for d in ordered:
            label = _SEV_STYLE.get(d.severity, ("", d.severity))[1]
            iid = self.tree.insert(
                "", "end",
                values=(label, d.signature, str(d.path), d.description),
                tags=(d.severity,))
            self._detections_by_iid[iid] = d

        self.summary_var.set(
            f"Scanned {result.files_scanned:,} files / {result.bytes_scanned:,} bytes.   "
            f"Threats: {len(result.known_bad)}   "
            f"Review: {len(result.suspicious)}   "
            f"Test: {len(result.test_hits)}   "
            f"Skipped: {len(result.skipped)}")

        if result.known_bad:
            self.quar_btn.configure(state="normal")
            self.status_var.set("Done. KNOWN-BAD files found -- review them, then quarantine if you choose.")
        elif result.suspicious:
            self.status_var.set("Done. Heuristic flags to review (not confirmed malware).")
        else:
            self.status_var.set("Done. Nothing flagged. Files were not modified.")

    def _finish_ui(self):
        self.progress.stop()
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _show_detail(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        d = self._detections_by_iid.get(sel[0])
        if not d:
            return
        msg = (f"Detection: {d.signature}\n"
               f"Severity:  {d.severity}\n"
               f"Method:    {d.method}\n\n"
               f"File:\n{d.path}\n\n"
               f"Why:\n{d.description}\n")
        if d.evidence:
            msg += f"\nEvidence:\n{d.evidence}\n"
        if d.severity == SUSPICIOUS:
            msg += ("\nThis is a HEURISTIC signal, not a confirmed virus. "
                    "Review the file or check it against another scanner before acting.")
        messagebox.showinfo("Detection detail", msg)

    def _quarantine(self):
        if not self._result or not self._result.known_bad:
            return
        targets = []
        seen = set()
        for d in self._result.known_bad:
            if d.path not in seen and Path(d.path).exists():
                seen.add(d.path)
                targets.append(d)
        if not targets:
            messagebox.showinfo("Quarantine", "No known-bad files remain to quarantine.")
            return

        qdir = Path.home() / "Antivirus_Quarantine"
        listing = "\n".join(f"  {d.path}" for d in targets)
        ok = messagebox.askyesno(
            "Confirm quarantine",
            f"MOVE {len(targets)} known-bad file(s) into:\n{qdir}\n\n"
            f"This is reversible -- files are moved, not deleted. "
            f"Heuristic-only findings are not included.\n\n{listing}\n\nProceed?")
        if not ok:
            return

        qdir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        moved, failed = 0, []
        for d in targets:
            try:
                dest = qdir / f"{stamp}__{d.signature}__{Path(d.path).name}"
                shutil.move(str(d.path), str(dest))
                moved += 1
            except OSError as e:
                failed.append(f"{d.path}: {e}")
        msg = f"Moved {moved} file(s) to {qdir}."
        if failed:
            msg += "\n\nFailed:\n" + "\n".join(failed)
        messagebox.showinfo("Quarantine complete", msg)
        self.quar_btn.configure(state="disabled")
        self.status_var.set(f"Quarantined {moved} file(s) to {qdir} (reversible).")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
