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

from . import __version__, targets
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
        ttk.Label(top, text="Scan:", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.quick_btn = ttk.Button(top, text="Quick Scan",
                                    command=lambda: self._start_scan(targets.QUICK))
        self.quick_btn.pack(side="left", padx=(8, 4))
        self.full_btn = ttk.Button(top, text="Full Scan (all drives)",
                                   command=lambda: self._start_scan(targets.FULL))
        self.full_btn.pack(side="left", padx=4)
        self.custom_btn = ttk.Button(top, text="Custom Folder...",
                                     command=lambda: self._start_scan(targets.CUSTOM))
        self.custom_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(top, text="Stop", command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="right")
        self.update_btn = ttk.Button(top, text="Update signatures",
                                     command=self._update_signatures)
        self.update_btn.pack(side="right", padx=6)

        ttk.Label(self,
                  text="Quick = where malware hides (temp, downloads, app data, startup, "
                       "autoruns). No folder picking needed.",
                  foreground="#555").pack(fill="x", padx=8)

        opt = ttk.Frame(self)
        opt.pack(fill="x", padx=8, pady=(6, 0))
        self.heur_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Heuristics + behavior + code-signing trust",
                        variable=self.heur_var).pack(side="left")
        ttk.Label(opt, text="Skip files larger than (MiB):").pack(side="left", padx=(16, 4))
        self.maxmb_var = tk.StringVar(value="200")
        ttk.Entry(opt, textvariable=self.maxmb_var, width=7).pack(side="left")
        # Hidden state: the path/label of the active scan, for the worker + quarantine.
        self.path_var = tk.StringVar(value="")
        self._active_buttons = [self.quick_btn, self.full_btn, self.custom_btn]

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

    def _start_scan(self, profile: str):
        if self._worker and self._worker.is_alive():
            return

        if profile == targets.CUSTOM:
            d = filedialog.askdirectory(title="Choose a folder to scan")
            if not d:
                return
            roots = [Path(d)]
            label = d
        elif profile == targets.FULL:
            if not messagebox.askyesno(
                    "Full scan",
                    "A full scan walks every fixed drive and can take a long "
                    "time. Run it now?"):
                return
            roots = targets.resolve_profile(targets.FULL)
            label = f"Full scan ({len(roots)} locations)"
        else:
            roots = targets.resolve_profile(targets.QUICK)
            label = f"Quick scan ({len(roots)} locations)"

        if not roots:
            messagebox.showerror("Nothing to scan", "No scannable locations were found.")
            return

        try:
            max_mb = float(self.maxmb_var.get())
            max_bytes = int(max_mb * 1024 * 1024) if max_mb > 0 else None
        except ValueError:
            max_bytes = None

        self.path_var.set(label)
        self.tree.delete(*self.tree.get_children())
        self._detections_by_iid.clear()
        self._result = None
        self._stop_flag.clear()
        self.quar_btn.configure(state="disabled")
        self.summary_var.set("")
        self.progress.start(12)
        for b in self._active_buttons:
            b.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set(f"Scanning: {label} ... (your files are not modified)")

        self._scanner = Scanner(max_file_bytes=max_bytes,
                                enable_heuristics=self.heur_var.get())
        self._worker = threading.Thread(
            target=self._scan_worker, args=(roots,), daemon=True)
        self._worker.start()

    def _scan_worker(self, roots: list):
        counter = {"n": 0}

        def progress(path: Path):
            counter["n"] += 1
            if counter["n"] % 50 == 0:
                self._events.put(("status", f"Scanned {counter['n']:,} files... {path}"))

        try:
            result = self._scanner.scan_roots(
                roots, progress=progress,
                should_stop=self._stop_flag.is_set)
            self._events.put(("done", result))
        except Exception as e:  # last-resort guard; a scan must never crash the app
            self._events.put(("error", str(e)))

    def _stop_scan(self):
        self._stop_flag.set()
        self.status_var.set("Stopping...")

    def _update_signatures(self):
        if self._worker and self._worker.is_alive():
            return
        self.update_btn.configure(state="disabled")
        self.status_var.set("Downloading latest malware-hash feed (abuse.ch)...")

        def work():
            try:
                from .feeds import update_local_db
                count, _ = update_local_db(full=False)
                self._events.put(("update_done", count))
            except Exception as e:
                self._events.put(("update_done", f"error: {e}"))

        threading.Thread(target=work, daemon=True).start()

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
                elif kind == "update_done":
                    self.update_btn.configure(state="normal")
                    if isinstance(payload, int) and payload:
                        self.status_var.set(
                            f"Signature DB updated: {payload:,} known malware hashes "
                            f"loaded for the next scan.")
                    elif isinstance(payload, int):
                        self.status_var.set(
                            "Update failed (offline?). Existing signatures unchanged.")
                    else:
                        self.status_var.set(str(payload))
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
            f"Signed/cleared: {result.trusted_suppressed}   "
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
        for b in self._active_buttons:
            b.configure(state="normal")
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
