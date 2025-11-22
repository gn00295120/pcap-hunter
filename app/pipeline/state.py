from __future__ import annotations

import time
from typing import Optional

import streamlit as st

from app.utils.common import make_slug


def ss_init(key, default):
    if key not in st.session_state:
        st.session_state[key] = default
    return st.session_state[key]

def reset_run_state(phase_titles):
    st.session_state["run_active"] = True
    st.session_state["run_started_at"] = time.time()
    for t in phase_titles:
        slug = make_slug(t)
        st.session_state[f"skip_{slug}"] = False
        st.session_state[f"done_{slug}"] = False

def is_run_active() -> bool:
    return st.session_state.get("run_active", False)

def end_run():
    st.session_state["run_active"] = False

class PhaseTracker:
    def __init__(self, total_phases: int, progress_container: Optional[st.delta_generator.DeltaGenerator] = None):
        self.total_phases = max(total_phases, 1)
        self.done_phases = 0
        self._pc = progress_container or st
        with self._pc:
            self.overall_bar = st.progress(0)
            self.overall_text = st.empty()

    def update_overall(self, label: str = ""):
        pct = int(min(self.done_phases / self.total_phases, 1.0) * 100)
        self.overall_bar.progress(pct)
        if label:
            self.overall_text.write(f"Overall progress: {pct}% — {label}")

    def next_phase(self, title: str):
        with self._pc:
            st.caption(title)
            # Safe CSS hook wrapper (no .classes() calls)
            st.markdown('<div class="phase-row">', unsafe_allow_html=True)
            cols = st.columns([5, 1.1])
            with cols[0]:
                bar = st.progress(0)
                text = st.empty()
            with cols[1]:
                slug = make_slug(title)
                skip_key = f"skip_{slug}"
                ss_init(skip_key, False)
                done_key = f"done_{slug}"
                ss_init(done_key, False)
                st.button(
                    "Skip",
                    key=f"btn_{slug}",
                    width='stretch',
                    on_click=lambda: st.session_state.__setitem__(skip_key, True),
                )
            st.markdown('</div>', unsafe_allow_html=True)
        return PhaseHandle(self, bar, text, title, slug, skip_key, done_key)

    def mark_phase_done(self, phase_title: str, skipped: bool = False):
        self.done_phases += 1
        self.update_overall(("Skipped" if skipped else "Completed") + f": {phase_title}")

class PhaseHandle:
    def __init__(self, tracker, bar, text, title, slug, skip_key, done_key):
        self.tracker = tracker
        self.bar = bar
        self.text = text
        self.title = title
        self.slug = slug
        self.skip_key = skip_key
        self.done_key = done_key
        self._last_pct = -1

    def should_skip(self) -> bool:
        return st.session_state.get(self.skip_key, False)

    def is_done(self) -> bool:
        return st.session_state.get(self.done_key, False)

    def _set_done_flag(self):
        st.session_state[self.done_key] = True

    def set(self, pct: float, msg: str = ""):
        if self.is_done():
            return
        if self.should_skip():
            self.text.write("Skipping on user request…")
            return
        pct = int(max(0, min(100, pct)))
        if pct != self._last_pct:
            self.bar.progress(pct)
            self._last_pct = pct
        if msg:
            self.text.write(msg)

    def done(self, msg: str = "Done"):
        if not self.is_done():
            skipped = False
            if not self.should_skip():
                self.set(100, msg)
            else:
                skipped = True
                self.text.write("Skipped by user.")
                self.bar.progress(100)
            self._set_done_flag()
            self.tracker.mark_phase_done(self.title, skipped=skipped)
