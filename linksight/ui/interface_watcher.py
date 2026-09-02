"""Link-state and interface watcher — polls for link-state and IP changes."""

from __future__ import annotations

from typing import Callable
from PySide6.QtCore import QObject, QTimer, Signal

from ..capture.interfaces import list_interfaces, NetInterface


class InterfaceWatcher(QObject):
    """Monitors network interfaces for link flaps, IP acquisitions, and adapter additions/removals.

    Signals:
        interfaces_changed(list[NetInterface]): Emitted when any link-state, IP, or adapter set changes.
        capture_restart_needed(str): Emitted when the active capture interface
            recovered from a DOWN state (debounced by ~2 consecutive ticks) or vanished.
    """

    interfaces_changed = Signal(object)  # list[NetInterface]
    capture_restart_needed = Signal(str)  # interface name (or "" if vanished)

    def __init__(
        self,
        active_interface: str = "",
        state_provider: Callable[[], list[NetInterface]] | None = None,
        poll_interval_ms: int = 2000,
        parent: QObject | None = None,
    ):
        super().__init__(parent)
        self._active_interface = active_interface
        self._state_provider = state_provider or list_interfaces
        self._poll_interval_ms = poll_interval_ms

        self._last_snapshot: list[NetInterface] = []
        self._active_was_down: bool = False
        self._active_up_ticks: int = 0
        self._consecutive_up_required: int = 2

        self._timer = QTimer(self)
        self._timer.setInterval(self._poll_interval_ms)
        self._timer.timeout.connect(self.check_now)

    @property
    def active_interface(self) -> str:
        return self._active_interface

    @property
    def timer(self) -> QTimer:
        return self._timer

    def start(self) -> None:
        self._last_snapshot = self._read_state()
        active = self._find_nic(self._last_snapshot, self._active_interface)
        if active is not None:
            self._active_was_down = not active.is_up
            self._active_up_ticks = self._consecutive_up_required if active.is_up else 0
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def set_active_interface(self, name: str) -> None:
        self._active_interface = name
        active = self._find_nic(self._last_snapshot, self._active_interface)
        if active is not None:
            self._active_was_down = not active.is_up
            self._active_up_ticks = self._consecutive_up_required if active.is_up else 0
        else:
            self._active_was_down = False
            self._active_up_ticks = 0

    def set_state_provider(self, provider: Callable[[], list[NetInterface]]) -> None:
        self._state_provider = provider

    def _read_state(self) -> list[NetInterface]:
        try:
            return list(self._state_provider())
        except Exception:
            return self._last_snapshot

    @staticmethod
    def _find_nic(nics: list[NetInterface], name: str) -> NetInterface | None:
        for nic in nics:
            if nic.name == name:
                return nic
        return None

    def check_now(self) -> None:
        """Poll once for interface state changes and handle debounce logic."""
        new_snapshot = self._read_state()
        old_snapshot = self._last_snapshot

        has_change = self._has_changes(old_snapshot, new_snapshot)

        restart_needed = False
        restart_target = self._active_interface

        if self._active_interface:
            new_active = self._find_nic(new_snapshot, self._active_interface)
            if new_active is None:
                # Active interface vanished
                restart_needed = True
                restart_target = ""
            else:
                if not new_active.is_up:
                    self._active_was_down = True
                    self._active_up_ticks = 0
                else:
                    self._active_up_ticks += 1
                    if self._active_was_down and self._active_up_ticks >= self._consecutive_up_required:
                        # Debounce satisfied: stable UP for 2 consecutive ticks after being down
                        self._active_was_down = False
                        restart_needed = True
                        restart_target = new_active.name

        self._last_snapshot = new_snapshot

        if has_change:
            self.interfaces_changed.emit(new_snapshot)

        if restart_needed:
            self.capture_restart_needed.emit(restart_target)

    def _has_changes(self, old: list[NetInterface], new: list[NetInterface]) -> bool:
        if not old and new:
            return True
        old_by_name = {nic.name: nic for nic in old}
        new_by_name = {nic.name: nic for nic in new}

        if set(old_by_name.keys()) != set(new_by_name.keys()):
            return True

        for name, new_nic in new_by_name.items():
            old_nic = old_by_name.get(name)
            if old_nic is None:
                return True
            if old_nic.is_up != new_nic.is_up:
                return True
            if set(old_nic.ips) != set(new_nic.ips):
                return True

        return False
