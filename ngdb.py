#!/usr/bin/env python3
"""N-gdb: WinDbg-style GDB graphical debugger."""

import os
import re
import json
import subprocess
import sys
import threading
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from queue import Queue, Empty
from collections import OrderedDict


def _unescape_mi_string(text):
    """Unescape GDB/MI C-string escapes: \\, \n, \t, \r, \"
    Single-pass character-by-character to avoid order-dependent bugs."""
    result = []
    byte_buf = bytearray()

    def flush_bytes():
        nonlocal byte_buf
        if byte_buf:
            result.append(byte_buf.decode('utf-8', errors='replace'))
            byte_buf = bytearray()

    i = 0
    while i < len(text):
        if text[i] == '\\' and i + 1 < len(text):
            c = text[i + 1]
            if c in '01234567':
                j = i + 1
                digits = []
                while j < len(text) and len(digits) < 3 and text[j] in '01234567':
                    digits.append(text[j])
                    j += 1
                byte_buf.append(int(''.join(digits), 8))
                i = j
                continue
            flush_bytes()
            if c == 'n':
                result.append('\n')
            elif c == 't':
                result.append('\t')
            elif c == 'r':
                result.append('\r')
            elif c == '"':
                result.append('"')
            elif c == '\\':
                result.append('\\')
            else:
                result.append('\\')
                result.append(c)
            i += 2
        else:
            flush_bytes()
            result.append(text[i])
            i += 1
    flush_bytes()
    return ''.join(result)


class GDBMiClient:
    """Manages GDB subprocess communication via MI protocol."""

    def __init__(self, output_queue):
        self.process = None
        self.token_counter = 0
        self.output_queue = output_queue
        self.pending = {}
        self._pending_lock = threading.Lock()
        self._reader_thread = None
        self._running = False
        self._user_stopped = False

    def start(self):
        if self.process and self.process.poll() is None:
            return
        self.process = subprocess.Popen(
            ['gdb', '--interpreter=mi'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self._running = True
        self._user_stopped = False
        self._reader_thread = threading.Thread(
            target=self._reader_loop, daemon=True
        )
        self._reader_thread.start()

    def stop(self):
        self._running = False
        self._user_stopped = True
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=3)
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                self.process.kill()
            self.process = None

    def send_cmd(self, mi_cmd, callback=None):
        self.token_counter += 1
        token = self.token_counter
        if callback:
            with self._pending_lock:
                self.pending[token] = callback
        line = f"{token}{mi_cmd}\n"
        try:
            self.process.stdin.write(line.encode())
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            self.output_queue.put(('status', {'state': 'error', 'msg': 'GDB process died'}))
        return token

    def send_raw(self, cmd):
        escaped = cmd.replace('\\', '\\\\').replace('"', '\\"')
        return self.send_cmd(f'-interpreter-exec console "{escaped}"')

    def _reader_loop(self):
        buffer = ""
        while self._running:
            try:
                data = self.process.stdout.read(4096)
                if not data:
                    break
                buffer += data.decode('utf-8', errors='replace')
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if line:
                        record = self._parse_mi_line(line)
                        if record:
                            self._dispatch(record)
            except OSError:
                break
        self._running = False
        if not self._user_stopped:
            self.output_queue.put(('status', {'state': 'exited'}))

    @staticmethod
    def _parse_mi_line(line):
        if not line:
            return None

        if line == '(gdb)':
            return {'type': 'prompt', 'token': None, 'cls': None, 'payload': ''}

        token = None
        rest = line

        m = re.match(r'^(\d+)(.*)', rest)
        if m:
            token = int(m.group(1))
            rest = m.group(2)

        if rest.startswith('^'):
            cls_name = ''
            i = 1
            while i < len(rest) and rest[i] not in (',', '\n'):
                cls_name += rest[i]
                i += 1
            payload = rest[i+1:] if i < len(rest) and rest[i] == ',' else ''
            return {'type': 'result', 'token': token, 'cls': cls_name, 'payload': payload}

        if rest.startswith('*'):
            cls_name = ''
            i = 1
            while i < len(rest) and rest[i] not in (',', '\n'):
                cls_name += rest[i]
                i += 1
            payload = rest[i+1:] if i < len(rest) and rest[i] == ',' else ''
            return {'type': 'exec_async', 'token': token, 'cls': cls_name, 'payload': payload}

        if rest.startswith('='):
            cls_name = ''
            i = 1
            while i < len(rest) and rest[i] not in (',', '\n'):
                cls_name += rest[i]
                i += 1
            payload = rest[i+1:] if i < len(rest) and rest[i] == ',' else ''
            return {'type': 'notify_async', 'token': token, 'cls': cls_name, 'payload': payload}

        if rest.startswith('+'):
            cls_name = ''
            i = 1
            while i < len(rest) and rest[i] not in (',', '\n'):
                cls_name += rest[i]
                i += 1
            return {'type': 'status_async', 'token': token, 'cls': cls_name, 'payload': ''}

        if rest.startswith('~'):
            text = rest[1:]
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1]
                text = _unescape_mi_string(text)
            return {'type': 'console', 'token': None, 'cls': None, 'payload': text}
        if rest.startswith('@'):
            text = rest[1:]
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1]
                text = _unescape_mi_string(text)
            return {'type': 'target', 'token': None, 'cls': None, 'payload': text}
        if rest.startswith('&'):
            text = rest[1:]
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1]
                text = _unescape_mi_string(text)
            return {'type': 'log', 'token': None, 'cls': None, 'payload': text}

        return None

    def _dispatch(self, record):
        rtype = record['type']
        token = record.get('token')

        with self._pending_lock:
            cb = self.pending.pop(token, None) if token else None

        if cb:
            self.output_queue.put((rtype, record, cb))
        else:
            self.output_queue.put((rtype, record))


def parse_mi_tuple(text):
    result = {}
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] in ' ,':
            i += 1
        if i >= n:
            break
        key_start = i
        while i < n and text[i] not in '=,':
            i += 1
        key = text[key_start:i].strip()
        if i >= n or text[i] != '=':
            if key:
                result[key] = True
            i += 1
            continue
        i += 1
        if i >= n:
            break
        if text[i] == '"':
            i += 1
            val_start = i
            while i < n and text[i] != '"':
                if text[i] == '\\':
                    i += 1
                i += 1
            val = text[val_start:i]
            val = _unescape_mi_string(val)
            i += 1
            result[key] = val
        elif text[i] == '{':
            depth = 1
            i += 1
            val_start = i
            while i < n and depth > 0:
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                i += 1
            result[key] = parse_mi_tuple(text[val_start:i-1])
        elif text[i] == '[':
            depth = 1
            i += 1
            val_start = i
            while i < n and depth > 0:
                if text[i] == '[':
                    depth += 1
                elif text[i] == ']':
                    depth -= 1
                i += 1
            result[key] = text[val_start:i-1]
        else:
            val_start = i
            while i < n and text[i] not in ',}':
                i += 1
            result[key] = text[val_start:i].strip()
    return result


def parse_mi_list(text):
    items = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] in ' ,':
            i += 1
        if i >= n:
            break
        if text[i] == '{':
            depth = 1
            i += 1
            start = i
            while i < n and depth > 0:
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                i += 1
            items.append(parse_mi_tuple(text[start:i-1]))
        else:
            start = i
            while i < n and text[i] != ',':
                i += 1
            val = text[start:i].strip()
            if val:
                items.append(val)
        i += 1
    return items


class DebugState:
    """Holds all debugger state: registers, breakpoints, frames, threads, disassembly."""

    def __init__(self):
        self.target_path = None
        self.running = False
        self.pid = None
        self.current_thread = None
        self.current_frame = 0
        self.pc = None

        self.registers = OrderedDict()
        self.prev_registers = OrderedDict()

        self.breakpoints = {}

        self.frames = []
        self.locals = []
        self.watches = []
        self.watch_values = {}

        self.threads = []
        self.disassembly = []
        self.libraries = []
        self.import_symbols = []
        self.pc_history = []
        self.pc_history_index = -1

        self.memory_data = {}
        self.memory_start_addr = None
        self.memory_maps = []

    def update_registers(self, reg_list):
        self.prev_registers = OrderedDict(self.registers)
        self.registers.clear()
        for item in reg_list:
            name = item.get('name', '')
            val = item.get('value', '')
            self.registers[name] = val

    def changed_registers(self):
        changed = set()
        for name, val in self.registers.items():
            if name not in self.prev_registers or self.prev_registers[name] != val:
                changed.add(name)
        return changed

    def update_breakpoints(self, bp_list):
        for bp in bp_list:
            num = bp.get('number', '')
            self.breakpoints[num] = {
                'addr': bp.get('addr', ''),
                'enabled': bp.get('enabled', 'y') == 'y',
                'hits': bp.get('times', '0'),
                'cond': bp.get('cond', ''),
                'file': bp.get('file', ''),
                'line': bp.get('line', ''),
                'fullname': bp.get('fullname', ''),
                'func': bp.get('func', ''),
                'original_location': bp.get('original-location', bp.get('original_location', '')),
                'locations': self._parse_breakpoint_locations(bp),
            }

    def _parse_breakpoint_locations(self, bp):
        raw_locations = bp.get('locations', bp.get('location', []))
        if isinstance(raw_locations, str):
            locations = parse_mi_list(raw_locations)
        elif isinstance(raw_locations, (list, tuple)):
            locations = raw_locations
        else:
            locations = []

        parsed = []
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            parsed.append({
                'number': loc.get('number', loc.get('id', '')),
                'addr': loc.get('addr', ''),
                'enabled': loc.get('enabled', 'y') == 'y',
                'func': loc.get('func', ''),
                'file': loc.get('file', ''),
                'line': loc.get('line', ''),
                'fullname': loc.get('fullname', ''),
            })
        return parsed

    def remove_breakpoint(self, num):
        self.breakpoints.pop(num, None)

    def update_frames(self, frame_list):
        self.frames = frame_list

    def update_threads(self, thread_list):
        self.threads = thread_list

    def update_disassembly(self, asm_list):
        self.disassembly = asm_list

    def remember_pc(self, pc):
        pc = (pc or '').strip()
        if not pc:
            return
        if self.pc_history_index >= 0 and self.pc_history_index < len(self.pc_history) - 1:
            self.pc_history = self.pc_history[:self.pc_history_index + 1]
        if self.pc_history and self.pc_history[-1] == pc:
            self.pc_history_index = len(self.pc_history) - 1
            return
        self.pc_history.append(pc)
        if len(self.pc_history) > 256:
            self.pc_history = self.pc_history[-256:]
        self.pc_history_index = len(self.pc_history) - 1

    def previous_pc(self):
        if self.pc_history_index <= 0:
            return None
        self.pc_history_index -= 1
        return self.pc_history[self.pc_history_index]


class ConsolePanel(tk.Frame):
    """GDB command input/output console."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app

        # Output text
        self.output = tk.Text(self, wrap=tk.WORD, font=app.font,
                              bg=app.colors['code_bg'], fg=app.colors['fg'],
                              insertbackground=app.colors['fg'],
                              selectbackground=app.colors['select'],
                              selectforeground=app.colors['fg'],
                              state=tk.DISABLED, bd=0, padx=8, pady=6)
        scroll = tk.Scrollbar(self, command=self.output.yview)
        self.output.config(yscrollcommand=scroll.set)

        # Input frame
        input_frame = tk.Frame(self, bg=app.colors['surface'])
        ttk.Label(input_frame, text="(gdb) ", font=app.font,
                  style='Prompt.TLabel').pack(side=tk.LEFT, padx=(8, 2))
        self.input = ttk.Entry(input_frame, font=app.font, style='Compact.TEntry')
        self.input.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=(0, 8), pady=6)
        self.input.bind('<Return>', self._on_submit)
        self.input.state(['disabled'])

        # Grid: row 0 = output + scrollbar, row 1 = input (spans both columns)
        self.output.grid(row=0, column=0, sticky='nsew')
        scroll.grid(row=0, column=1, sticky='ns')
        input_frame.grid(row=1, column=0, columnspan=2, sticky='ew')

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._history = []
        self._history_idx = -1
        self.input.bind('<Up>', self._history_up)
        self.input.bind('<Down>', self._history_down)

    def _on_submit(self, event=None):
        cmd = self.input.get().strip()
        if not cmd:
            return
        self.append_output(f"(gdb) {cmd}\n")
        self._history.append(cmd)
        self._history_idx = len(self._history)
        self.input.delete(0, tk.END)

        # Intercept commands that should update UI panels
        if not self._try_intercept(cmd):
            self.app.gdb.send_raw(cmd)

    def _history_up(self, event=None):
        if self._history_idx > 0:
            self._history_idx -= 1
            self.input.delete(0, tk.END)
            self.input.insert(0, self._history[self._history_idx])
        return 'break'

    def _history_down(self, event=None):
        if self._history_idx < len(self._history) - 1:
            self._history_idx += 1
            self.input.delete(0, tk.END)
            self.input.insert(0, self._history[self._history_idx])
        elif self._history_idx == len(self._history) - 1:
            self._history_idx = len(self._history)
            self.input.delete(0, tk.END)
        return 'break'

    def append_output(self, text):
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def show_prompt(self):
        pass

    def clear(self):
        self.output.config(state=tk.NORMAL)
        self.output.delete('1.0', tk.END)
        self.output.config(state=tk.DISABLED)

    def _try_intercept(self, cmd):
        """Intercept GDB commands that should update UI panels.
        Returns True if handled (don't send as raw)."""
        parts = cmd.split()
        if not parts:
            return False
        base = parts[0]

        # Commands that change PC and should refresh disassembly
        # j/jump addr, until addr, advance addr
        if base in ('j', 'jump') and len(parts) >= 2:
            self.app.gdb.send_raw(cmd)
            self._refresh_after_pc_change(parts[1])
            return True

        if base in ('until', 'advance', 'u') and len(parts) >= 2:
            self.app.gdb.send_raw(cmd)
            self._refresh_after_pc_change(parts[1])
            return True

        # x/Nx addr — examine memory, show in memory panel
        if base.startswith('x'):
            return self._intercept_examine(cmd, parts)

        # set $pc = addr
        if base == 'set' and len(parts) >= 3 and parts[1] == '$pc':
            self.app.gdb.send_raw(cmd)
            self._refresh_after_pc_change(parts[-1])
            return True

        return False

    def _refresh_after_pc_change(self, addr_str):
        """After a jump/set pc, refresh disassembly around the new address."""
        addr_str = addr_str.lstrip('*')
        try:
            a = int(addr_str, 16)
            s, e = hex(max(0, a - 64)), hex(a + 128)
        except ValueError:
            s, e = addr_str, f'"{addr_str}+100"'
        self.app.gdb.send_cmd(
            f'-data-disassemble -s {s} -e {e} -- 0',
            callback=self.app._on_disasm)
        # Also refresh registers to show updated PC
        self.app.gdb.send_cmd('-data-list-register-values x',
                              callback=self.app._on_register_values)

    def _intercept_examine(self, cmd, parts):
        """Handle x/Nx addr command — display in memory panel."""
        # Parse: x/Nuf addr  (N=count, u=unit, f=format)
        # e.g. x/64xb 0x400000, x/16xw 0x7ffffff
        import re as _re
        m = _re.match(r'x/(\d+)?([bhwg])?([xo])?\s+(.+)', cmd)
        if not m:
            return False
        count_str, unit, fmt, addr = m.groups()
        count = int(count_str) if count_str else 16
        # unit size: b=1, h=2, w=4, g=8
        unit_size = {'b': 1, 'h': 2, 'w': 4, 'g': 8}.get(unit, 1)
        total_bytes = count * unit_size
        addr = addr.strip()
        try:
            start_int = int(addr, 16)
        except ValueError:
            return False

        # Show in memory panel
        self.app.mem_panel.addr_entry.delete(0, tk.END)
        self.app.mem_panel.addr_entry.insert(0, addr)
        self.app.mem_panel._mem_start_int = start_int
        self.app.mem_panel._mem_end_int = start_int + total_bytes
        self.app.mem_panel._scroll_to_addr = None
        self.app.mem_panel._fetch_current_range()
        return True


class DisassemblyPanel(tk.Frame):
    """Assembly code view with current-line highlight and breakpoint markers."""

    _EXPAND_BYTES = 256   # bytes to fetch each expansion
    _MAX_INSN = 2000      # max instructions to keep
    _PREFETCH_TOP = 0.18
    _PREFETCH_BOTTOM = 0.82
    _DISPLAY_TOP = 0.02
    _DISPLAY_BOTTOM = 0.98
    _MAX_WHEEL_UNITS = 1
    _MAX_SCROLL_FRACTION_STEP = 0.04
    _DEBUG_SHORTCUT_KEYS = {
        'F2', 'F5', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
        'Break', 'Pause',
    }

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app
        self._fetching = False
        self._scroll_to_addr = None
        self._bounds_after_id = None
        self._pending_bounds_check = False
        self._suspend_bounds_check = False
        self._top_exhausted = False
        self._bottom_exhausted = False
        self._top_cache = []
        self._bottom_cache = []
        self._display_fetch_when_done = False
        self._disasm_generation = 0

        header = tk.Frame(self, bg=app.colors['panel_header'], height=28)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        ttk.Label(header, text="Disassembly", style='Panel.TLabel'
                 ).pack(side=tk.LEFT, padx=4)
        app._add_panel_close_button(header, 'Disassembly')

        # Vertical scrollbar
        self._vscroll = tk.Scrollbar(self, orient=tk.VERTICAL, command=self._yview)
        self._vscroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Inner frame for margin + text + hscroll
        frame = tk.Frame(self, bg=app.colors['surface'])
        frame.pack(fill=tk.BOTH, expand=True)

        # Create widgets before packing
        # Margin sidebar for breakpoint markers — kept NORMAL so clicks work on Linux
        self.margin = tk.Text(frame, width=3, font=app.font,
                              bg=app.colors['panel_header'], fg=app.colors['fg'],
                              bd=0, padx=4, cursor='hand2',
                              insertwidth=0, takefocus=False,
                              selectbackground=app.colors['panel_bg'])

        # Main text for assembly — kept NORMAL so clicks work on Linux
        self.text = tk.Text(frame, wrap=tk.NONE, font=app.font,
                            bg=app.colors['code_bg'], fg=app.colors['fg'],
                            bd=0, padx=4, cursor='arrow',
                            insertwidth=0, takefocus=False,
                            selectbackground=app.colors['select'],
                            selectforeground=app.colors['fg'])

        self._hscroll = tk.Scrollbar(frame, orient=tk.HORIZONTAL,
                                     command=self.text.xview)

        # Pack in order: hscroll bottom, margin left, text expand
        self._hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.margin.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scroll connections
        self.text.config(xscrollcommand=self._hscroll.set,
                         yscrollcommand=self._on_text_yscroll)

        # Tags
        self.text.tag_configure('current', background=app.colors['highlight'])
        self.text.tag_configure('goto', background=app.colors['goto_highlight'])
        self.text.tag_configure('ctx_selected', background='#0A3069', foreground='#FFFFFF')
        self._goto_addr_int = None
        self.margin.tag_configure('bp_marker', foreground=app.colors['bp_marker'],
                                  font=app.font_bold)
        self.margin.tag_configure('bp_marker_disabled', foreground='#DAA520',
                                  font=app.font_bold)
        self.margin.tag_configure('ctx_selected', background='#0A3069', foreground='#FFFFFF')

        # Block editing but allow copy/select shortcuts
        for w in (self.margin, self.text):
            w.bind('<Key>', self._block_edit)
            w.bind('<Escape>', self._on_escape)
            w.bind('<Button-2>', lambda e: 'break')

        # Ctrl+G go to address
        for w in (self.margin, self.text):
            w.bind('<Control-g>', lambda e: self.app._goto_address())
            w.bind('<Control-G>', lambda e: self.app._goto_address())

        # Click bindings — only margin sidebar toggles breakpoints
        self.margin.bind('<Button-1>', self._on_click)
        self.text.bind('<Button-1>', self._clear_context_selection)
        self.margin.bind('<B1-Motion>', lambda e: 'break')
        self.margin.bind('<Button-3>', self._on_right_click)
        self.text.bind('<Button-3>', self._on_right_click)

        # Right-click context menu
        self._ctx_menu = self.app._make_menu(self)
        self._ctx_addr = None
        self._ctx_insn = None

        # Mouse wheel — scroll and check bounds for dynamic loading
        for w in (self.margin, self.text):
            w.bind('<MouseWheel>', self._on_mousewheel)
            w.bind('<Button-4>', self._on_mousewheel)
            w.bind('<Button-5>', self._on_mousewheel)

    def _block_edit(self, event):
        if event.keysym in self._DEBUG_SHORTCUT_KEYS:
            return None
        if event.state & 0x4 and event.keysym in ('c', 'a', 'g', 'G'):
            return  # allow Ctrl+C copy, Ctrl+A select all, Ctrl+G go to address
        return 'break'

    def _on_escape(self, event=None):
        return self.app._navigate_execution_history_back(event)

    def _wheel_scroll_units(self, event):
        if getattr(event, 'num', None) == 4:
            return -1
        if getattr(event, 'num', None) == 5:
            return 1
        delta = getattr(event, 'delta', 0)
        if not delta:
            return 0
        return -1 if event.delta > 0 else 1

    def _on_mousewheel(self, event):
        units = self._wheel_scroll_units(event)
        units = max(-self._MAX_WHEEL_UNITS, min(self._MAX_WHEEL_UNITS, units))
        if units:
            self.text.yview_scroll(units, 'units')
        self._schedule_bounds_check()
        return 'break'

    def _schedule_bounds_check(self, delay=35):
        if self._suspend_bounds_check:
            return
        self._cancel_bounds_check()
        self._bounds_after_id = self.after(delay, self._run_scheduled_bounds_check)

    def _cancel_bounds_check(self):
        if self._bounds_after_id is not None:
            try:
                self.after_cancel(self._bounds_after_id)
            except tk.TclError:
                pass
            self._bounds_after_id = None

    def _run_scheduled_bounds_check(self):
        self._bounds_after_id = None
        self._check_bounds()

    def _check_bounds(self):
        if self._suspend_bounds_check:
            return
        if self._fetching:
            self._pending_bounds_check = True
            return
        if not self.app.state.disassembly:
            return
        first, last = self.text.yview()
        if first <= self._DISPLAY_TOP:
            if self._show_cached_up():
                self._expand_up()
            elif not self._top_exhausted:
                self._display_fetch_when_done = True
                self._expand_up()
            return
        elif first <= self._PREFETCH_TOP and not self._top_cache and not self._top_exhausted:
            self._display_fetch_when_done = False
            self._expand_up()
            return

        if last >= self._DISPLAY_BOTTOM:
            if self._show_cached_down():
                self._expand_down()
            elif not self._bottom_exhausted:
                self._display_fetch_when_done = True
                self._expand_down()
        elif last >= self._PREFETCH_BOTTOM and not self._bottom_cache and not self._bottom_exhausted:
            self._display_fetch_when_done = False
            self._expand_down()

    def _expand_up(self):
        if self._fetching:
            self._pending_bounds_check = True
            return
        disasm = self.app.state.disassembly
        if not disasm:
            return
        try:
            top_addr = int(disasm[0]['addr'], 16)
        except (ValueError, TypeError):
            return
        if top_addr <= 0:
            self._top_exhausted = True
            return
        new_start = hex(max(0, top_addr - self._EXPAND_BYTES))
        new_end = hex(top_addr)
        generation = self._disasm_generation
        self._fetching = True
        self._pending_bounds_check = False
        self.app.gdb.send_cmd(
            f'-data-disassemble -s {new_start} -e {new_end} -- 0',
            callback=lambda r, g=generation: self._on_expand_up_done(r, g))

    def _parse_disasm_insns(self, payload):
        m = re.search(r'asm_insns=\[(.+)\]', payload, re.DOTALL)
        if not m:
            return []
        insns = []
        for item in parse_mi_list(m.group(1)):
            if isinstance(item, dict):
                insns.append({
                    'addr': item.get('address', ''),
                    'asm': item.get('inst', item.get('line-inst', '')),
                    'func': item.get('func-name', ''),
                })
        return insns

    def _known_disasm_addrs(self):
        addrs = {i['addr'] for i in self.app.state.disassembly}
        addrs.update(i['addr'] for i in self._top_cache)
        addrs.update(i['addr'] for i in self._bottom_cache)
        return addrs

    def _visible_anchor_addr(self):
        try:
            line_num = int(self.text.index('@0,0').split('.')[0]) - 1
        except (tk.TclError, ValueError):
            return None
        if 0 <= line_num < len(self.app.state.disassembly):
            return self.app.state.disassembly[line_num]['addr']
        return None

    def _scroll_addr_to_top(self, addr):
        line = self._line_for_addr(addr)
        if line is None:
            return
        total = max(1, len(self.app.state.disassembly))
        fraction = max(0.0, min(1.0, (line - 1) / total))
        self.text.yview_moveto(fraction)
        self.margin.yview_moveto(fraction)

    def _show_cached_up(self):
        if not self._top_cache:
            return False
        anchor = self.app.state.disassembly[0]['addr'] if self.app.state.disassembly else None
        self.app.state.disassembly = self._top_cache + self.app.state.disassembly
        self._top_cache = []
        if len(self.app.state.disassembly) > self._MAX_INSN:
            self.app.state.disassembly = self.app.state.disassembly[:self._MAX_INSN]
        self._rebuild()
        if anchor:
            self._scroll_addr_to_top(anchor)
        return True

    def _show_cached_down(self):
        if not self._bottom_cache:
            return False
        anchor = self._visible_anchor_addr()
        self.app.state.disassembly = self.app.state.disassembly + self._bottom_cache
        self._bottom_cache = []
        if len(self.app.state.disassembly) > self._MAX_INSN:
            self.app.state.disassembly = self.app.state.disassembly[-self._MAX_INSN:]
        self._rebuild()
        if anchor:
            self._scroll_addr_to_top(anchor)
        return True

    def _cache_or_show_up(self, insns):
        prepend = [i for i in insns if i['addr'] not in self._known_disasm_addrs()]
        if not prepend:
            self._top_exhausted = True
            return
        self._top_exhausted = False
        self._top_cache = prepend
        if self._display_fetch_when_done:
            self._show_cached_up()

    def _cache_or_show_down(self, insns):
        append = [i for i in insns if i['addr'] not in self._known_disasm_addrs()]
        if not append:
            self._bottom_exhausted = True
            return
        self._bottom_exhausted = False
        self._bottom_cache = append
        if self._display_fetch_when_done:
            self._show_cached_down()

    def _on_expand_up_done(self, record, generation=None):
        self._fetching = False
        show_when_done = self._display_fetch_when_done
        self._display_fetch_when_done = False
        if generation != self._disasm_generation:
            return
        if record.get('cls') != 'done':
            return
        self._display_fetch_when_done = show_when_done
        new_insns = self._parse_disasm_insns(record.get('payload', ''))
        if not new_insns:
            self._top_exhausted = True
        else:
            self._cache_or_show_up(new_insns)
        self._display_fetch_when_done = False

    def _expand_down(self):
        if self._fetching:
            self._pending_bounds_check = True
            return
        disasm = self.app.state.disassembly
        if not disasm:
            return
        try:
            bot_addr = int(disasm[-1]['addr'], 16)
        except (ValueError, TypeError):
            return
        new_start = hex(bot_addr)
        new_end = hex(bot_addr + self._EXPAND_BYTES)
        generation = self._disasm_generation
        self._fetching = True
        self._pending_bounds_check = False
        self.app.gdb.send_cmd(
            f'-data-disassemble -s {new_start} -e {new_end} -- 0',
            callback=lambda r, g=generation: self._on_expand_down_done(r, g))

    def _on_expand_down_done(self, record, generation=None):
        self._fetching = False
        show_when_done = self._display_fetch_when_done
        self._display_fetch_when_done = False
        if generation != self._disasm_generation:
            return
        if record.get('cls') != 'done':
            return
        self._display_fetch_when_done = show_when_done
        new_insns = self._parse_disasm_insns(record.get('payload', ''))
        if not new_insns:
            self._bottom_exhausted = True
        else:
            self._cache_or_show_down(new_insns)
        self._display_fetch_when_done = False

    def _line_for_addr(self, addr):
        try:
            addr_int = int(addr, 16)
        except (ValueError, TypeError):
            return None
        for i, insn in enumerate(self.app.state.disassembly):
            try:
                if int(insn['addr'], 16) == addr_int:
                    return i + 1
            except (ValueError, TypeError):
                continue
        return None

    def _scroll_to_addr_line(self, addr):
        line = self._line_for_addr(addr)
        if line is not None:
            self.text.see(f'{line}.0')
            self.margin.see(f'{line}.0')

    def _rebuild(self):
        """Rebuild text/margin from state.disassembly preserving highlights."""
        self._suspend_bounds_check = True
        scroll_pos = self.text.yview()[0]
        self.text.delete('1.0', tk.END)
        self.margin.delete('1.0', tk.END)
        pc = self.app.state.pc
        goto_line = None
        for i, insn in enumerate(self.app.state.disassembly):
            addr = insn['addr']
            asm = insn['asm']
            bp_num = self.app._find_bp_at_addr(addr)
            if bp_num:
                bp_info = self.app.state.breakpoints[bp_num]
                if bp_info.get('enabled', True):
                    self.margin.insert(tk.END, " ●\n", 'bp_marker')
                else:
                    self.margin.insert(tk.END, " ●\n", 'bp_marker_disabled')
            else:
                self.margin.insert(tk.END, "  \n")
            if addr.startswith('0x'):
                line = f"{addr:>18s}  {asm}\n"
            else:
                line = f"0x{addr:>16s}  {asm}\n"
            tags = ()
            if addr == pc or f'0x{addr}' == pc:
                tags = ('current',)
            self.text.insert(tk.END, line, tags)
            # Track goto highlight line
            if self._goto_addr_int is not None:
                try:
                    if int(addr, 16) == self._goto_addr_int:
                        goto_line = i + 1
                except (ValueError, TypeError):
                    pass
        # Apply goto highlight after all inserts
        if goto_line:
            self.text.tag_add('goto', f'{goto_line}.0', f'{goto_line}.end')
        self.text.yview_moveto(scroll_pos)
        self.margin.yview_moveto(scroll_pos)
        self._suspend_bounds_check = False

    def clear_goto_highlight(self):
        self._goto_addr_int = None
        self.text.tag_remove('goto', '1.0', tk.END)

    def _clamped_moveto(self, requested):
        try:
            requested = float(requested)
        except (TypeError, ValueError):
            return self.text.yview()[0]
        current = self.text.yview()[0]
        if requested > current + self._MAX_SCROLL_FRACTION_STEP:
            return current + self._MAX_SCROLL_FRACTION_STEP
        if requested < current - self._MAX_SCROLL_FRACTION_STEP:
            return current - self._MAX_SCROLL_FRACTION_STEP
        return requested

    def _yview(self, *args):
        """Scrollbar command — scroll both widgets together."""
        if args and args[0] == 'moveto':
            fraction = self._clamped_moveto(args[1])
            self.text.yview_moveto(fraction)
            self.margin.yview_moveto(fraction)
        else:
            self.text.yview(*args)
            self.margin.yview(*args)
        self._schedule_bounds_check()

    def _on_text_yscroll(self, first, last):
        """Text scrolled — update scrollbar and sync margin position."""
        self._vscroll.set(first, last)
        self.margin.yview_moveto(first)

    def refresh(self, state, follow_pc=False):
        self._cancel_bounds_check()
        self._disasm_generation += 1
        self._top_cache = []
        self._bottom_cache = []
        self._display_fetch_when_done = False
        self._fetching = False
        self._suspend_bounds_check = True
        try:
            self._top_exhausted = False
            self._bottom_exhausted = False
            scroll_pos = self.text.yview()[0]

            self.text.delete('1.0', tk.END)
            self.margin.delete('1.0', tk.END)

            pc = state.pc
            goto_line = None
            for i, insn in enumerate(state.disassembly):
                addr = insn['addr']
                asm = insn['asm']

                bp_num = self.app._find_bp_at_addr(addr)
                if bp_num:
                    bp_info = self.app.state.breakpoints[bp_num]
                    if bp_info.get('enabled', True):
                        self.margin.insert(tk.END, " ●\n", 'bp_marker')
                    else:
                        self.margin.insert(tk.END, " ●\n", 'bp_marker_disabled')
                else:
                    self.margin.insert(tk.END, "  \n")

                if addr.startswith('0x'):
                    line = f"{addr:>18s}  {asm}\n"
                else:
                    line = f"0x{addr:>16s}  {asm}\n"

                if addr == pc or f'0x{addr}' == pc:
                    self.text.insert(tk.END, line, 'current')
                else:
                    self.text.insert(tk.END, line)

                if self._goto_addr_int is not None:
                    try:
                        if int(addr, 16) == self._goto_addr_int:
                            goto_line = i + 1
                    except (ValueError, TypeError):
                        pass

            if goto_line:
                self.text.tag_add('goto', f'{goto_line}.0', f'{goto_line}.end')

            self.text.yview_moveto(scroll_pos)
            self.margin.yview_moveto(scroll_pos)
            if follow_pc and pc:
                self._scroll_to_addr_line(pc)
        finally:
            self._suspend_bounds_check = False

    def _clear_context_selection(self, event=None):
        self.text.tag_remove('ctx_selected', '1.0', tk.END)
        self.margin.tag_remove('ctx_selected', '1.0', tk.END)
        self._ctx_addr = None
        self._ctx_insn = None
        return None

    def _select_context_line(self, line_num):
        self.text.tag_remove('ctx_selected', '1.0', tk.END)
        self.margin.tag_remove('ctx_selected', '1.0', tk.END)
        self.text.tag_add('ctx_selected', f'{line_num + 1}.0', f'{line_num + 1}.end')
        self.margin.tag_add('ctx_selected', f'{line_num + 1}.0', f'{line_num + 1}.end')
        self.text.tag_raise('ctx_selected')
        self.margin.tag_raise('ctx_selected')

    def _format_context_addr(self, addr):
        addr = str(addr or '').strip()
        if not addr:
            return ''
        return addr if addr.startswith('0x') else f'0x{addr}'

    def _on_click(self, event):
        self._clear_context_selection()
        widget = event.widget
        index = widget.index(f"@{event.x},{event.y}")
        line_num = int(index.split('.')[0]) - 1
        if 0 <= line_num < len(self.app.state.disassembly):
            addr = self.app.state.disassembly[line_num]['addr']
            existing = self.app._find_bp_at_addr(addr)
            if existing:
                self.app.gdb.send_cmd(f'-break-delete {existing}',
                    callback=lambda r, n=existing: self.app._on_break_deleted(r, n))
            else:
                if addr.startswith('0x'):
                    self.app.gdb.send_cmd(f'-break-insert *{addr}',
                        callback=self.app._on_break_created)
                else:
                    self.app.gdb.send_cmd(f'-break-insert *0x{addr}',
                        callback=self.app._on_break_created)
        return 'break'

    def _on_right_click(self, event):
        widget = event.widget
        index = widget.index(f"@{event.x},{event.y}")
        line_num = int(index.split('.')[0]) - 1
        if line_num < 0 or line_num >= len(self.app.state.disassembly):
            return
        insn = self.app.state.disassembly[line_num]
        addr = self._format_context_addr(insn.get('addr', ''))
        self._ctx_addr = addr
        self._ctx_insn = insn
        self._select_context_line(line_num)

        self._ctx_menu.delete(0, tk.END)
        existing = self.app._find_bp_at_addr(addr)

        if existing:
            bp_info = self.app.state.breakpoints[existing]
            is_enabled = bp_info.get('enabled', True)
            self.app._menu_command(
                self._ctx_menu, '×', f"Delete breakpoint #{existing}",
                command=lambda: self._ctx_delete(existing))
            if is_enabled:
                self.app._menu_command(
                    self._ctx_menu, '○', f"Disable breakpoint #{existing}",
                    command=lambda: self._ctx_disable(existing))
            else:
                self.app._menu_command(
                    self._ctx_menu, '●', f"Enable breakpoint #{existing}",
                    command=lambda: self._ctx_enable(existing))
        else:
            self.app._menu_command(
                self._ctx_menu, '●', "Insert breakpoint",
                command=lambda: self._ctx_insert(addr))

        self._ctx_menu.add_separator()
        self.app._menu_command(self._ctx_menu, '⧉', "Copy Address",
                               command=self._ctx_copy_address)
        self.app._menu_command(self._ctx_menu, '⧉', "Copy Instruction",
                               command=self._ctx_copy_instruction)
        self.app._menu_command(self._ctx_menu, '⧉', "Copy Address + Instruction",
                               command=self._ctx_copy_address_instruction)
        self._ctx_menu.add_separator()
        self.app._menu_command(self._ctx_menu, '▦', "Open Address in Memory",
                               command=self._ctx_open_memory)

        self._ctx_menu.tk_popup(event.x_root, event.y_root)

    def _copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _ctx_copy_address(self):
        if self._ctx_addr:
            self._copy_to_clipboard(self._ctx_addr)

    def _ctx_copy_instruction(self):
        asm = (self._ctx_insn or {}).get('asm', '')
        if asm:
            self._copy_to_clipboard(asm)

    def _ctx_copy_address_instruction(self):
        asm = (self._ctx_insn or {}).get('asm', '')
        text = f"{self._ctx_addr}  {asm}".rstrip()
        if text:
            self._copy_to_clipboard(text)

    def _ctx_open_memory(self):
        addr = self._ctx_addr
        if not addr:
            return
        var = self.app._view_vars.get('Memory')
        if var is not None and not var.get():
            var.set(True)
            self.app._toggle_panel('Memory')
        mem = self.app.mem_panel
        mem.addr_entry.state(['!disabled'])
        mem._go_btn.state(['!disabled'])
        mem.addr_entry.delete(0, tk.END)
        mem.addr_entry.insert(0, addr)
        mem._read_memory()

    def _ctx_insert(self, addr):
        if addr.startswith('0x'):
            self.app.gdb.send_cmd(f'-break-insert *{addr}',
                callback=self.app._on_break_created)
        else:
            self.app.gdb.send_cmd(f'-break-insert *0x{addr}',
                callback=self.app._on_break_created)

    def _ctx_delete(self, num):
        self.app.gdb.send_cmd(f'-break-delete {num}',
            callback=lambda r, n=num: self.app._on_break_deleted(r, n))

    def _ctx_disable(self, num):
        self.app.gdb.send_cmd(f'-break-disable {num}',
            callback=lambda r, n=num: self.app._on_break_modified(r, n, False))

    def _ctx_enable(self, num):
        self.app.gdb.send_cmd(f'-break-enable {num}',
            callback=lambda r, n=num: self.app._on_break_modified(r, n, True))


class RegisterPanel(tk.Frame):
    """Register display with change highlighting and inline editing."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app

        header = tk.Frame(self, bg=app.colors['panel_header'], height=28)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        ttk.Label(header, text="Registers", style='Panel.TLabel'
                 ).pack(side=tk.LEFT, padx=4)
        app._add_panel_close_button(header, 'Registers')

        canvas = tk.Canvas(self, bg=app.colors['surface'], highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview)
        self.reg_frame = tk.Frame(canvas, bg=app.colors['surface'])
        self.reg_frame.bind('<Configure>',
                            lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=self.reg_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(fill=tk.BOTH, expand=True)

        self._reg_labels = {}
        self._reg_ctx_menu = self.app._make_menu(self)
        self._ctx_reg_name = None
        self._ctx_reg_value = None

    def refresh(self, state):
        changed = state.changed_registers()

        if set(self._reg_labels.keys()) != set(state.registers.keys()):
            for w in self.reg_frame.winfo_children():
                w.destroy()
            self._reg_labels.clear()
            for i, (name, val) in enumerate(state.registers.items()):
                row = i // 2
                col = (i % 2) * 3
                tk.Label(self.reg_frame, text=name, font=self.app.font_bold,
                         bg=self.app.colors['surface'], fg=self.app.colors['fg'],
                         anchor=tk.W, width=8).grid(row=row, column=col, sticky=tk.W, padx=(4, 0))
                val_label = tk.Label(self.reg_frame, text=val, font=self.app.font,
                                     bg=self.app.colors['surface'], fg=self.app.colors['fg'],
                                     anchor=tk.W, width=18, cursor='hand2')
                val_label.grid(row=row, column=col+1, sticky=tk.W, padx=(2, 8))
                val_label.bind('<Double-1>', lambda e, n=name: self._edit_register(n))
                val_label.bind('<Button-3>', lambda e, n=name: self._on_reg_right_click(e, n))
                self._reg_labels[name] = val_label

        for name, val in state.registers.items():
            if name in self._reg_labels:
                self._reg_labels[name].config(text=val)
                if name in changed:
                    self._reg_labels[name].config(fg=self.app.colors['changed'])
                else:
                    self._reg_labels[name].config(fg=self.app.colors['fg'])

    def _on_reg_right_click(self, event, name):
        self._ctx_reg_name = name
        self._ctx_reg_value = self.app.state.registers.get(name, '')
        self._reg_ctx_menu.delete(0, tk.END)
        self.app._menu_command(self._reg_ctx_menu, '▦', "Open Value in Memory",
                               command=self._open_reg_value_in_memory)
        self.app._menu_command(self._reg_ctx_menu, '⧉', "Copy Value",
                               command=self._copy_reg_value)
        self._reg_ctx_menu.tk_popup(event.x_root, event.y_root)

    def _open_reg_value_in_memory(self):
        value = self._ctx_reg_value
        if not value:
            return
        var = self.app._view_vars.get('Memory')
        if var is not None and not var.get():
            var.set(True)
            self.app._toggle_panel('Memory')
        mem = self.app.mem_panel
        mem.addr_entry.state(['!disabled'])
        mem._go_btn.state(['!disabled'])
        mem.addr_entry.delete(0, tk.END)
        mem.addr_entry.insert(0, value)
        mem._read_memory()

    def _copy_reg_value(self):
        if self._ctx_reg_value:
            self.clipboard_clear()
            self.clipboard_append(self._ctx_reg_value)

    def _edit_register(self, name):
        current = self.app.state.registers.get(name, '0x0')
        new_val = simpledialog.askstring(
            f"Edit Register", f"Set {name} = ",
            initialvalue=current, parent=self.app)
        if new_val is not None:
            self.app.gdb.send_raw(f'set ${name} = {new_val}')
            self.app.after(200, lambda: self.app.gdb.send_cmd(
                '-data-list-register-values x',
                callback=self.app._on_register_values))


class CallStackPanel(tk.Frame):
    """Stack frame tree view."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app

        header = tk.Frame(self, bg=app.colors['panel_header'], height=28)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        ttk.Label(header, text="Call Stack", style='Panel.TLabel'
                 ).pack(side=tk.LEFT, padx=4)
        app._add_panel_close_button(header, 'Call Stack')

        cols = ('level', 'func', 'file', 'addr')
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=5)
        self.tree.heading('level', text='#')
        self.tree.heading('func', text='Function')
        self.tree.heading('file', text='File:Line')
        self.tree.heading('addr', text='Address')
        self.tree.column('level', width=30, anchor=tk.CENTER)
        self.tree.column('func', width=140)
        self.tree.column('file', width=120)
        self.tree.column('addr', width=100)

        scroll = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.config(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind('<Double-1>', self._on_double_click)

    def refresh(self, state):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for frame in state.frames:
            file_str = f"{frame['file']}:{frame['line']}" if frame['file'] else ''
            self.tree.insert('', tk.END, iid=frame['level'],
                             values=(frame['level'], frame['func'],
                                     file_str, frame['addr']))

    def _on_double_click(self, event):
        sel = self.tree.selection()
        if sel:
            level = sel[0]
            self.app.state.current_frame = int(level)
            self.app.gdb.send_cmd(f'-stack-select-frame {level}')
            self.app._refresh_all()


class BreakpointPanel(tk.Frame):
    """Breakpoint list with toggle/delete actions."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app

        tb = tk.Frame(self, bg=app.colors['panel_header'])
        tb.pack(fill=tk.X, padx=0, pady=0)
        ttk.Button(tb, text="Delete", command=self._delete_selected,
                   style='Small.TButton').pack(side=tk.LEFT, padx=(8, 2), pady=4)
        ttk.Button(tb, text="Toggle", command=self._toggle_selected,
                   style='Small.TButton').pack(side=tk.LEFT, padx=2, pady=4)
        self.app._add_panel_close_button(tb, 'Breakpoints')

        cols = ('num', 'addr', 'enabled', 'hits', 'file', 'cond')
        self.tree = ttk.Treeview(self, columns=cols, show='tree headings', height=4)
        self.tree.heading('#0', text='')
        self.tree.heading('num', text='#')
        self.tree.heading('addr', text='Address')
        self.tree.heading('enabled', text='Enb')
        self.tree.heading('hits', text='Hits')
        self.tree.heading('file', text='File')
        self.tree.heading('cond', text='Condition')
        self.tree.column('#0', width=24, minwidth=22, stretch=False)
        self.tree.column('num', width=34, minwidth=30, anchor=tk.CENTER, stretch=False)
        self.tree.column('addr', width=118, minwidth=96, stretch=False)
        self.tree.column('enabled', width=44, minwidth=38, anchor=tk.CENTER, stretch=False)
        self.tree.column('hits', width=46, minwidth=40, anchor=tk.CENTER, stretch=False)
        self.tree.column('file', width=120, minwidth=90, stretch=True)
        self.tree.column('cond', width=120, minwidth=80, stretch=True)

        self._bp_hscroll = tk.Scrollbar(self, orient=tk.HORIZONTAL,
                                        command=self.tree.xview)
        scroll = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.config(yscrollcommand=scroll.set,
                         xscrollcommand=self._bp_hscroll.set)
        self._bp_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind('<Double-1>', self._on_double_click)
        self.tree.bind('<Button-3>', self._on_right_click)

    def refresh(self, state):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for num, bp in state.breakpoints.items():
            enb = 'y' if bp['enabled'] else 'n'
            self.tree.insert('', tk.END, iid=num,
                             values=(num, bp['addr'], enb, bp['hits'],
                                     f"{bp['file']}:{bp['line']}" if bp['file'] else '',
                                     bp['cond']),
                             open=bool(bp.get('locations')))
            for loc in bp.get('locations', []):
                loc_num = loc.get('number') or f'{num}.{len(self.tree.get_children(num)) + 1}'
                loc_iid = loc_num if str(loc_num).startswith(f'{num}.') else f'{num}.{loc_num}'
                loc_enb = 'y' if loc.get('enabled', True) else 'n'
                loc_file = f"{loc.get('file', '')}:{loc.get('line', '')}" if loc.get('file') else ''
                loc_func = loc.get('func', '')
                self.tree.insert(num, tk.END, iid=loc_iid,
                                 values=(loc_num, loc.get('addr', ''), loc_enb,
                                         '', loc_file, loc_func),
                                 open=False)

    def _parent_bp_num(self, item):
        item = str(item or '')
        if item in self.app.state.breakpoints:
            return item
        if '.' in item:
            return item.split('.', 1)[0]
        return item

    def _location_for_item(self, item):
        item = str(item or '')
        if '.' not in item:
            return None
        parent = self._parent_bp_num(item)
        bp = self.app.state.breakpoints.get(parent, {})
        for loc in bp.get('locations', []):
            if loc.get('number') == item:
                return loc
        return None

    def _delete_selected(self):
        sel = self.tree.selection()
        for item in sel:
            num = self._parent_bp_num(item)
            self.app.gdb.send_cmd(f'-break-delete {num}',
                callback=lambda r, n=num: self.app._on_break_deleted(r, n))

    def _toggle_selected(self):
        sel = self.tree.selection()
        for item in sel:
            num = self._parent_bp_num(item)
            bp = self.app.state.breakpoints.get(num)
            if bp:
                if bp['enabled']:
                    self.app.gdb.send_cmd(f'-break-disable {num}',
                        callback=lambda r, n=num: self.app._on_break_modified(r, n, False))
                else:
                    self.app.gdb.send_cmd(f'-break-enable {num}',
                        callback=lambda r, n=num: self.app._on_break_modified(r, n, True))

    def _set_condition(self):
        sel = self.tree.selection()
        if sel:
            num = self._parent_bp_num(sel[0])
            bp = self.app.state.breakpoints.get(num, {})
            cur_cond = bp.get('cond', '')
            cond = simpledialog.askstring("Set Condition",
                                           f"Condition for breakpoint {num}:",
                                           initialvalue=cur_cond, parent=self.app)
            if cond is not None:
                if cond:
                    self.app.gdb.send_cmd(f'-break-condition {num} {cond}')
                else:
                    self.app.gdb.send_cmd(f'-break-condition {num}')

    def _on_double_click(self, event):
        sel = self.tree.selection()
        if sel:
            loc = self._location_for_item(sel[0])
            bp = self.app.state.breakpoints.get(self._parent_bp_num(sel[0]))
            addr = loc.get('addr', '') if loc else (bp or {}).get('addr', '')
            if addr:
                try:
                    a = int(addr, 16)
                    s, e = hex(max(0, a - 64)), hex(a + 128)
                except (ValueError, TypeError):
                    s, e = addr, f'"{addr}+100"'
                self.app.gdb.send_cmd(
                    f'-data-disassemble -s {s} -e {e} -- 0',
                    callback=self.app._on_disasm)

    def _on_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        menu = self.app._make_menu(self)
        bp = self.app.state.breakpoints.get(self._parent_bp_num(item), {})
        if bp.get('enabled'):
            self.app._menu_command(menu, '○', "Disable",
                                   command=self._toggle_selected)
        else:
            self.app._menu_command(menu, '●', "Enable",
                                   command=self._toggle_selected)
        self.app._menu_command(menu, '◇', "Set Condition...",
                               command=self._set_condition)
        menu.add_separator()
        self.app._menu_command(menu, '×', "Delete",
                               command=self._delete_selected)
        menu.tk_popup(event.x_root, event.y_root)


class MemoryPanel(tk.Frame):
    """Hex dump memory view with dynamic scroll loading."""

    _EXPAND_BYTES = 256
    _PREFETCH_TOP = 0.18
    _PREFETCH_BOTTOM = 0.82
    _DISPLAY_TOP = 0.02
    _DISPLAY_BOTTOM = 0.98
    _MAX_WHEEL_UNITS = 1
    _MAX_SCROLL_FRACTION_STEP = 0.04
    _HEX_COL_START = 20
    _HEX_BYTE_WIDTH = 3
    _HEX_BYTE_CHARS = 2

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app
        self.bytes_per_row = 16

        self._mem_start_int = None
        self._mem_end_int = None
        self._mem_fetching = False
        self._scroll_to_addr = None
        self._MAX_MEM = 16384
        self._bounds_after_id = None
        self._pending_bounds_check = False
        self._suspend_bounds_check = False
        self._top_exhausted = False
        self._bottom_exhausted = False
        self._top_cache = None
        self._bottom_cache = None
        self._display_fetch_when_done = False
        self._mem_bytes = b''
        self._mem_ctx_menu = self.app._make_menu(self)
        self._last_mem_context_event = None

        addr_frame = tk.Frame(self, bg=app.colors['panel_header'])
        addr_frame.pack(fill=tk.X)
        ttk.Label(addr_frame, text="Address:", style='Panel.TLabel'
                  ).pack(side=tk.LEFT, padx=(8, 4))
        self.addr_entry = ttk.Entry(addr_frame, font=app.font, width=20,
                                    style='Compact.TEntry')
        self.addr_entry.pack(side=tk.LEFT, padx=4, pady=4)
        self.addr_entry.state(['disabled'])
        self.addr_entry.bind('<Return>', lambda event: self._read_memory())
        self._go_btn = ttk.Button(addr_frame, text="Go", command=self._read_memory,
                                  style='Small.TButton')
        self._go_btn.pack(side=tk.LEFT, padx=2, pady=4)
        self._go_btn.state(['disabled'])

        ttk.Label(addr_frame, text="Size:", style='Panel.TLabel'
                  ).pack(side=tk.LEFT, padx=(8, 2))
        self.size_var = tk.StringVar(value='256')
        size_cb = ttk.Combobox(addr_frame, textvariable=self.size_var,
                                values=['128', '256', '512'], width=5, state='readonly')
        size_cb.pack(side=tk.LEFT, pady=4)
        self.app._add_panel_close_button(addr_frame, 'Memory')

        self.text = tk.Text(self, wrap=tk.NONE, font=app.font,
                            bg=app.colors['code_bg'], fg=app.colors['fg'],
                            selectbackground=app.colors['select'],
                            selectforeground=app.colors['fg'],
                            state=tk.DISABLED, bd=0, padx=8, pady=6)
        hscroll = tk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.text.xview)
        self._vscroll = tk.Scrollbar(self, orient=tk.VERTICAL, command=self._yview)
        self.text.config(xscrollcommand=hscroll.set,
                         yscrollcommand=self._on_text_yscroll)
        hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self._vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.pack(fill=tk.BOTH, expand=True)

        self.text.tag_configure('ascii', foreground=app.colors['success'])
        self.text.tag_configure('addr_col', foreground=app.colors['accent'])

        self.text.bind('<MouseWheel>', self._on_mousewheel)
        self.text.bind('<Button-4>', self._on_mousewheel)
        self.text.bind('<Button-5>', self._on_mousewheel)
        self.text.bind('<Button-3>', self._on_memory_right_click)

    def _wheel_scroll_units(self, event):
        if getattr(event, 'num', None) == 4:
            return -1
        if getattr(event, 'num', None) == 5:
            return 1
        delta = getattr(event, 'delta', 0)
        if not delta:
            return 0
        return -1 if delta > 0 else 1

    def _on_mousewheel(self, event):
        units = self._wheel_scroll_units(event)
        units = max(-self._MAX_WHEEL_UNITS, min(self._MAX_WHEEL_UNITS, units))
        if units:
            self.text.yview_scroll(units, 'units')
        self._schedule_bounds_check()
        return 'break'

    def _schedule_bounds_check(self, delay=35):
        if self._suspend_bounds_check:
            return
        self._cancel_bounds_check()
        self._bounds_after_id = self.after(delay, self._run_scheduled_bounds_check)

    def _cancel_bounds_check(self):
        if self._bounds_after_id is not None:
            try:
                self.after_cancel(self._bounds_after_id)
            except tk.TclError:
                pass
            self._bounds_after_id = None

    def _run_scheduled_bounds_check(self):
        self._bounds_after_id = None
        self._check_bounds()

    def _clamped_moveto(self, requested):
        try:
            requested = float(requested)
        except (TypeError, ValueError):
            return self.text.yview()[0]
        current = self.text.yview()[0]
        if requested > current + self._MAX_SCROLL_FRACTION_STEP:
            return current + self._MAX_SCROLL_FRACTION_STEP
        if requested < current - self._MAX_SCROLL_FRACTION_STEP:
            return current - self._MAX_SCROLL_FRACTION_STEP
        return requested

    def _yview(self, *args):
        if args and args[0] == 'moveto':
            self.text.yview_moveto(self._clamped_moveto(args[1]))
        else:
            self.text.yview(*args)
        self._schedule_bounds_check()

    def _on_text_yscroll(self, first, last):
        self._vscroll.set(first, last)

    def _on_memory_right_click(self, event):
        self._last_mem_context_event = event
        self._mem_ctx_menu.delete(0, tk.END)
        self.app._menu_command(self._mem_ctx_menu, '⇩', "Save Selected Bytes...",
                               command=self._save_selected_bytes)
        self.app._menu_command(self._mem_ctx_menu, '⧉', "Copy Selected Bytes (Hex)",
                               command=self._copy_selected_bytes_hex)
        self.app._menu_command(self._mem_ctx_menu, '⧉', "Copy Selected Bytes (\\xNN)",
                               command=self._copy_selected_bytes_escaped)
        self.app._menu_command(self._mem_ctx_menu, '⧉', "Copy Row Hex",
                               command=lambda e=event: self._copy_row_hex(e))
        self.app._menu_command(self._mem_ctx_menu, '⧉', "Copy Row Bytes (\\xNN)",
                               command=lambda e=event: self._copy_row_escaped(e))
        self._mem_ctx_menu.add_separator()
        self.app._menu_command(self._mem_ctx_menu, '⇩', "Dump Range...",
                               command=self._dump_range_dialog)
        self._mem_ctx_menu.tk_popup(event.x_root, event.y_root)
        return 'break'

    def _byte_offset_for_text_index(self, index):
        line_text, col_text = str(index).split('.', 1)
        line = int(line_text) - 1
        col = int(col_text)
        if line < 0:
            return None
        rel_col = col - self._HEX_COL_START
        if rel_col < 0:
            return None
        byte_in_row = rel_col // self._HEX_BYTE_WIDTH
        col_in_byte = rel_col % self._HEX_BYTE_WIDTH
        if byte_in_row >= self.bytes_per_row:
            return None
        if col_in_byte >= self._HEX_BYTE_CHARS:
            return None
        return line * self.bytes_per_row + byte_in_row

    def _bytes_for_text_range(self, start_index, end_index):
        start_line, start_col = (int(v) for v in str(start_index).split('.', 1))
        end_line, end_col = (int(v) for v in str(end_index).split('.', 1))
        if (end_line, end_col) < (start_line, start_col):
            start_line, start_col, end_line, end_col = end_line, end_col, start_line, start_col
        selected = bytearray()
        hex_col_start = self._HEX_COL_START
        hex_col_end = (
            hex_col_start
            + (self.bytes_per_row - 1) * self._HEX_BYTE_WIDTH
            + self._HEX_BYTE_CHARS
        )
        for line in range(start_line, end_line + 1):
            row = line - 1
            if row < 0:
                continue
            row_start_col = start_col if line == start_line else hex_col_start
            row_end_col = end_col if line == end_line else hex_col_end
            row_start_col = max(row_start_col, hex_col_start)
            row_end_col = min(row_end_col, hex_col_end)
            if row_end_col <= row_start_col:
                continue
            row_base = row * self.bytes_per_row
            for byte_in_row in range(self.bytes_per_row):
                byte_start = hex_col_start + byte_in_row * self._HEX_BYTE_WIDTH
                byte_end = byte_start + self._HEX_BYTE_CHARS
                if row_start_col < byte_end and row_end_col > byte_start:
                    offset = row_base + byte_in_row
                    if 0 <= offset < len(self._mem_bytes):
                        selected.append(self._mem_bytes[offset])
        return bytes(selected)

    def _selected_memory_bytes(self):
        try:
            start_index = self.text.index(tk.SEL_FIRST)
            end_index = self.text.index(tk.SEL_LAST)
        except tk.TclError:
            return b''
        return self._bytes_for_text_range(start_index, end_index)

    def _row_bytes_for_event(self, event):
        try:
            line = int(self.text.index(f"@{event.x},{event.y}").split('.')[0]) - 1
        except (tk.TclError, ValueError, AttributeError):
            return b''
        offset = line * self.bytes_per_row
        return self._mem_bytes[offset:offset + self.bytes_per_row]

    def _default_memory_filename(self, prefix, start=None, end=None, size=None):
        parts = [prefix]
        if start is not None:
            parts.append(hex(start))
        if end is not None:
            parts.append(hex(end))
        elif size is not None:
            parts.append(str(size))
        return '_'.join(parts) + '.bin'

    def _save_bytes_to_file(self, data, path):
        with open(path, 'wb') as f:
            f.write(data)

    def _save_selected_bytes(self):
        data = self._selected_memory_bytes()
        start_addr = None
        try:
            first = self.text.index(tk.SEL_FIRST)
            offset = self._byte_offset_for_text_index(first)
            if offset is not None and self._mem_start_int is not None:
                start_addr = self._mem_start_int + offset
        except tk.TclError:
            pass
        if not data and self._last_mem_context_event is not None:
            data = self._row_bytes_for_event(self._last_mem_context_event)
            try:
                line = int(self.text.index(
                    f"@{self._last_mem_context_event.x},{self._last_mem_context_event.y}"
                ).split('.')[0]) - 1
                start_addr = self._mem_start_int + line * self.bytes_per_row
            except (tk.TclError, ValueError, AttributeError, TypeError):
                start_addr = self._mem_start_int
        if not data:
            return
        default_name = self._default_memory_filename(
            'mem', start=start_addr, size=len(data))
        path = filedialog.asksaveasfilename(
            parent=self.app, title="Save Selected Bytes",
            initialfile=default_name, defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if not path:
            return
        try:
            self._save_bytes_to_file(data, path)
        except OSError as exc:
            self.app.console_panel.append_output(f"Save failed: {exc}\n")
            return
        self.app.console_panel.append_output(
            f"Saved {len(data)} bytes to {path}\n")

    def _copy_bytes_binary(self, data):
        if not data:
            return
        self.clipboard_clear()
        self.clipboard_append(data.decode('latin-1'))

    def _format_bytes_hex(self, data):
        return ' '.join(f'{b:02x}' for b in data)

    def _format_bytes_escaped(self, data):
        return ''.join(f'\\x{b:02x}' for b in data)

    def _copy_bytes_hex(self, data):
        if not data:
            return
        self.clipboard_clear()
        self.clipboard_append(self._format_bytes_hex(data))

    def _copy_bytes_escaped(self, data):
        if not data:
            return
        self.clipboard_clear()
        self.clipboard_append(self._format_bytes_escaped(data))

    def _copy_selected_bytes_binary(self):
        data = self._selected_memory_bytes()
        if not data and self._last_mem_context_event is not None:
            data = self._row_bytes_for_event(self._last_mem_context_event)
        self._copy_bytes_binary(data)

    def _copy_selected_bytes_hex(self):
        data = self._selected_memory_bytes()
        if not data and self._last_mem_context_event is not None:
            data = self._row_bytes_for_event(self._last_mem_context_event)
        self._copy_bytes_hex(data)

    def _copy_selected_bytes_escaped(self):
        data = self._selected_memory_bytes()
        if not data and self._last_mem_context_event is not None:
            data = self._row_bytes_for_event(self._last_mem_context_event)
        self._copy_bytes_escaped(data)

    def _copy_row_hex(self, event):
        self._copy_bytes_hex(self._row_bytes_for_event(event))

    def _copy_row_escaped(self, event):
        self._copy_bytes_escaped(self._row_bytes_for_event(event))

    def _dump_range_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Dump Memory Range")
        dlg.resizable(False, False)
        dlg.transient(self.app)

        frame = tk.Frame(dlg, padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        start_var = tk.StringVar(value=hex(self._mem_start_int or 0))
        end_var = tk.StringVar(value=hex(self._mem_end_int or 0))

        ttk.Label(frame, text="Start address:").grid(row=0, column=0, sticky=tk.W, pady=(0, 6))
        start_entry = ttk.Entry(frame, textvariable=start_var, style='Compact.TEntry', width=30)
        start_entry.grid(row=0, column=1, sticky=tk.EW, pady=(0, 6))
        ttk.Label(frame, text="End address:").grid(row=1, column=0, sticky=tk.W)
        end_entry = ttk.Entry(frame, textvariable=end_var, style='Compact.TEntry', width=30)
        end_entry.grid(row=1, column=1, sticky=tk.EW)

        buttons = tk.Frame(frame)
        buttons.grid(row=2, column=0, columnspan=2, sticky=tk.E, pady=(10, 0))
        ttk.Button(buttons, text="Cancel", command=dlg.destroy,
                   style='Small.TButton').pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(buttons, text="Dump",
                   command=lambda: self._dump_range_to_file(start_var.get(), end_var.get(), dlg),
                   style='Primary.Tool.TButton').pack(side=tk.RIGHT)
        frame.grid_columnconfigure(1, weight=1)
        start_entry.focus_set()
        start_entry.selection_range(0, tk.END)

    def _parse_dump_addr(self, text):
        clean = str(text or '').strip().lstrip('*').strip()
        if not clean:
            raise ValueError("empty address")
        return int(clean, 0)

    def _dump_range_to_file(self, start_text, end_text, dlg=None):
        try:
            start = self._parse_dump_addr(start_text)
            end = self._parse_dump_addr(end_text)
        except ValueError as exc:
            self.app.console_panel.append_output(f"Invalid dump address: {exc}\n")
            return
        size = end - start
        if size <= 0:
            self.app.console_panel.append_output("Invalid dump range: end must be greater than start\n")
            return
        default_name = self._default_memory_filename('dump', start=start, end=end)
        path = filedialog.asksaveasfilename(
            parent=self.app, title="Save Dump",
            initialfile=default_name, defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if not path:
            return
        if dlg is not None:
            dlg.destroy()
        self.app.gdb.send_cmd(f'-data-read-memory-bytes {hex(start)} {size}',
            callback=lambda r, s=start, e=end, p=path: self._on_dump_range(r, s, e, p))

    def _on_dump_range(self, record, start, end, path):
        _start_int, raw_bytes = self._parse_memory_payload(record)
        if not raw_bytes:
            self.app.console_panel.append_output(
                f"Dump failed for {hex(start)}..{hex(end)}\n")
            return
        try:
            self._save_bytes_to_file(raw_bytes, path)
        except OSError as exc:
            self.app.console_panel.append_output(f"Save failed: {exc}\n")
            return
        self.app.console_panel.append_output(f"Saved {len(raw_bytes)} bytes from {hex(start)} to {hex(end)} to {path}\n")

    def _check_bounds(self):
        if self._suspend_bounds_check:
            return
        if self._mem_start_int is None:
            return
        if self._mem_fetching:
            self._pending_bounds_check = True
            return
        if not self._mem_bytes:
            return
        yview = self.text.yview()
        first, last = yview
        total = len(self._mem_bytes)
        if first <= self._DISPLAY_TOP:
            if self._show_cached_up():
                self._expand_up()
            elif self._mem_start_int > 0 and total < self._MAX_MEM and not self._top_exhausted:
                self._display_fetch_when_done = True
                self._expand_up()
            return
        elif first <= self._PREFETCH_TOP and self._top_cache is None and self._mem_start_int > 0 and total < self._MAX_MEM and not self._top_exhausted:
            self._display_fetch_when_done = False
            self._expand_up()
            return

        if last >= self._DISPLAY_BOTTOM:
            if self._show_cached_down():
                self._expand_down()
            elif total < self._MAX_MEM and not self._bottom_exhausted:
                self._display_fetch_when_done = True
                self._expand_down()
        elif last >= self._PREFETCH_BOTTOM and self._bottom_cache is None and total < self._MAX_MEM and not self._bottom_exhausted:
            self._display_fetch_when_done = False
            self._expand_down()

    def _expand_up(self):
        if self._mem_fetching:
            self._pending_bounds_check = True
            return
        if self._mem_start_int is None or self._mem_start_int <= 0:
            self._top_exhausted = True
            return
        size = min(self._EXPAND_BYTES, self._mem_start_int)
        start_int = self._mem_start_int - size
        if size <= 0:
            self._top_exhausted = True
            return
        self._mem_fetching = True
        self._pending_bounds_check = False
        self._fetch_memory_range(
            start_int, size,
            callback=lambda r, s=start_int: self._on_expand_up_done(r, s))

    def _expand_down(self):
        if self._mem_fetching:
            self._pending_bounds_check = True
            return
        if self._mem_end_int is None:
            return
        start_int = self._mem_end_int
        self._mem_fetching = True
        self._pending_bounds_check = False
        self._fetch_memory_range(
            start_int, self._EXPAND_BYTES,
            callback=lambda r, s=start_int: self._on_expand_down_done(r, s))

    def _fetch_memory_range(self, start_int, size, callback):
        self.app.gdb.send_cmd(
            f'-data-read-memory-bytes {hex(start_int)} {size}',
            callback=callback)

    def _fetch_current_range(self):
        self._cancel_bounds_check()
        self._mem_fetching = True
        if self._mem_start_int is None or self._mem_end_int is None:
            return
        size = self._mem_end_int - self._mem_start_int
        self._fetch_memory_range(self._mem_start_int, size,
                                 callback=self._on_memory)

    def _parse_memory_payload(self, record):
        if record.get('cls') != 'done':
            return None, b''
        payload = record.get('payload', '')
        m = re.search(r'memory=\[\{(.+?)\}\]', payload, re.DOTALL)
        if not m:
            return None, b''
        parsed = parse_mi_tuple(m.group(1))
        start = parsed.get('begin', '0x0')
        contents = parsed.get('contents', '')
        start_int = int(start, 16) if str(start).startswith('0x') else int(start)
        try:
            raw_bytes = bytes.fromhex(contents)
        except ValueError:
            raw_bytes = b''
        return start_int, raw_bytes

    def _visible_anchor_addr(self):
        if self._mem_start_int is None:
            return None
        try:
            top_line = int(self.text.index('@0,0').split('.')[0])
        except (tk.TclError, ValueError):
            return None
        return self._mem_start_int + max(0, top_line - 1) * self.bytes_per_row

    def _scroll_addr_to_top(self, addr):
        if addr is None or self._mem_start_int is None:
            return
        if addr < self._mem_start_int or addr >= self._mem_end_int:
            return
        line = max(0, (addr - self._mem_start_int) // self.bytes_per_row)
        rows = max(1, (len(self._mem_bytes) + self.bytes_per_row - 1) // self.bytes_per_row)
        fraction = max(0.0, min(1.0, line / rows))
        self.text.yview_moveto(fraction)

    def _show_cached_up(self):
        if self._top_cache is None:
            return False
        start_int, raw_bytes = self._top_cache
        self._top_cache = None
        if not raw_bytes:
            return False
        anchor = self._mem_start_int
        merged = raw_bytes + self._mem_bytes
        self._mem_start_int = start_int
        if len(merged) > self._MAX_MEM:
            merged = merged[:self._MAX_MEM]
        self._mem_bytes = merged
        self._mem_end_int = self._mem_start_int + len(self._mem_bytes)
        self._render_memory(self._mem_start_int, self._mem_bytes)
        self._scroll_addr_to_top(anchor)
        return True

    def _show_cached_down(self):
        if self._bottom_cache is None:
            return False
        _start_int, raw_bytes = self._bottom_cache
        self._bottom_cache = None
        if not raw_bytes:
            return False
        anchor = self._visible_anchor_addr()
        merged = self._mem_bytes + raw_bytes
        if len(merged) > self._MAX_MEM:
            trim = len(merged) - self._MAX_MEM
            self._mem_start_int += trim
            merged = merged[trim:]
        self._mem_bytes = merged
        self._mem_end_int = self._mem_start_int + len(self._mem_bytes)
        self._render_memory(self._mem_start_int, self._mem_bytes)
        self._scroll_addr_to_top(anchor)
        return True

    def _cache_or_show_up(self, start_int, raw_bytes):
        if not raw_bytes:
            self._top_exhausted = True
            return
        self._top_exhausted = False
        self._top_cache = (start_int, raw_bytes)
        if self._display_fetch_when_done:
            self._show_cached_up()

    def _cache_or_show_down(self, start_int, raw_bytes):
        if not raw_bytes:
            self._bottom_exhausted = True
            return
        self._bottom_exhausted = False
        self._bottom_cache = (start_int, raw_bytes)
        if self._display_fetch_when_done:
            self._show_cached_down()

    def _on_expand_up_done(self, record, start_int):
        self._mem_fetching = False
        show_when_done = self._display_fetch_when_done
        self._display_fetch_when_done = show_when_done
        payload_start, raw_bytes = self._parse_memory_payload(record)
        if payload_start is None:
            raw_bytes = b''
        self._cache_or_show_up(start_int, raw_bytes)
        self._display_fetch_when_done = False
        if self._pending_bounds_check:
            self._pending_bounds_check = False
            self._schedule_bounds_check()

    def _on_expand_down_done(self, record, start_int):
        self._mem_fetching = False
        show_when_done = self._display_fetch_when_done
        self._display_fetch_when_done = show_when_done
        payload_start, raw_bytes = self._parse_memory_payload(record)
        if payload_start is None:
            raw_bytes = b''
        self._cache_or_show_down(start_int, raw_bytes)
        self._display_fetch_when_done = False
        if self._pending_bounds_check:
            self._pending_bounds_check = False
            self._schedule_bounds_check()

    def _read_memory(self):
        addr = self.addr_entry.get().strip()
        if not addr:
            return
        # Try direct hex parse first
        try:
            start_int = int(addr, 16)
            self._do_read(start_int)
            return
        except ValueError:
            pass
        # Otherwise resolve via GDB (registers, symbols, expressions)
        clean = addr.lstrip('*').strip()
        if re.match(r'^[a-z]+\d*$|^[er]?[a-z]{2,3}[lh]?$',
                    clean, re.IGNORECASE) and not clean.startswith('0x'):
            if not clean.startswith('$'):
                clean = '$' + clean
        self.app.gdb.send_cmd(
            f'-data-evaluate-expression {clean}',
            callback=self._on_mem_addr_resolved)

    def _on_mem_addr_resolved(self, record):
        if record.get('cls') != 'done':
            self.app.console_panel.append_output("Cannot resolve address\n")
            return
        payload = record.get('payload', '')
        m = re.search(r'value="([^"]+)"', payload)
        if not m:
            self.app.console_panel.append_output("Cannot resolve address\n")
            return
        val = m.group(1)
        addr_match = re.search(r'0x[0-9a-fA-F]+', val)
        if addr_match:
            start_int = int(addr_match.group(0), 16)
        else:
            try:
                start_int = int(val, 0)
            except ValueError:
                self.app.console_panel.append_output(f"Cannot resolve: {val}\n")
                return
        self._do_read(start_int)

    def _do_read(self, start_int):
        size = int(self.size_var.get())
        self._mem_start_int = start_int
        self._mem_end_int = start_int + size
        self._scroll_to_addr = None
        self._mem_bytes = b''
        self._top_cache = None
        self._bottom_cache = None
        self._top_exhausted = False
        self._bottom_exhausted = False
        self._pending_bounds_check = False
        self._display_fetch_when_done = False
        self._fetch_current_range()

    def _on_memory(self, record):
        self._mem_fetching = False
        start_int, raw_bytes = self._parse_memory_payload(record)
        if start_int is None:
            return
        self._mem_start_int = start_int
        self._mem_bytes = raw_bytes
        self._mem_end_int = self._mem_start_int + len(self._mem_bytes)
        self._render_memory(self._mem_start_int, self._mem_bytes)
        if self._scroll_to_addr is not None:
            self._scroll_addr_to_top(self._scroll_to_addr)
            self._scroll_to_addr = None

    def _render_memory(self, start_int, raw_bytes):
        self._suspend_bounds_check = True
        self.text.config(state=tk.NORMAL)
        self.text.delete('1.0', tk.END)
        try:
            for offset in range(0, len(raw_bytes), self.bytes_per_row):
                chunk = raw_bytes[offset:offset + self.bytes_per_row]
                row_addr = start_int + offset

                addr_str = f"0x{row_addr:016x}  "
                self.text.insert(tk.END, addr_str, 'addr_col')

                hex_parts = []
                for _j, b in enumerate(chunk):
                    hex_parts.append(f"{b:02x}")
                hex_str = ' '.join(hex_parts)
                if len(chunk) < self.bytes_per_row:
                    hex_str = hex_str.ljust(self.bytes_per_row * 3 - 1)
                self.text.insert(tk.END, hex_str + "  ")

                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                self.text.insert(tk.END, ascii_str + "\n", 'ascii')
        finally:
            self.text.config(state=tk.DISABLED)
            self._suspend_bounds_check = False

    def refresh(self, state):
        if self._mem_start_int is not None:
            self._fetch_current_range()


class LocalsWatchPanel(tk.Frame):
    """Local variables and watch expressions."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app

        tb = tk.Frame(self, bg=app.colors['panel_header'])
        tb.pack(fill=tk.X)
        ttk.Button(tb, text="Add Watch", command=self._add_watch,
                   style='Small.TButton').pack(side=tk.LEFT, padx=(8, 2), pady=4)
        ttk.Button(tb, text="Remove", command=self._remove_watch,
                   style='Small.TButton').pack(side=tk.LEFT, padx=2, pady=4)
        self.app._add_panel_close_button(tb, 'Locals/Watch')

        cols = ('name', 'value', 'type')
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=6)
        self.tree.heading('name', text='Name')
        self.tree.heading('value', text='Value')
        self.tree.heading('type', text='Type')
        self.tree.column('name', width=120)
        self.tree.column('value', width=150)
        self.tree.column('type', width=100)

        scroll = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.config(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

    def refresh(self, state):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for var in state.locals:
            if isinstance(var, dict):
                self.tree.insert('', tk.END,
                                 values=(var.get('name', ''),
                                         var.get('value', ''),
                                         var.get('type', '')))
        for expr in state.watches:
            val = state.watch_values.get(expr, '...')
            self.tree.insert('', tk.END,
                             values=(f"[w] {expr}", val, ''))

    def _add_watch(self):
        expr = simpledialog.askstring("Add Watch", "Expression:", parent=self.app)
        if expr:
            self.app.state.watches.append(expr)
            self.app.gdb.send_cmd(
                f'-data-evaluate-expression "{expr}"',
                callback=lambda r: self._on_watch_result(r, expr))

    def _remove_watch(self):
        sel = self.tree.selection()
        if sel:
            item = self.tree.item(sel[0])
            name = item['values'][0]
            if str(name).startswith('[w] '):
                expr = str(name)[4:]
                if expr in self.app.state.watches:
                    self.app.state.watches.remove(expr)

    def _on_watch_result(self, record, expr):
        if record.get('cls') == 'done':
            payload = record.get('payload', '')
            m = re.search(r'value="([^"]*)"', payload)
            if m:
                self.app.state.watch_values[expr] = m.group(1)
            self.refresh(self.app.state)


class ThreadPanel(tk.Frame):
    """Thread list with selection."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app

        tb = tk.Frame(self, bg=app.colors['panel_header'])
        tb.pack(fill=tk.X)
        ttk.Label(tb, text="Threads", style='Panel.TLabel'
                  ).pack(side=tk.LEFT, padx=4)
        self.app._add_panel_close_button(tb, 'Threads')

        cols = ('id', 'target_id', 'state', 'core', 'func')
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=6)
        self.tree.heading('id', text='ID')
        self.tree.heading('target_id', text='Target ID')
        self.tree.heading('state', text='State')
        self.tree.heading('core', text='Core')
        self.tree.heading('func', text='Function')
        self.tree.column('id', width=50, anchor=tk.CENTER)
        self.tree.column('target_id', width=100)
        self.tree.column('state', width=80)
        self.tree.column('core', width=50, anchor=tk.CENTER)
        self.tree.column('func', width=140)

        scroll = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.config(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind('<Double-1>', self._on_double_click)

    def refresh(self, state):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for thread in state.threads:
            self.tree.insert('', tk.END, iid=str(thread['id']),
                             values=(thread['id'], thread['target_id'],
                                     thread['state'], thread.get('core', ''),
                                     thread['func']))
        if state.current_thread:
            self.app.status_thread.config(text=f"Thread: {state.current_thread}")

    def _on_double_click(self, event):
        sel = self.tree.selection()
        if sel:
            self.app.gdb.send_cmd(f'-thread-select {sel[0]}')
            self.app._refresh_all()


class LibraryPanel(tk.Frame):
    """Loaded libraries plus exported and imported dynamic symbols."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app
        self._libraries = []
        self._exports = []
        self._imports = []

        toolbar = tk.Frame(self, bg=app.colors['panel_header'])
        toolbar.pack(fill=tk.X)
        self.app._add_panel_close_button(toolbar, 'Libraries')
        ttk.Button(toolbar, text="Refresh", command=self.app._refresh_libraries,
                   style='Small.TButton').pack(side=tk.LEFT, padx=(8, 2), pady=4)
        ttk.Label(toolbar, text="Filter:", style='Panel.TLabel').pack(
            side=tk.LEFT, padx=(8, 2))
        self.filter_var = tk.StringVar()
        entry = ttk.Entry(toolbar, textvariable=self.filter_var,
                          style='Compact.TEntry', width=18)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), pady=4)
        self.filter_var.trace_add('write', lambda *args: self._fill_libraries())

        pane = tk.PanedWindow(self, orient=tk.VERTICAL, sashwidth=4,
                              bg=app.colors['border'], bd=0, relief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True)

        library_frame = tk.Frame(pane, bg=app.colors['surface'])
        cols = ('base', 'end', 'name', 'path')
        self.library_tree = ttk.Treeview(library_frame, columns=cols,
                                         show='headings', height=6)
        for col, text, width in (
            ('base', 'Base', 96), ('end', 'End', 96),
            ('name', 'Name', 130), ('path', 'Path', 260),
        ):
            self.library_tree.heading(col, text=text)
            self.library_tree.column(col, width=width, minwidth=70,
                                     stretch=(col == 'path'))
        lib_scroll = tk.Scrollbar(library_frame, orient=tk.VERTICAL,
                                  command=self.library_tree.yview)
        self.library_tree.config(yscrollcommand=lib_scroll.set)
        self.library_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lib_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.symbol_notebook = ttk.Notebook(pane)
        export_frame = tk.Frame(self.symbol_notebook, bg=app.colors['surface'])
        import_frame = tk.Frame(self.symbol_notebook, bg=app.colors['surface'])
        sym_cols = ('addr', 'type', 'name', 'source')
        self.export_tree = ttk.Treeview(export_frame, columns=sym_cols,
                                        show='headings', height=6)
        self.import_tree = ttk.Treeview(import_frame, columns=sym_cols,
                                        show='headings', height=6)
        for tree in (self.export_tree, self.import_tree):
            tree.heading('addr', text='Address')
            tree.heading('type', text='Type')
            tree.heading('name', text='Name')
            tree.heading('source', text='Source')
            tree.column('addr', width=96, minwidth=70, stretch=False)
            tree.column('type', width=54, minwidth=42, stretch=False)
            tree.column('name', width=160, minwidth=110, stretch=True)
            tree.column('source', width=140, minwidth=90, stretch=True)
            scroll = tk.Scrollbar(tree.master, orient=tk.VERTICAL,
                                  command=tree.yview)
            tree.config(yscrollcommand=scroll.set)
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.symbol_notebook.add(export_frame, text="Exports")
        self.symbol_notebook.add(import_frame, text="Imports")

        pane.add(library_frame, minsize=120)
        pane.add(self.symbol_notebook, minsize=120)

        self.library_tree.bind('<<TreeviewSelect>>', self._on_library_select)
        self.library_tree.bind('<Double-1>', self._disassemble_selected_library)
        self.library_tree.bind('<Button-3>', self._on_library_right_click)
        self.export_tree.bind('<Double-1>', self._disassemble_selected_symbol)
        self.export_tree.bind('<Button-3>', self._on_symbol_right_click)
        self.import_tree.bind('<Double-1>', self._disassemble_selected_symbol)
        self.import_tree.bind('<Button-3>', self._on_symbol_right_click)

    def refresh_libraries(self, libraries):
        self._libraries = list(libraries or [])
        self._fill_libraries()

    def refresh_exports(self, symbols):
        self._exports = list(symbols or [])
        self._fill_symbol_tree(self.export_tree, self._exports)

    def refresh_imports(self, symbols):
        self._imports = list(symbols or [])
        self._fill_symbol_tree(self.import_tree, self._imports)

    def _fill_libraries(self):
        query = self.filter_var.get().strip().lower()
        self.library_tree.delete(*self.library_tree.get_children())
        for idx, lib in enumerate(self._libraries):
            haystack = ' '.join((
                lib.get('base', ''), lib.get('end', ''),
                lib.get('name', ''), lib.get('path', ''),
            )).lower()
            if query and query not in haystack:
                continue
            self.library_tree.insert('', tk.END, iid=str(idx),
                                     values=(lib.get('base', ''),
                                             lib.get('end', ''),
                                             lib.get('name', ''),
                                             lib.get('path', '')))

    def _fill_symbol_tree(self, tree, symbols):
        tree.delete(*tree.get_children())
        for idx, sym in enumerate(symbols):
            tree.insert('', tk.END, iid=str(idx),
                        values=(sym.get('addr', ''), sym.get('type', ''),
                                sym.get('name', ''), sym.get('source', '')))

    def _selected_library(self):
        sel = self.library_tree.selection()
        if not sel:
            return None
        try:
            return self._libraries[int(sel[0])]
        except (ValueError, IndexError):
            return None

    def _selected_symbol(self, tree):
        sel = tree.selection()
        symbols = self._exports if tree is self.export_tree else self._imports
        if not sel:
            return None
        try:
            return symbols[int(sel[0])]
        except (ValueError, IndexError):
            return None

    def _on_library_select(self, event=None):
        lib = self._selected_library()
        if lib:
            self.refresh_exports(self.app._load_library_exports(lib.get('path', '')))

    def _disassemble_selected_library(self, event=None):
        lib = self._selected_library()
        if lib:
            self.app._disassemble_library_base(lib)

    def _disassemble_selected_symbol(self, event=None):
        tree = event.widget if event else self.export_tree
        sym = self._selected_symbol(tree)
        if sym:
            self.app._disassemble_symbol(sym)

    def _on_library_right_click(self, event):
        item = self.library_tree.identify_row(event.y)
        if not item:
            return
        self.library_tree.selection_set(item)
        lib = self._selected_library()
        if not lib:
            return
        menu = self.app._make_menu(self)
        self.app._menu_command(menu, '↦', "Disassemble at Base",
                               command=lambda l=lib: self.app._disassemble_library_base(l))
        self.app._menu_command(menu, '●', "Breakpoint at Base",
                               command=lambda l=lib: self.app._break_library_base(l))
        menu.add_separator()
        self.app._menu_command(menu, '⟳', "Refresh Exports",
                               command=self._on_library_select)
        menu.tk_popup(event.x_root, event.y_root)

    def _on_symbol_right_click(self, event):
        tree = event.widget
        item = tree.identify_row(event.y)
        if not item:
            return
        tree.selection_set(item)
        sym = self._selected_symbol(tree)
        if not sym:
            return
        menu = self.app._make_menu(self)
        self.app._menu_command(menu, '↦', "Disassemble Symbol",
                               command=lambda s=sym: self.app._disassemble_symbol(s))
        self.app._menu_command(menu, '●', "Breakpoint at Symbol",
                               command=lambda s=sym: self.app._break_symbol(s))
        menu.tk_popup(event.x_root, event.y_root)


class MemoryMapWindow(tk.Toplevel):
    """Non-modal process memory map window docked beside the main app."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self._maps = []
        self._filtered_maps = []
        self.title("Memory Map")
        self.configure(bg=app.colors['surface'])
        self.geometry("760x560")
        self.minsize(620, 360)
        self.transient(app)

        self.dock_var = tk.BooleanVar(value=True)
        self.readable_var = tk.BooleanVar(value=True)
        self.filter_var = tk.StringVar()

        toolbar = tk.Frame(self, bg=app.colors['panel_header'])
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Refresh", command=self.app._refresh_memory_map,
                   style='Small.TButton').pack(side=tk.LEFT, padx=(8, 2), pady=4)
        ttk.Button(toolbar, text="Open Start in Memory",
                   command=self._open_selected_start,
                   style='Small.TButton').pack(side=tk.LEFT, padx=2, pady=4)
        ttk.Button(toolbar, text="Dump Range...",
                   command=self._dump_selected_range,
                   style='Small.TButton').pack(side=tk.LEFT, padx=2, pady=4)
        ttk.Checkbutton(toolbar, text="Readable only",
                        variable=self.readable_var,
                        command=self._fill_tree).pack(side=tk.LEFT, padx=(10, 2))
        ttk.Checkbutton(toolbar, text="Dock",
                        variable=self.dock_var,
                        command=self.app._dock_memory_map_window).pack(side=tk.LEFT, padx=2)
        ttk.Label(toolbar, text="Filter:", style='Panel.TLabel').pack(
            side=tk.LEFT, padx=(8, 2))
        entry = ttk.Entry(toolbar, textvariable=self.filter_var,
                          style='Compact.TEntry', width=18)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), pady=4)
        self.filter_var.trace_add('write', lambda *args: self._fill_tree())

        body = tk.PanedWindow(self, orient=tk.VERTICAL, sashwidth=4,
                              bg=app.colors['border'], bd=0, relief=tk.FLAT)
        body.pack(fill=tk.BOTH, expand=True)

        table_frame = tk.Frame(body, bg=app.colors['surface'])
        cols = ('start', 'end', 'size', 'perm', 'offset', 'type', 'section', 'path')
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings', height=12)
        for col, label, width, stretch in (
            ('start', 'Start', 126, False),
            ('end', 'End', 126, False),
            ('size', 'Size', 76, False),
            ('perm', 'Perm', 58, False),
            ('offset', 'Offset', 86, False),
            ('type', 'Type', 72, False),
            ('section', 'Section', 160, True),
            ('path', 'Object / Path', 260, True),
        ):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, minwidth=50, stretch=stretch)
        yscroll = tk.Scrollbar(table_frame, orient=tk.VERTICAL,
                               command=self.tree.yview)
        xscroll = tk.Scrollbar(table_frame, orient=tk.HORIZONTAL,
                               command=self.tree.xview)
        self.tree.config(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        detail_frame = tk.Frame(body, bg=app.colors['surface'])
        self.detail = tk.Text(detail_frame, wrap=tk.WORD, height=7,
                              font=app.font, bg=app.colors['code_bg'],
                              fg=app.colors['fg'],
                              selectbackground=app.colors['select'],
                              selectforeground=app.colors['fg'],
                              state=tk.DISABLED, bd=0, padx=8, pady=6)
        self.detail.pack(fill=tk.BOTH, expand=True)

        body.add(table_frame, minsize=190)
        body.add(detail_frame, minsize=90)

        self._ctx_menu = app._make_menu(self)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Double-1>', lambda event: self._open_selected_start())
        self.tree.bind('<Button-3>', self._on_right_click)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.app._dock_memory_map_window()
        self.app._refresh_memory_map()

    def refresh_maps(self, maps):
        self._maps = list(maps or [])
        self._fill_tree()

    def _fill_tree(self):
        query = self.filter_var.get().strip().lower()
        readable_only = self.readable_var.get()
        self._filtered_maps = []
        self.tree.delete(*self.tree.get_children())
        for row in self._maps:
            if readable_only and not row.get('readable'):
                continue
            haystack = ' '.join(str(row.get(k, '')) for k in (
                'start', 'end', 'size', 'perm', 'offset', 'type', 'section', 'path'
            )).lower()
            if query and query not in haystack:
                continue
            idx = len(self._filtered_maps)
            self._filtered_maps.append(row)
            self.tree.insert('', tk.END, iid=str(idx),
                             values=(row.get('start', ''), row.get('end', ''),
                                     row.get('size', ''), row.get('perm', ''),
                                     row.get('offset', ''), row.get('type', ''),
                                     row.get('section', ''),
                                     row.get('path', '')))
        self._on_select()

    def _selected_map(self):
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return self._filtered_maps[int(sel[0])]
        except (ValueError, IndexError):
            return None

    def _on_select(self, event=None):
        row = self._selected_map()
        self.detail.config(state=tk.NORMAL)
        self.detail.delete('1.0', tk.END)
        if row:
            lines = [
                f"Range: {row.get('start', '')} - {row.get('end', '')}",
                f"Size: {row.get('size', '')}",
                f"Permissions: {row.get('perm', '')}",
                f"Offset: {row.get('offset', '')}",
                f"Type: {row.get('type', '')}",
                f"Object: {row.get('path', '')}",
            ]
            sections = row.get('sections', [])
            if sections:
                lines.append("")
                lines.append("Sections:")
                for sec in sections:
                    lines.append(
                        f"{sec.get('name', '')}  "
                        f"offset=0x{sec.get('offset', 0):x}  "
                        f"vma=0x{sec.get('addr', 0):x}  "
                        f"size=0x{sec.get('size', 0):x}  "
                        f"flags={sec.get('flags', '')}"
                    )
            if not row.get('readable'):
                lines.append("Read access: unavailable")
            self.detail.insert(tk.END, '\n'.join(lines))
        self.detail.config(state=tk.DISABLED)

    def _open_selected_start(self):
        row = self._selected_map()
        if row and row.get('readable'):
            self.app._open_address_in_memory(row.get('start', ''))

    def _dump_selected_range(self):
        row = self._selected_map()
        if row and row.get('readable'):
            self.app.mem_panel._dump_range_to_file(row.get('start', ''),
                                                   row.get('end', ''))

    def _copy_selected_range(self):
        row = self._selected_map()
        if not row:
            return
        self.clipboard_clear()
        self.clipboard_append(f"{row.get('start', '')}-{row.get('end', '')}")

    def _copy_selected_sections(self):
        row = self._selected_map()
        if not row:
            return
        self.clipboard_clear()
        self.clipboard_append(row.get('section', ''))

    def _on_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        row = self._selected_map()
        if not row:
            return
        self._ctx_menu.delete(0, tk.END)
        state = tk.NORMAL if row.get('readable') else tk.DISABLED
        self.app._menu_command(self._ctx_menu, '▦', "Open Start in Memory",
                               command=self._open_selected_start, state=state)
        self.app._menu_command(self._ctx_menu, '⇩', "Dump Range...",
                               command=self._dump_selected_range, state=state)
        self.app._menu_command(self._ctx_menu, '⧉', "Copy Range",
                               command=self._copy_selected_range)
        self.app._menu_command(self._ctx_menu, '⧉', "Copy Section Names",
                               command=self._copy_selected_sections)
        self._ctx_menu.tk_popup(event.x_root, event.y_root)

    def _on_close(self):
        self.app._memory_map_window = None
        self.destroy()


class StackTracePanel(tk.Frame):
    """Combined call-frame and stack-memory view."""

    def __init__(self, parent, app):
        super().__init__(parent, bg=app.colors['surface'])
        self.app = app
        self._selected_level = None
        self._selected_sp = None
        self._selected_bp = None
        self._frame_regs = {}
        self._loading = False

        toolbar = tk.Frame(self, bg=app.colors['panel_header'])
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Refresh", command=self._refresh_selected,
                   style='Small.TButton').pack(side=tk.LEFT, padx=(8, 2), pady=4)
        ttk.Label(toolbar, text="Bytes:", style='Panel.TLabel'
                  ).pack(side=tk.LEFT, padx=(8, 2))
        self.bytes_var = tk.StringVar(value='256')
        bytes_combo = ttk.Combobox(toolbar, textvariable=self.bytes_var,
                                   values=['128', '256', '512'],
                                   width=5, state='readonly')
        bytes_combo.pack(side=tk.LEFT, pady=4)
        bytes_combo.bind('<<ComboboxSelected>>',
                         lambda event: self._refresh_selected())
        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="Follow selected frame",
                        variable=self.follow_var,
                        command=self._refresh_selected).pack(
                            side=tk.LEFT, padx=(10, 2), pady=4)
        self.app._add_panel_close_button(toolbar, 'Stack Trace')

        pane = tk.PanedWindow(self, orient=tk.VERTICAL, sashwidth=4,
                              bg=app.colors['border'], bd=0, relief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True)

        frame_box = tk.Frame(pane, bg=app.colors['surface'])
        stack_box = tk.Frame(pane, bg=app.colors['surface'])
        pane.add(frame_box, minsize=90, height=130)
        pane.add(stack_box, minsize=100)

        frame_cols = ('level', 'func', 'file', 'pc', 'sp', 'bp')
        self.frame_tree = ttk.Treeview(frame_box, columns=frame_cols,
                                       show='headings', height=4)
        for col, label, width in (
            ('level', '#', 36),
            ('func', 'Function', 140),
            ('file', 'File:Line', 130),
            ('pc', 'PC', 116),
            ('sp', 'SP', 116),
            ('bp', 'BP', 116),
        ):
            self.frame_tree.heading(col, text=label)
            self.frame_tree.column(col, width=width, minwidth=36,
                                   stretch=col in ('func', 'file'))
        frame_scroll = tk.Scrollbar(frame_box, orient=tk.VERTICAL,
                                    command=self.frame_tree.yview)
        self.frame_tree.config(yscrollcommand=frame_scroll.set)
        frame_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.frame_tree.pack(fill=tk.BOTH, expand=True)
        self.frame_tree.bind('<<TreeviewSelect>>', self._on_frame_selected)

        stack_cols = ('addr', 'offset', 'qword', 'ascii', 'hint')
        self.stack_tree = ttk.Treeview(stack_box, columns=stack_cols,
                                       show='headings', height=6)
        for col, label, width in (
            ('addr', 'Address', 132),
            ('offset', '+Offset', 64),
            ('qword', 'Qword', 138),
            ('ascii', 'ASCII', 92),
            ('hint', 'Hint', 120),
        ):
            self.stack_tree.heading(col, text=label)
            self.stack_tree.column(col, width=width, minwidth=50,
                                   stretch=col == 'hint')
        stack_vscroll = tk.Scrollbar(stack_box, orient=tk.VERTICAL,
                                     command=self.stack_tree.yview)
        stack_hscroll = tk.Scrollbar(stack_box, orient=tk.HORIZONTAL,
                                     command=self.stack_tree.xview)
        self.stack_tree.config(yscrollcommand=stack_vscroll.set,
                               xscrollcommand=stack_hscroll.set)
        stack_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        stack_vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.stack_tree.pack(fill=tk.BOTH, expand=True)

    def refresh_frames(self, state):
        current = self._selected_level
        self.frame_tree.delete(*self.frame_tree.get_children())
        for frame in state.frames:
            level = str(frame.get('level', ''))
            file_name = frame.get('file', '')
            line = frame.get('line', '')
            file_str = f"{file_name}:{line}" if file_name else ''
            regs = self._frame_regs.get(level, {})
            self.frame_tree.insert('', tk.END, iid=level,
                                   values=(
                                       level,
                                       frame.get('func', '??'),
                                       file_str,
                                       frame.get('addr', ''),
                                       regs.get('sp', ''),
                                       regs.get('bp', ''),
                                   ))
        children = self.frame_tree.get_children()
        if not children:
            self._clear_stack()
            return
        wanted = current if current in children else children[0]
        self.frame_tree.selection_set(wanted)
        self.frame_tree.focus(wanted)
        if self.follow_var.get():
            self._load_selected_frame(wanted)

    def _on_frame_selected(self, event=None):
        sel = self.frame_tree.selection()
        if sel and self.follow_var.get():
            self._load_selected_frame(sel[0])

    def _refresh_selected(self):
        sel = self.frame_tree.selection()
        if sel:
            self._load_selected_frame(sel[0])

    def _load_selected_frame(self, level):
        if self._loading:
            return
        self._loading = True
        self._selected_level = str(level)
        self.app.gdb.send_cmd(f'-stack-select-frame {level}',
                              callback=lambda record, lvl=str(level):
                              self._on_frame_selected_done(record, lvl))

    def _on_frame_selected_done(self, record, level):
        self._loading = False
        if record.get('cls') != 'done':
            return
        self._selected_sp = None
        self._selected_bp = None
        self._eval_register('$rsp',
                            lambda r, lvl=level: self._on_sp_eval(r, lvl))
        self._eval_register('$rbp',
                            lambda r, lvl=level: self._on_bp_eval(r, lvl))

    def _eval_register(self, expr, callback):
        self.app.gdb.send_cmd(f'-data-evaluate-expression {expr}',
                              callback=callback)

    def _on_sp_eval(self, record, level):
        self._selected_sp = self._extract_eval_addr(record)
        self._remember_frame_reg(level, 'sp', self._selected_sp)
        self._read_stack_if_ready()

    def _on_bp_eval(self, record, level):
        self._selected_bp = self._extract_eval_addr(record)
        self._remember_frame_reg(level, 'bp', self._selected_bp)
        self._read_stack_if_ready()

    def _remember_frame_reg(self, level, name, value):
        regs = self._frame_regs.setdefault(str(level), {})
        regs[name] = f'0x{value:x}' if value is not None else ''
        if self.frame_tree.exists(str(level)):
            vals = list(self.frame_tree.item(str(level), 'values'))
            idx = 4 if name == 'sp' else 5
            vals[idx] = regs[name]
            self.frame_tree.item(str(level), values=vals)

    def _read_stack_if_ready(self):
        if self._selected_sp is None or self._selected_bp is None:
            return
        size = int(self.bytes_var.get())
        self.app.gdb.send_cmd(
            f'-data-read-memory-bytes {hex(self._selected_sp)} {size}',
            callback=self._on_stack_memory)

    def _on_stack_memory(self, record):
        if record.get('cls') != 'done':
            return
        payload = record.get('payload', '')
        m = re.search(r'memory=\[\{(.+?)\}\]', payload, re.DOTALL)
        if not m:
            self._clear_stack()
            return
        parsed = parse_mi_tuple(m.group(1))
        start = parsed.get('begin', '0x0')
        contents = parsed.get('contents', '')
        start_int = int(start, 16) if str(start).startswith('0x') else int(start)
        raw_bytes = bytes.fromhex(contents)
        self._format_stack_rows(start_int, raw_bytes)

    def _format_stack_rows(self, start_int, raw_bytes):
        self.stack_tree.delete(*self.stack_tree.get_children())
        frame_pcs = set()
        for frame in self.app.state.frames:
            addr = self._parse_addr(frame.get('addr', ''))
            if addr is not None:
                frame_pcs.add(addr)
        for offset in range(0, len(raw_bytes), 8):
            chunk = raw_bytes[offset:offset + 8]
            if not chunk:
                continue
            row_addr = start_int + offset
            padded = chunk.ljust(8, b'\x00')
            qword = int.from_bytes(padded, byteorder='little', signed=False)
            ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hints = []
            if self._selected_sp is not None and row_addr == self._selected_sp:
                hints.append('SP')
            if self._selected_bp is not None and row_addr == self._selected_bp:
                hints.append('BP')
            if qword in frame_pcs:
                hints.append('code ptr')
            rel = row_addr - self._selected_sp if self._selected_sp is not None else offset
            rel_text = f'+0x{rel:x}' if rel >= 0 else f'-0x{abs(rel):x}'
            self.stack_tree.insert('', tk.END,
                                   values=(
                                       f'0x{row_addr:016x}',
                                       rel_text,
                                       f'0x{qword:016x}',
                                       ascii_text,
                                       ', '.join(hints),
                                   ))

    def _clear_stack(self):
        self.stack_tree.delete(*self.stack_tree.get_children())

    @staticmethod
    def _parse_addr(value):
        if not value:
            return None
        m = re.search(r'0x[0-9a-fA-F]+', str(value))
        if not m:
            return None
        try:
            return int(m.group(0), 16)
        except ValueError:
            return None

    def _extract_eval_addr(self, record):
        if record.get('cls') != 'done':
            return None
        payload = record.get('payload', '')
        m = re.search(r'value="([^"]+)"', payload)
        if not m:
            return None
        return self._parse_addr(m.group(1))


class NGdbApp(tk.Tk):
    """Main application window."""

    _DEFAULT_BREAKPOINT_OPTIONS = (
        ('entry', 'Entry point from symbols (info files fallback)', None, True),
        ('main', 'main', 'main', False),
        ('libc_start', '__libc_start_main', '__libc_start_main', False),
        ('dlopen', 'dlopen', 'dlopen', False),
        ('libc_dlopen', '__libc_dlopen_mode', '__libc_dlopen_mode', False),
        ('dl_debug_state', '_dl_debug_state', '_dl_debug_state', False),
        ('loadlibrary_a', 'LoadLibraryA', 'LoadLibraryA', False),
        ('loadlibrary_w', 'LoadLibraryW', 'LoadLibraryW', False),
        ('loadlibrary_ex_a', 'LoadLibraryExA', 'LoadLibraryExA', False),
        ('loadlibrary_ex_w', 'LoadLibraryExW', 'LoadLibraryExW', False),
    )
    _ENTRY_POINT_SYMBOLS = (
        '_start',
        'start',
        '__start',
        'mainCRTStartup',
        'WinMainCRTStartup',
        'wmainCRTStartup',
        'wWinMainCRTStartup',
    )

    def __init__(self):
        super().__init__()
        self.title("N-gdb")
        self.geometry("1280x800")
        self.minsize(960, 600)
        self._create_app_icon()

        self.output_queue = Queue()
        self.gdb = GDBMiClient(self.output_queue)
        self.state = DebugState()
        self._toolbar_mode = 'empty'
        self._stop_requested = False
        self._program_args = ''
        self._debug_options = self._default_debug_options()
        self._default_bp_requests = set()
        self._info_files_capture = None
        self._memory_map_capture = None
        self._memory_map_window = None
        self._section_cache = {}

        self.colors = {
            'bg': '#F6F8FA',
            'surface': '#FFFFFF',
            'code_bg': '#FAFBFC',
            'fg': '#24292F',
            'muted_fg': '#57606A',
            'panel_bg': '#F6F8FA',
            'panel_header': '#F6F8FA',
            'highlight': '#FFF8C5',
            'goto_highlight': '#DAFBE1',
            'bp_marker': '#CF222E',
            'changed': '#CF222E',
            'toolbar_bg': '#FFFFFF',
            'status_bg': '#F6F8FA',
            'status_fg': '#24292F',
            'border': '#D0D7DE',
            'accent': '#0969DA',
            'accent_hover': '#0757B8',
            'danger': '#CF222E',
            'danger_hover': '#A40E26',
            'success': '#1A7F37',
            'warning': '#9A6700',
            'select': '#DDF4FF',
            'tab_selected': '#DDF4FF',
            'input_bg': '#FFFFFF',
            'input_disabled': '#F6F8FA',
            'status_running': '#1A7F37',
            'status_stopped': '#9A6700',
            'status_error': '#CF222E',
        }
        self.configure(bg=self.colors['bg'])
        self.font = ('Consolas', 10) if sys.platform == 'win32' else ('Courier', 10)
        self.font_bold = ('Consolas', 10, 'bold') if sys.platform == 'win32' else ('Courier', 10, 'bold')
        self._ui_font = ('Segoe UI', 9) if sys.platform == 'win32' else ('TkDefaultFont', 10)

        # Apply ttk theme for better look on all platforms
        self._setup_theme()

        self._create_menu()
        self._create_toolbar()
        self._create_panels()
        self._create_statusbar()
        self._bind_shortcuts()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind('<Configure>', self._dock_memory_map_window)
        self._poll_queue()

    def _create_app_icon(self):
        """Generate a debugger icon programmatically (no external file).
        Sets icon for both title bar and taskbar on Linux/Windows."""
        s = 48
        icon = tk.PhotoImage(width=s, height=s)
        bg = '#1e1e3a'
        border = '#3a3a5c'
        green = '#00e676'
        green_dark = '#00a854'
        red = '#ff1744'

        # Triangle: play button — scale to 48x48
        tx1, ty1 = 12, 9
        tx2, ty2 = 12, 39
        tx3, ty3 = 36, 24

        # Breakpoint circle
        cx, cy, cr = 38, 12, 6

        for y in range(s):
            row = []
            for x in range(s):
                in_corner = False
                for cex, cey in [(2, 2), (s - 3, 2), (2, s - 3), (s - 3, s - 3)]:
                    if (x - cex) ** 2 + (y - cey) ** 2 < 12:
                        in_corner = True
                        break

                if in_corner:
                    row.append(bg)
                elif x == 0 or y == 0 or x == s - 1 or y == s - 1:
                    row.append(border)
                elif (x - cx) ** 2 + (y - cy) ** 2 <= cr * cr:
                    row.append(red)
                elif self._pt_in_tri(x, y, tx1, ty1, tx2, ty2, tx3, ty3):
                    if not self._pt_in_tri(x, y, tx1 + 2, ty1 + 2,
                                           tx2 + 2, ty2 - 2, tx3 - 2, ty3):
                        row.append(green_dark)
                    else:
                        row.append(green)
                else:
                    row.append(bg)
            icon.put('{' + ' '.join(row) + '}', to=(0, y))

        # Keep reference to prevent GC
        self._app_icon = icon
        # iconphoto: works for taskbar on most platforms
        self.iconphoto(True, icon)
        # On Linux, also write a temp .xbm for title bar icon
        if sys.platform.startswith('linux'):
            try:
                import tempfile
                xbm_path = os.path.join(tempfile.gettempdir(), 'ngdb_icon.xbm')
                self._write_xbm(xbm_path, s)
                self.iconbitmap('@' + xbm_path)
            except Exception:
                pass

    def _write_xbm(self, path, size):
        """Write a minimal XBM for the title bar icon (monochrome)."""
        lines = [f'#define ngdb_width {size}', f'#define ngdb_height {size}',
                 'static unsigned char ngdb_bits[] = {']
        for y in range(size):
            byte_row = 0
            bits = []
            for x in range(size):
                # 1 = foreground (drawn), 0 = background
                # Simple: anything not bg color is foreground
                if not (x == 0 or y == 0 or x == size - 1 or y == size - 1):
                    # Triangle check
                    tx1, ty1 = 12, 9
                    tx2, ty2 = 12, 39
                    tx3, ty3 = 36, 24
                    cx, cy, cr = 38, 12, 6
                    in_tri = self._pt_in_tri(x, y, tx1, ty1, tx2, ty2, tx3, ty3)
                    in_circle = (x - cx) ** 2 + (y - cy) ** 2 <= cr * cr
                    if in_tri or in_circle:
                        byte_row |= (1 << (x % 8))
                if (x + 1) % 8 == 0 or x == size - 1:
                    bits.append(f'0x{byte_row:02x}')
                    byte_row = 0
            lines.append('    ' + ', '.join(bits) + ',')
        lines.append('};')
        with open(path, 'w') as f:
            f.write('\n'.join(lines))

    @staticmethod
    def _pt_in_tri(px, py, x1, y1, x2, y2, x3, y3):
        def sign(ax, ay, bx, by, cx, cy):
            return (ax - cx) * (by - cy) - (bx - cx) * (ay - cy)
        d1 = sign(px, py, x1, y1, x2, y2)
        d2 = sign(px, py, x2, y2, x3, y3)
        d3 = sign(px, py, x3, y3, x1, y1)
        has_neg = (d1 < 0) or (d2 < 0) or (d3 < 0)
        has_pos = (d1 > 0) or (d2 > 0) or (d3 > 0)
        return not (has_neg and has_pos)

    def _setup_theme(self):
        style = ttk.Style(self)
        available = style.theme_names()
        if 'clam' in available:
            style.theme_use('clam')
        elif 'alt' in available:
            style.theme_use('alt')

        ui_font = self._ui_font
        c = self.colors
        # === Global styles ===
        style.configure('.', font=ui_font, background=c['bg'], foreground=c['fg'])
        style.configure('TFrame', background=c['bg'])
        style.configure('Surface.TFrame', background=c['surface'])
        style.configure('Prompt.TLabel', font=self.font, background=c['surface'],
                        foreground=c['muted_fg'])

        # === Toolbar ===
        style.configure('Toolbar.TFrame', background=c['toolbar_bg'])
        style.configure('Tool.TButton', padding=(12, 5), font=ui_font,
                        background=c['surface'], foreground=c['fg'],
                        bordercolor=c['border'], lightcolor=c['border'],
                        darkcolor=c['border'], borderwidth=1, relief=tk.FLAT)
        style.map('Tool.TButton',
                  background=[('active', '#F0F3F6'), ('pressed', '#EAEEF2'),
                              ('disabled', c['panel_bg'])],
                  foreground=[('disabled', '#8C959F')])
        style.configure('Primary.Tool.TButton', padding=(12, 5), font=ui_font,
                        background=c['accent'], foreground='#FFFFFF',
                        bordercolor=c['accent'], lightcolor=c['accent'],
                        darkcolor=c['accent'], borderwidth=1, relief=tk.FLAT)
        style.map('Primary.Tool.TButton',
                  background=[('active', c['accent_hover']), ('pressed', '#054DA7'),
                              ('disabled', '#B6D7F8')],
                  foreground=[('disabled', '#FFFFFF')])
        style.configure('Danger.Tool.TButton', padding=(12, 5), font=ui_font,
                        background=c['danger'], foreground='#FFFFFF',
                        bordercolor=c['danger'], lightcolor=c['danger'],
                        darkcolor=c['danger'], borderwidth=1, relief=tk.FLAT)
        style.map('Danger.Tool.TButton',
                  background=[('active', c['danger_hover']), ('pressed', '#82071E'),
                              ('disabled', '#F1B8C0')],
                  foreground=[('disabled', '#FFFFFF')])

        # === Small panel buttons ===
        style.configure('Small.TButton', padding=(9, 3), font=ui_font,
                        background=c['surface'], foreground=c['fg'],
                        bordercolor=c['border'], lightcolor=c['border'],
                        darkcolor=c['border'], borderwidth=1, relief=tk.FLAT)
        style.map('Small.TButton',
                  background=[('active', '#F0F3F6'), ('pressed', '#EAEEF2')],
                  foreground=[('disabled', '#8C959F')])
        style.configure('PanelClose.TButton', padding=(4, 1), font=ui_font,
                        background=c['panel_header'], foreground=c['muted_fg'],
                        bordercolor=c['panel_header'], lightcolor=c['panel_header'],
                        darkcolor=c['panel_header'], borderwidth=0, relief=tk.FLAT)
        style.map('PanelClose.TButton',
                  background=[('active', c['select']), ('pressed', c['select'])],
                  foreground=[('active', c['danger']), ('pressed', c['danger'])])

        # === Entry fields ===
        style.configure('Compact.TEntry', padding=(8, 5),
                        fieldbackground=c['input_bg'], foreground=c['fg'],
                        insertcolor=c['fg'], selectbackground=c['select'],
                        selectforeground=c['fg'], bordercolor=c['border'],
                        lightcolor=c['border'], darkcolor=c['border'])
        style.map('Compact.TEntry',
                  fieldbackground=[('disabled', c['input_disabled'])],
                  foreground=[('disabled', c['muted_fg'])],
                  bordercolor=[('focus', c['accent'])],
                  lightcolor=[('focus', c['accent'])],
                  darkcolor=[('focus', c['accent'])])

        # === Panel headers ===
        hdr_font = (ui_font[0], ui_font[1], 'bold') if len(ui_font) > 1 else ('TkDefaultFont', 10, 'bold')
        style.configure('Panel.TLabel', font=hdr_font, background=c['panel_header'],
                        foreground=c['muted_fg'], padding=(8, 5))

        # === Status bar ===
        style.configure('Status.TLabel', font=ui_font,
                        background=c['status_bg'], foreground=c['status_fg'],
                        padding=(10, 4))

        # === Treeview (breakpoints, call stack, threads, locals) ===
        style.configure('Treeview', background=c['surface'], foreground=c['fg'],
                        fieldbackground=c['surface'], rowheight=26,
                        borderwidth=0, font=ui_font)
        style.configure('Treeview.Heading', font=hdr_font,
                        background=c['panel_header'], foreground=c['muted_fg'],
                        bordercolor=c['border'], borderwidth=1, relief=tk.FLAT,
                        padding=(6, 5))
        style.map('Treeview',
                  background=[('selected', c['select'])],
                  foreground=[('selected', c['fg'])])
        style.map('Treeview.Heading',
                  background=[('active', '#EAEEF2')])

        # === Notebook tabs ===
        style.configure('TNotebook', background=c['panel_bg'], borderwidth=0)
        style.configure('TNotebook.Tab', font=ui_font, padding=(14, 6),
                        background=c['panel_bg'], borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', c['tab_selected']), ('!selected', c['panel_bg'])],
                  foreground=[('selected', c['accent']), ('!selected', c['muted_fg'])],
                  expand=[('selected', (0, 0, 0, 0))])

        # === Combobox ===
        style.configure('TCombobox', padding=(6, 4),
                        fieldbackground=c['input_bg'], foreground=c['fg'],
                        bordercolor=c['border'], arrowcolor=c['muted_fg'])

        # === Scrollbar ===
        style.configure('TScrollbar', background=c['panel_bg'],
                        troughcolor=c['surface'], borderwidth=0, arrowsize=13)
        style.map('TScrollbar',
                  background=[('active', '#AFB8C1')])

    def _make_menu(self, parent):
        c = self.colors
        return tk.Menu(parent, tearoff=0,
                       bg=c['surface'],
                       fg=c['fg'],
                       activebackground=c['select'],
                       activeforeground=c['accent'],
                       disabledforeground=c['muted_fg'],
                       selectcolor=c['accent'],
                       relief=tk.FLAT,
                       bd=1,
                       activeborderwidth=0,
                       font=self._ui_font)

    def _menu_label(self, icon, text):
        return f"{icon}  {text}" if icon else text

    def _menu_command(self, menu, icon, label, command=None,
                      accelerator=None, state=tk.NORMAL):
        options = {
            'label': self._menu_label(icon, label),
            'state': state,
        }
        if command is not None:
            options['command'] = command
        if accelerator:
            options['accelerator'] = accelerator
        menu.add_command(**options)

    def _menu_checkbutton(self, menu, icon, label, variable, command):
        menu.add_checkbutton(label=self._menu_label(icon, label),
                             variable=variable,
                             command=command)

    def _menu_cascade(self, menu, icon, label, submenu):
        menu.add_cascade(label=self._menu_label(icon, label), menu=submenu)

    def _create_menu(self):
        menubar = self._make_menu(self)

        file_menu = self._make_menu(menubar)
        self._menu_command(file_menu, '▣', "Open Executable...",
                           command=self._open_file, accelerator="Ctrl+O")
        self._menu_command(file_menu, '⇄', "Attach to Process...",
                           command=self._open_attach_process_dialog)
        self._recent_menu = self._make_menu(file_menu)
        self._menu_cascade(file_menu, '◷', "Recent Files", self._recent_menu)
        file_menu.add_separator()
        self._menu_command(file_menu, '×', "Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        # Load recent files config
        self._config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ngdb.json')
        self._recent_files = self._load_recent_files()
        self._refresh_recent_menu()

        view_menu = self._make_menu(menubar)
        self._view_vars = {}
        for name in ('Disassembly', 'Registers', 'Call Stack', 'Memory',
                      'Breakpoints', 'Locals/Watch', 'Threads', 'Stack Trace', 'Libraries'):
            var = tk.BooleanVar(value=(name != 'Call Stack'))
            self._view_vars[name] = var
            self._menu_checkbutton(view_menu, '▦', name, var,
                                   command=lambda n=name: self._toggle_panel(n))
        view_menu.add_separator()
        self._menu_command(view_menu, '▦', "Memory Map...",
                           command=self._open_memory_map_window)
        menubar.add_cascade(label="View", menu=view_menu)

        debug_menu = self._make_menu(menubar)
        self._menu_command(debug_menu, '▶', "Run / Continue",
                           command=self._cmd_run, accelerator="F9 / F5")
        self._menu_command(debug_menu, '⏸', "Break",
                           command=self._cmd_break, accelerator="F12")
        debug_menu.add_separator()
        self._menu_command(debug_menu, '↧', "Step Into",
                           command=lambda: self._cmd_step('into'),
                           accelerator="F7 / F11")
        self._menu_command(debug_menu, '↷', "Step Over",
                           command=lambda: self._cmd_step('over'),
                           accelerator="F8 / F10")
        self._menu_command(debug_menu, '↥', "Step Out",
                           command=self._cmd_step_out,
                           accelerator="Shift+F8 / Shift+F11")
        debug_menu.add_separator()
        self._menu_command(debug_menu, '●', "Toggle Breakpoint",
                           command=self._toggle_bp, accelerator="F2")
        debug_menu.add_separator()
        self._menu_command(debug_menu, '■', "Stop",
                           command=self._cmd_stop,
                           accelerator="Alt+F2 / Shift+F5")
        self._menu_command(debug_menu, '⟲', "Restart",
                           command=self._cmd_restart, accelerator="Ctrl+F2")
        debug_menu.add_separator()
        self._menu_command(debug_menu, '⚙', "Options...",
                           command=self._open_debug_options_dialog)
        menubar.add_cascade(label="Debug", menu=debug_menu)

        help_menu = self._make_menu(menubar)
        self._menu_command(help_menu, 'ⓘ', "About N-gdb", command=self._about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _create_toolbar(self):
        toolbar = tk.Frame(self, bg=self.colors['toolbar_bg'], bd=0, relief=tk.FLAT)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        buttons = [
            ("▶ Run (F9)", self._cmd_run),
            ("⏸ Break (F12)", self._cmd_break),
            ("⏭ Over (F8)", lambda: self._cmd_step('over')),
            ("⏬ Into (F7)", lambda: self._cmd_step('into')),
            ("⏫ Out (S-F8)", self._cmd_step_out),
            ("■ Stop (Alt+F2)", self._cmd_stop),
            ("⟲ Restart (Ctrl+F2)", self._cmd_restart),
        ]
        self._run_btn = None
        self._run_menu_btn = None
        self._run_menu = None
        self._toolbar_buttons = []
        self._toolbar_button_roles = []
        for text, cmd in buttons:
            style_name = 'Tool.TButton'
            role = 'debug'
            if "Run" in text:
                style_name = 'Primary.Tool.TButton'
                role = 'run'
            elif "Stop" in text:
                style_name = 'Danger.Tool.TButton'
            b = ttk.Button(toolbar, text=text, command=cmd, style=style_name)
            b.pack(side=tk.LEFT, padx=(8 if not self._toolbar_buttons else 4, 0), pady=6)
            b.state(['disabled'])
            self._toolbar_buttons.append(b)
            self._toolbar_button_roles.append(role)
            if "Run" in text:
                self._run_btn = b
                self._run_menu_btn = ttk.Button(
                    toolbar, text="▾", command=self._show_run_menu,
                    style='Primary.Tool.TButton', width=2)
                self._run_menu_btn.pack(side=tk.LEFT, padx=(1, 0), pady=6)
                self._run_menu_btn.state(['disabled'])
                self._toolbar_buttons.append(self._run_menu_btn)
                self._toolbar_button_roles.append('run-options')
                self._run_menu = self._make_menu(toolbar)
                self._menu_command(self._run_menu, '▶', "Run with Arguments...",
                                   command=self._cmd_run_with_args)
                self._menu_command(self._run_menu, '✎', "Edit Arguments...",
                                   command=self._edit_run_args)
                self._menu_command(self._run_menu, '×', "Clear Arguments",
                                   command=self._clear_run_args)
        self._set_toolbar_mode('empty')

        # Thin separator line below toolbar
        sep = tk.Frame(self, height=1, bg=self.colors['border'])
        sep.pack(side=tk.TOP, fill=tk.X)

    def _create_panels(self):
        self.vpane = tk.PanedWindow(self, orient=tk.VERTICAL, sashwidth=4,
                                     bg=self.colors['border'], bd=0, relief=tk.FLAT)
        self.vpane.pack(fill=tk.BOTH, expand=True)

        self.hpane_top = tk.PanedWindow(self.vpane, orient=tk.HORIZONTAL,
                                         sashwidth=4, bg=self.colors['border'],
                                         bd=0, relief=tk.FLAT)
        self.vpane.add(self.hpane_top, minsize=200)

        self.hpane_bot = tk.PanedWindow(self.vpane, orient=tk.HORIZONTAL,
                                         sashwidth=4, bg=self.colors['border'],
                                         bd=0, relief=tk.FLAT)
        self.vpane.add(self.hpane_bot, minsize=150)

        self.right_vpane = tk.PanedWindow(self.hpane_top, orient=tk.VERTICAL,
                                      sashwidth=4, bg=self.colors['border'],
                                      bd=0, relief=tk.FLAT)

        self.disasm_panel = DisassemblyPanel(self.hpane_top, self)
        self.reg_panel = RegisterPanel(self.right_vpane, self)
        self.stack_panel = CallStackPanel(self.right_vpane, self)

        self.notebook = ttk.Notebook(self.right_vpane)
        self.bp_panel = BreakpointPanel(self.notebook, self)
        self.locals_panel = LocalsWatchPanel(self.notebook, self)
        self.thread_panel = ThreadPanel(self.notebook, self)
        self.stack_trace_panel = StackTracePanel(self.notebook, self)
        self.library_panel = LibraryPanel(self.notebook, self)
        self.notebook.add(self.bp_panel, text="Breakpoints")
        self.notebook.add(self.locals_panel, text="Locals/Watch")
        self.notebook.add(self.thread_panel, text="Threads")
        self.notebook.add(self.stack_trace_panel, text="Stack Trace")
        self.notebook.add(self.library_panel, text="Libraries")

        self.right_vpane.add(self.reg_panel, minsize=120)
        self.right_vpane.add(self.stack_panel, minsize=80)
        self.right_vpane.add(self.notebook, minsize=180)

        self.console_panel = ConsolePanel(self.hpane_bot, self)
        self.mem_panel = MemoryPanel(self.hpane_bot, self)

        self.hpane_top.add(self.disasm_panel, minsize=300, width=600)
        self.hpane_top.add(self.right_vpane, minsize=250, width=400)
        self.hpane_bot.add(self.console_panel, minsize=200, width=600)
        self.hpane_bot.add(self.mem_panel, minsize=200, width=400)

        # Complete ordered children per pane: [(widget, cfg_dict), ...]
        # Used to rebuild pane in correct order when toggling visibility
        self._pane_children = {
            self.hpane_top: [
                (self.disasm_panel, {'minsize': 300, 'width': 600}),
                (self.right_vpane, {'minsize': 250, 'width': 400}),
            ],
            self.hpane_bot: [
                (self.console_panel, {'minsize': 200, 'width': 600}),
                (self.mem_panel, {'minsize': 200, 'width': 400}),
            ],
            self.right_vpane: [
                (self.reg_panel, {'minsize': 120}),
                (self.stack_panel, {'minsize': 80}),
                (self.notebook, {'minsize': 180}),
            ],
        }
        # Toggleable panels: name -> (pane, panel)
        self._panel_cfg = {
            'Disassembly': (self.hpane_top, self.disasm_panel),
            'Memory': (self.hpane_bot, self.mem_panel),
            'Registers': (self.right_vpane, self.reg_panel),
            'Call Stack': (self.right_vpane, self.stack_panel),
        }
        # Reverse map: widget -> toggle name (None = always visible)
        self._widget_toggle = {}
        for name, (pane, panel) in self._panel_cfg.items():
            self._widget_toggle[panel] = name
        self._tab_cfg = {
            'Breakpoints': (self.notebook, self.bp_panel, "Breakpoints"),
            'Locals/Watch': (self.notebook, self.locals_panel, "Locals/Watch"),
            'Threads': (self.notebook, self.thread_panel, "Threads"),
            'Stack Trace': (self.notebook, self.stack_trace_panel, "Stack Trace"),
            'Libraries': (self.notebook, self.library_panel, "Libraries"),
        }
        self._apply_initial_panel_visibility()

    def _create_statusbar(self):
        status = tk.Frame(self, bd=0, bg=self.colors['status_bg'],
                          highlightthickness=1,
                          highlightbackground=self.colors['border'])
        status.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_target = ttk.Label(status, text="Target: (none)",
                                       style='Status.TLabel', anchor=tk.W)
        self.status_target.pack(side=tk.LEFT, padx=4)
        self.status_pid = ttk.Label(status, text="PID: -",
                                    style='Status.TLabel', anchor=tk.W)
        self.status_pid.pack(side=tk.LEFT, padx=4)
        self.status_thread = ttk.Label(status, text="Thread: -",
                                       style='Status.TLabel', anchor=tk.W)
        self.status_thread.pack(side=tk.LEFT, padx=4)
        self.status_state = ttk.Label(status, text="Idle",
                                      style='Status.TLabel', anchor=tk.E)
        self.status_state.config(foreground=self.colors['muted_fg'])
        self.status_state.pack(side=tk.RIGHT, padx=4)

    def _bind_shortcuts(self):
        # x64dbg style shortcuts (primary)
        self.bind('<F9>', lambda e: self._cmd_run())
        self.bind('<F7>', lambda e: self._cmd_step('into'))
        self.bind('<F8>', lambda e: self._cmd_step('over'))
        self.bind('<Shift-F8>', lambda e: self._cmd_step_out())
        self.bind('<Alt-F2>', lambda e: self._cmd_stop())
        self.bind('<Control-F2>', lambda e: self._cmd_restart())
        self.bind('<F12>', lambda e: self._cmd_break())
        self.bind('<F2>', lambda e: self._toggle_bp())
        # VS/WinDbg style shortcuts (also kept)
        self.bind('<F5>', lambda e: self._cmd_run())
        self.bind('<F10>', lambda e: self._cmd_step('over'))
        self.bind('<F11>', lambda e: self._cmd_step('into'))
        self.bind('<Shift-F11>', lambda e: self._cmd_step_out())
        self.bind('<Shift-F5>', lambda e: self._cmd_stop())
        self.bind('<Control-Shift-F5>', lambda e: self._cmd_restart())
        # General shortcuts
        self.bind('<Control-o>', lambda e: self._open_file())
        self.bind('<Control-g>', lambda e: self._goto_address())
        self.bind('<Control-b>', lambda e: self._toggle_bp())
        self.bind('<Control-l>', lambda e: self.console_panel.clear())
        self.bind('<Control-Break>', lambda e: self._cmd_break())
        self.bind('<Control-Pause>', lambda e: self._cmd_break())
        self.bind('<Escape>', self._on_escape_shortcut)

    def _on_escape_shortcut(self, event=None):
        if self._is_text_input_focus():
            return None
        return self._navigate_execution_history_back(event)

    def _is_text_input_focus(self):
        widget = self.focus_get()
        if widget in (getattr(self.disasm_panel, 'text', None),
                      getattr(self.disasm_panel, 'margin', None)):
            return False
        try:
            return widget.winfo_class() in ('Entry', 'TEntry', 'Text',
                                            'Spinbox', 'TSpinbox')
        except (AttributeError, tk.TclError):
            return False

    def _add_panel_close_button(self, header, name):
        ttk.Button(header, text="×",
                   command=lambda n=name: self._hide_panel(n),
                   style='PanelClose.TButton', width=2
                   ).pack(side=tk.RIGHT, padx=(0, 4), pady=2)

    def _hide_panel(self, name):
        var = self._view_vars.get(name)
        if not var:
            return
        var.set(False)
        self._toggle_panel(name)

    def _apply_initial_panel_visibility(self):
        for name, var in self._view_vars.items():
            if not var.get():
                self._toggle_panel(name)

    def _toggle_panel(self, name):
        var = self._view_vars[name]
        if name in self._panel_cfg:
            pane, panel = self._panel_cfg[name]
            if var.get():
                # Forget all children, then re-add visible ones in original order
                for child in pane.panes():
                    pane.forget(child)
                for widget, wcfg in self._pane_children[pane]:
                    toggle = self._widget_toggle.get(widget)
                    if toggle is None or self._view_vars[toggle].get():
                        try:
                            pane.add(widget, **wcfg)
                        except tk.TclError:
                            pass
            else:
                try:
                    pane.forget(panel)
                except tk.TclError:
                    pass
        elif name in self._tab_cfg:
            nb, panel, tab_text = self._tab_cfg[name]
            if var.get():
                try:
                    nb.index(panel)
                except tk.TclError:
                    nb.add(panel, text=tab_text)
            else:
                try:
                    nb.forget(panel)
                except tk.TclError:
                    pass

    def _on_close(self):
        self.gdb.stop()
        self.destroy()

    def _about(self):
        messagebox.showinfo("About N-gdb", "N-gdb v1.0\nWinDbg-style GDB Debugger")

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open Executable",
            filetypes=[("Executables", "*"), ("All files", "*.*")]
        )
        if path:
            self._load_program(path)

    def _load_program(self, path):
        if not os.path.isfile(path):
            messagebox.showerror("Error", f"File not found: {path}")
            return
        if not os.access(path, os.X_OK):
            messagebox.showwarning("Warning",
                                    f"{path} may not be executable. Attempting to load anyway.")
        if not self.gdb.process:
            self.gdb.start()
        self.state = DebugState()
        self.state.target_path = path
        self._stop_requested = False
        self._default_bp_requests.clear()
        self._info_files_capture = None
        self._memory_map_capture = None
        if self._run_btn:
            self._run_btn.config(text="▶ Run (F9)")
        self.status_target.config(text=f"Target: {os.path.basename(path)}")
        self.gdb.send_cmd(f'-file-exec-and-symbols "{path}"')
        self.console_panel.append_output(f"Loaded: {path}\n")
        self._add_recent_file(path)
        # Enable all controls now that a program is loaded
        self._enable_controls()
        self._refresh_import_symbols()

    def _open_attach_process_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Attach to Process")
        dlg.configure(bg=self.colors['surface'])
        dlg.geometry("820x500")
        dlg.minsize(640, 360)
        dlg.transient(self)

        frame = tk.Frame(dlg, bg=self.colors['surface'], padx=12, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)

        filter_var = tk.StringVar()
        manual_pid_var = tk.StringVar()

        ttk.Label(frame, text="Filter:", style='Panel.TLabel').pack(anchor=tk.W)
        filter_entry = ttk.Entry(frame, textvariable=filter_var,
                                 style='Compact.TEntry')
        filter_entry.pack(fill=tk.X, pady=(4, 8))

        tree_frame = tk.Frame(frame, bg=self.colors['surface'])
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ('pid', 'name', 'command')
        tree = ttk.Treeview(tree_frame, columns=cols, show='headings', height=14)
        tree.heading('pid', text='PID')
        tree.heading('name', text='Name')
        tree.heading('command', text='Command')
        tree.column('pid', width=80, minwidth=60, anchor=tk.CENTER, stretch=False)
        tree.column('name', width=180, minwidth=120, stretch=False)
        tree.column('command', width=520, minwidth=220, stretch=True)
        scroll = tk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.config(yscrollcommand=scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        manual = tk.Frame(frame, bg=self.colors['surface'])
        manual.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(manual, text="PID:", style='Panel.TLabel').pack(side=tk.LEFT)
        ttk.Entry(manual, textvariable=manual_pid_var, width=12,
                  style='Compact.TEntry').pack(side=tk.LEFT, padx=(6, 0))

        buttons = tk.Frame(frame, bg=self.colors['surface'])
        buttons.pack(fill=tk.X, pady=(10, 0))

        processes = []

        def fill_tree():
            query = filter_var.get().strip().lower()
            tree.delete(*tree.get_children())
            for proc in processes:
                haystack = ' '.join((
                    proc.get('pid', ''),
                    proc.get('name', ''),
                    proc.get('command', ''),
                )).lower()
                if query and query not in haystack:
                    continue
                tree.insert('', tk.END, iid=proc['pid'],
                            values=(proc['pid'], proc['name'], proc['command']))

        def refresh():
            nonlocal processes
            try:
                processes = self._list_processes()
            except Exception as exc:
                processes = []
                self.console_panel.append_output(
                    f"Failed to list processes: {exc}\n")
            fill_tree()

        def attach():
            sel = tree.selection()
            pid = manual_pid_var.get().strip()
            name = ''
            if sel:
                pid = sel[0]
                values = tree.item(sel[0], 'values')
                if len(values) > 1:
                    name = values[1]
            if not pid:
                messagebox.showerror("Attach Failed", "Select a process or enter a PID.")
                return
            dlg.destroy()
            self._attach_to_process(pid, name)

        def on_select(event=None):
            sel = tree.selection()
            if sel:
                manual_pid_var.set(sel[0])

        ttk.Button(buttons, text="Cancel", command=dlg.destroy,
                   style='Small.TButton').pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(buttons, text="Attach", command=attach,
                   style='Primary.Tool.TButton').pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Refresh", command=refresh,
                   style='Small.TButton').pack(side=tk.LEFT)

        filter_var.trace_add('write', lambda *args: fill_tree())
        tree.bind('<<TreeviewSelect>>', on_select)
        tree.bind('<Double-1>', lambda event: attach())
        filter_entry.bind('<Return>', lambda event: fill_tree())

        refresh()
        filter_entry.focus_set()

    def _list_processes(self):
        processes = []
        if sys.platform == 'win32':
            cmd = [
                'powershell', '-NoProfile', '-Command',
                'Get-CimInstance Win32_Process | '
                'Select-Object ProcessId,Name,CommandLine | '
                'ConvertTo-Json -Compress'
            ]
            output = subprocess.check_output(cmd, text=True, timeout=5)
            if output.strip():
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    pid = str(item.get('ProcessId', '')).strip()
                    if not pid.isdigit():
                        continue
                    processes.append({
                        'pid': pid,
                        'name': item.get('Name') or '',
                        'command': item.get('CommandLine') or '',
                    })
        else:
            ps_cmd = 'ps -eo pid=,comm=,args='
            output = subprocess.check_output(ps_cmd.split(), text=True, timeout=5)
            for line in output.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) < 2 or not parts[0].isdigit():
                    continue
                processes.append({
                    'pid': parts[0],
                    'name': parts[1],
                    'command': parts[2] if len(parts) > 2 else parts[1],
                })
        return sorted(processes, key=lambda p: int(p['pid']))

    def _attach_to_process(self, pid, name=''):
        pid = str(pid).strip()
        if not pid.isdigit():
            messagebox.showerror("Attach Failed", f"Invalid PID: {pid}")
            return
        if not self.gdb.process:
            self.gdb.start()
        label = name or pid
        self._stop_requested = False
        self.status_state.config(text="Attaching...",
                                 foreground=self.colors['accent'])
        self.console_panel.append_output(f"Attaching to process {pid}...\n")
        self.gdb.send_cmd(f'-target-attach {pid}',
            callback=lambda r, p=pid, n=name: self._on_attach_process(r, p, n))

    def _on_attach_process(self, record, pid, name):
        label = name or str(pid)
        if record.get('cls') == 'done':
            self.state = DebugState()
            self.state.pid = str(pid)
            self.state.target_path = f'attached:{label}'
            self.state.running = False
            self._stop_requested = False
            self._memory_map_capture = None
            if self._run_btn:
                self._run_btn.config(text="▶ Continue (F9)")
            self.status_pid.config(text=f"PID: {pid}")
            self.status_target.config(text=f"Target: attached:{label}")
            self.status_state.config(text="Attached",
                                     foreground=self.colors['status_stopped'])
            self._set_toolbar_mode('active')
            self.console_panel.input.state(['!disabled'])
            self.mem_panel.addr_entry.state(['!disabled'])
            self.mem_panel._go_btn.state(['!disabled'])
            self.console_panel.append_output(f"Attached to process {pid}\n")
            self._refresh_all()
            return
        payload = record.get('payload', '')
        parsed = parse_mi_tuple(payload)
        msg = parsed.get('msg', '')
        if not msg:
            msg = _unescape_mi_string(payload) or f"PID {pid}"
        self.status_state.config(text="Attach failed",
                                 foreground=self.colors['status_error'])
        self.console_panel.append_output(f"Attach failed: {msg}\n")
        messagebox.showerror("Attach Failed", msg)

    def _refresh_libraries(self):
        if not self.gdb.process:
            self.state.libraries = []
            self.library_panel.refresh_libraries(self.state.libraries)
            return
        self.gdb.send_cmd('-file-list-shared-libraries',
                          callback=self._on_shared_libraries)

    def _on_shared_libraries(self, record):
        state = self.state
        state.libraries = []
        if record.get('cls') != 'done':
            self.library_panel.refresh_libraries(self.state.libraries)
            return
        payload = record.get('payload', '')
        m = re.search(r'shared-libraries=\[(.*)\]', payload, re.DOTALL)
        if not m:
            self.library_panel.refresh_libraries(self.state.libraries)
            return
        for item in parse_mi_list(m.group(1)):
            if not isinstance(item, dict):
                continue
            path = (item.get('target-name') or item.get('host-name') or
                    item.get('name') or item.get('description') or '')
            name = item.get('name') or os.path.basename(path)
            state.libraries.append({
                'base': item.get('from', item.get('from_addr', '')),
                'end': item.get('to', item.get('to_addr', '')),
                'name': name,
                'path': path,
            })
        self.library_panel.refresh_libraries(self.state.libraries)

    def _open_memory_map_window(self):
        if self._memory_map_window is not None:
            try:
                if self._memory_map_window.winfo_exists():
                    self._memory_map_window.lift()
                    self._dock_memory_map_window()
                    return
            except tk.TclError:
                pass
        self._memory_map_window = MemoryMapWindow(self)

    def _dock_memory_map_window(self, event=None):
        win = self.__dict__.get('_memory_map_window')
        if win is None:
            return
        try:
            if not win.winfo_exists() or not win.dock_var.get():
                return
            self.update_idletasks()
            w = max(620, win.winfo_width() or 760)
            h = max(360, min(self.winfo_height(), win.winfo_height() or 560))
            x = self.winfo_rootx() + self.winfo_width() + 8
            y = self.winfo_rooty()
            win.geometry(f'{w}x{h}+{x}+{y}')
        except tk.TclError:
            self._memory_map_window = None

    def _refresh_memory_map(self):
        if not self.gdb.process:
            self.state.memory_maps = self._read_proc_maps_fallback()
            self._refresh_memory_map_window()
            return
        self._memory_map_capture = {'lines': []}
        self.gdb.send_cmd('-interpreter-exec console "info proc mappings"',
                          callback=self._on_info_proc_mappings)

    def _on_info_proc_mappings(self, record):
        capture = self._memory_map_capture or {'lines': []}
        self._memory_map_capture = None
        text = ''.join(capture.get('lines', []))
        rows = self._parse_info_proc_mappings(text)
        if not rows:
            rows = self._read_proc_maps_fallback()
        self.state.memory_maps = rows
        self._refresh_memory_map_window()

    def _refresh_memory_map_window(self):
        win = self.__dict__.get('_memory_map_window')
        if win is not None:
            try:
                if win.winfo_exists():
                    win.refresh_maps(self.state.memory_maps)
            except tk.TclError:
                self._memory_map_window = None

    def _read_proc_maps_fallback(self):
        pid = self.state.pid
        if not pid:
            return []
        path = f'/proc/{pid}/maps'
        if not os.path.isfile(path):
            return []
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return self._parse_proc_maps(f.read())
        except OSError:
            return []

    def _parse_info_proc_mappings(self, text):
        rows = []
        for line in str(text or '').splitlines():
            parts = line.strip().split()
            if len(parts) < 4 or not parts[0].startswith('0x') or not parts[1].startswith('0x'):
                continue
            perm = ''
            path_start = 4
            if len(parts) >= 5 and re.match(r'^[rwxsp-]{3,5}$', parts[4]):
                perm = parts[4]
                path_start = 5
            path = ' '.join(parts[path_start:]) if len(parts) > path_start else ''
            row = self._make_memory_map_row(parts[0], parts[1], parts[2],
                                            parts[3], perm, path)
            rows.append(row)
        return self._annotate_memory_map_sections(rows)

    def _parse_proc_maps(self, text):
        rows = []
        for line in str(text or '').splitlines():
            parts = line.strip().split(None, 5)
            if len(parts) < 5 or '-' not in parts[0]:
                continue
            start, end = parts[0].split('-', 1)
            perm = parts[1]
            offset = f"0x{int(parts[2], 16):x}" if parts[2] else '0x0'
            path = parts[5] if len(parts) > 5 else ''
            size = f"0x{max(0, int(end, 16) - int(start, 16)):x}"
            rows.append(self._make_memory_map_row(f"0x{start}", f"0x{end}",
                                                  size, offset, perm, path))
        return self._annotate_memory_map_sections(rows)

    def _make_memory_map_row(self, start, end, size, offset, perm, path):
        return {
            'start': start,
            'end': end,
            'size': self._format_map_size(size),
            'size_hex': size,
            'offset': offset,
            'perm': perm,
            'path': path,
            'type': self._classify_memory_map(path, perm),
            'readable': 'r' in (perm or ''),
            'section': '',
            'sections': [],
        }

    def _parse_map_int(self, value, base=0):
        try:
            return int(str(value), base)
        except (TypeError, ValueError):
            return None

    def _load_file_sections(self, path):
        path = (path or '').strip()
        if not path or not os.path.isfile(path):
            return []
        cache = self.__dict__.setdefault('_section_cache', {})
        if path in cache:
            return cache[path]

        sections = []
        readelf = shutil.which('readelf')
        if readelf:
            try:
                output = subprocess.check_output(
                    [readelf, '-SW', path],
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=8,
                )
                sections = self._parse_readelf_sections(output)
            except (OSError, subprocess.SubprocessError, ValueError):
                sections = []
        cache[path] = sections
        return sections

    def _parse_readelf_sections(self, output):
        sections = []
        pattern = re.compile(
            r'^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+'
            r'([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+'
            r'[0-9A-Fa-f]+\s+([A-Za-z]*)\b'
        )
        for line in str(output or '').splitlines():
            match = pattern.match(line)
            if not match:
                continue
            name, section_type, addr, offset, size, flags = match.groups()
            if section_type == 'NULL':
                continue
            section_size = int(size, 16)
            if section_size <= 0:
                continue
            sections.append({
                'name': name,
                'type': section_type,
                'addr': int(addr, 16),
                'offset': int(offset, 16),
                'size': section_size,
                'flags': flags,
            })
        return sections

    def _annotate_memory_map_sections(self, rows):
        for row in rows:
            sections = self._sections_for_mapping(row)
            row['sections'] = sections
            row['section'] = ', '.join(sec.get('name', '') for sec in sections)
        return rows

    def _sections_for_mapping(self, row):
        path = (row.get('path') or '').strip()
        if not path or path.startswith('['):
            return []
        sections = self._load_file_sections(path)
        if not sections:
            return []

        row_start = self._parse_map_int(row.get('start'))
        row_end = self._parse_map_int(row.get('end'))
        offset_start = self._parse_map_int(row.get('offset'))
        mapped_size = self._parse_map_int(row.get('size_hex'))
        offset_end = None
        if offset_start is not None and mapped_size is not None:
            offset_end = offset_start + mapped_size

        matches = []
        for section in sections:
            if self._section_overlaps_mapping(
                    section, row_start, row_end, offset_start, offset_end):
                matches.append(section)
        matches.sort(key=lambda sec: (sec.get('offset', 0), sec.get('addr', 0)))
        return matches

    def _section_overlaps_mapping(self, section, row_start, row_end,
                                  offset_start, offset_end):
        section_size = section.get('size', 0)
        sec_offset_start = section.get('offset', 0)
        sec_offset_end = sec_offset_start + section_size
        if offset_start is not None and offset_end is not None:
            if sec_offset_start < offset_end and sec_offset_end > offset_start:
                return True

        sec_addr_start = section.get('addr', 0)
        sec_addr_end = sec_addr_start + section_size
        if row_start is not None and row_end is not None:
            if sec_addr_start < row_end and sec_addr_end > row_start:
                return True
        return False

    def _format_map_size(self, size):
        try:
            value = int(str(size), 0)
        except (TypeError, ValueError):
            return str(size or '')
        if value >= 1024 * 1024:
            return f"{value / (1024 * 1024):.1f} MB"
        if value >= 1024:
            return f"{value // 1024} KB"
        return f"{value} B"

    def _classify_memory_map(self, path, perm):
        lower = (path or '').lower()
        state = self.__dict__.get('state')
        target = (getattr(state, 'target_path', '') or '').lower()
        if '[heap]' in lower:
            return 'heap'
        if '[stack]' in lower:
            return 'stack'
        if lower.endswith(('.so', '.dll')) or '.so.' in lower or '.dll' in lower:
            return 'library'
        if target and not target.startswith('attached:') and lower == target:
            return 'exe'
        if 'x' in (perm or ''):
            return 'code'
        if not path:
            return 'anon'
        return 'mapped'

    def _open_address_in_memory(self, addr):
        addr = (addr or '').strip()
        if not addr:
            return
        var = self._view_vars.get('Memory')
        if var is not None and not var.get():
            var.set(True)
            self._toggle_panel('Memory')
        mem = self.mem_panel
        mem.addr_entry.state(['!disabled'])
        mem._go_btn.state(['!disabled'])
        mem.addr_entry.delete(0, tk.END)
        mem.addr_entry.insert(0, addr)
        mem._read_memory()

    def _refresh_import_symbols(self):
        target = self.state.target_path or ''
        if target.startswith('attached:') or not os.path.isfile(target):
            self.state.import_symbols = []
        else:
            self.state.import_symbols = self._load_import_symbols(self.state.target_path)
        self.library_panel.refresh_imports(self.state.import_symbols)

    def _load_library_exports(self, path):
        return self._load_symbols(path, mode='exports')

    def _load_import_symbols(self, path):
        return self._load_symbols(path, mode='imports')

    def _load_symbols(self, path, mode):
        if not path or not os.path.isfile(path):
            return []
        commands = (
            ('nm', ['nm', '-D', '--defined-only' if mode == 'exports' else '--undefined-only', path],
             self._parse_nm_symbols),
            ('objdump', ['objdump', '-T', path], self._parse_objdump_symbols),
            ('readelf', ['readelf', '-Ws', path], self._parse_readelf_symbols),
        )
        for tool, cmd, parser in commands:
            if not shutil.which(tool):
                continue
            try:
                output = subprocess.check_output(
                    cmd, text=True, timeout=8, stderr=subprocess.STDOUT,
                    errors='replace')
            except (subprocess.SubprocessError, OSError):
                continue
            symbols = parser(output, mode, os.path.basename(path))
            if symbols:
                return symbols
        return []

    def _symbol_dict(self, addr, typ, name, source):
        name = (name or '').split('@')[0]
        return {'addr': addr, 'type': typ, 'name': name, 'source': source}

    def _parse_nm_symbols(self, output, mode, source):
        symbols = []
        for line in output.splitlines():
            parts = line.strip().split()
            if mode == 'imports':
                if parts and parts[0] == 'U':
                    symbols.append(self._symbol_dict('', 'U', parts[-1], source))
                continue
            if len(parts) >= 3 and re.fullmatch(r'[0-9a-fA-F]+', parts[0]):
                typ = parts[1]
                if typ.upper() != 'U':
                    symbols.append(self._symbol_dict('0x' + parts[0], typ, parts[2], source))
        return symbols

    def _parse_objdump_symbols(self, output, mode, source):
        symbols = []
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) < 6 or not re.fullmatch(r'[0-9a-fA-F]+', parts[0]):
                continue
            addr, sec, name = parts[0], parts[3], parts[-1]
            is_import = sec == '*UND*'
            if mode == 'imports' and is_import:
                symbols.append(self._symbol_dict('', 'UND', name, source))
            elif mode == 'exports' and not is_import:
                symbols.append(self._symbol_dict('0x' + addr, parts[2], name, source))
        return symbols

    def _parse_readelf_symbols(self, output, mode, source):
        symbols = []
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) < 8 or not parts[0].rstrip(':').isdigit():
                continue
            value, typ, ndx, name = parts[1], parts[3], parts[6], parts[7]
            if typ not in ('FUNC', 'IFUNC', 'OBJECT'):
                continue
            if mode == 'imports' and ndx == 'UND':
                symbols.append(self._symbol_dict('', typ, name, source))
            elif mode == 'exports' and ndx != 'UND' and re.fullmatch(r'[0-9a-fA-F]+', value):
                symbols.append(self._symbol_dict('0x' + value, typ, name, source))
        return symbols

    def _break_library_base(self, lib):
        base = lib.get('base', '')
        if base:
            self.gdb.send_cmd(f'-break-insert *{base}',
                              callback=self._on_break_created)

    def _break_symbol(self, sym):
        name = sym.get('name', '')
        if not name:
            return
        existing = self._find_bp_for_symbol(name)
        if existing:
            self.console_panel.append_output(
                f"Breakpoint {existing} already set at {name}\n")
            return
        self.gdb.send_cmd(f'-break-insert {name}',
                          callback=self._on_break_created)

    def _disassemble_library_base(self, lib):
        base = lib.get('base', '')
        if base:
            self._disassemble_address(base)

    def _disassemble_symbol(self, sym):
        addr = sym.get('addr', '')
        if addr:
            self._disassemble_address(addr)
        elif sym.get('name'):
            self.gdb.send_cmd(f'-data-disassemble -s {sym["name"]} -e "{sym["name"]}+80" -- 0',
                              callback=self._on_disasm)

    def _disassemble_address(self, addr):
        try:
            addr_int = int(addr, 16)
            start = hex(max(0, addr_int - 32))
            end = hex(addr_int + 160)
        except (ValueError, TypeError):
            start = addr
            end = f'"{addr}+80"'
        self.gdb.send_cmd(f'-data-disassemble -s {start} -e {end} -- 0',
                          callback=self._on_disasm)

    def _load_recent_files(self):
        try:
            with open(self._config_path, 'r') as f:
                data = json.load(f)
                return data.get('recent_files', [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_recent_files(self):
        try:
            with open(self._config_path, 'w') as f:
                json.dump({'recent_files': self._recent_files}, f, indent=2)
        except OSError:
            pass

    def _add_recent_file(self, path):
        path = os.path.abspath(path)
        if path in self._recent_files:
            self._recent_files.remove(path)
        self._recent_files.insert(0, path)
        self._recent_files = self._recent_files[:10]  # keep max 10
        self._save_recent_files()
        self._refresh_recent_menu()

    def _refresh_recent_menu(self):
        self._recent_menu.delete(0, tk.END)
        if not self._recent_files:
            self._menu_command(self._recent_menu, '·', "(empty)",
                               state=tk.DISABLED)
            return
        for path in self._recent_files:
            label = path
            if len(label) > 80:
                label = '...' + label[-77:]
            self._menu_command(
                self._recent_menu, '↪', label,
                command=lambda p=path: self._load_program(p))

    def _set_toolbar_mode(self, mode):
        """Apply debugger toolbar state.

        empty: no executable loaded, all debugger buttons disabled.
        loaded: executable loaded but not running, only Run is enabled.
        active: debugging started, run/continue and control buttons enabled.
        """
        self._toolbar_mode = mode
        for btn, role in zip(self._toolbar_buttons, self._toolbar_button_roles):
            btn.state(['disabled'])
            if role == 'run':
                if mode in ('loaded', 'active'):
                    btn.state(['!disabled'])
            elif role == 'run-options':
                if mode == 'loaded':
                    btn.state(['!disabled'])
            elif mode == 'loaded':
                pass
            elif mode == 'active':
                btn.state(['!disabled'])

    def _is_debug_active(self):
        return self._toolbar_mode == 'active'

    def _enable_controls(self):
        self._set_toolbar_mode('loaded')
        self.console_panel.input.state(['!disabled'])
        self.mem_panel.addr_entry.state(['!disabled'])
        self.mem_panel._go_btn.state(['!disabled'])

    def _default_debug_options(self):
        return {
            'default_breakpoints': {
                key: enabled
                for key, _label, _symbol, enabled in self._DEFAULT_BREAKPOINT_OPTIONS
            }
        }

    def _open_debug_options_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Debug Options")
        dlg.configure(bg=self.colors['surface'])
        dlg.geometry("560x420")
        dlg.minsize(480, 340)
        dlg.transient(self)

        frame = tk.Frame(dlg, bg=self.colors['surface'], padx=12, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        bp_page = tk.Frame(notebook, bg=self.colors['surface'], padx=12, pady=10)
        notebook.add(bp_page, text="Default Breakpoints")
        ttk.Label(
            bp_page,
            text="Breakpoints to set before starting a loaded executable:",
            style='Panel.TLabel',
        ).pack(anchor=tk.W, pady=(0, 8))

        bp_vars = {}
        current = self._debug_options.get('default_breakpoints', {})
        for key, label, _symbol, default in self._DEFAULT_BREAKPOINT_OPTIONS:
            var = tk.BooleanVar(value=current.get(key, default))
            bp_vars[key] = var
            ttk.Checkbutton(bp_page, text=label, variable=var).pack(
                anchor=tk.W, pady=2)

        buttons = tk.Frame(frame, bg=self.colors['surface'])
        buttons.pack(fill=tk.X, pady=(10, 0))

        def apply():
            self._apply_debug_options_from_vars(bp_vars)

        def ok():
            apply()
            dlg.destroy()

        ttk.Button(buttons, text="Cancel", command=dlg.destroy,
                   style='Small.TButton').pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(buttons, text="OK", command=ok,
                   style='Primary.Tool.TButton').pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Apply", command=apply,
                   style='Small.TButton').pack(side=tk.RIGHT, padx=(0, 6))

        dlg.grab_set()
        dlg.focus_set()

    def _apply_debug_options_from_vars(self, bp_vars):
        self._debug_options['default_breakpoints'] = {
            key: var.get()
            for key, var in bp_vars.items()
        }

    def _show_run_menu(self):
        if self._toolbar_mode != 'loaded' or not self._run_menu_btn:
            return
        x = self._run_menu_btn.winfo_rootx()
        y = self._run_menu_btn.winfo_rooty() + self._run_menu_btn.winfo_height()
        self._run_menu.tk_popup(x, y)

    def _ask_program_args(self, title):
        result = {'value': None}
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.configure(bg=self.colors['surface'])
        dlg.resizable(True, False)
        dlg.transient(self)

        self.update_idletasks()
        w, h = 720, 140
        x = self.winfo_x() + max(0, (self.winfo_width() - w) // 2)
        y = self.winfo_y() + max(0, (self.winfo_height() - h) // 2)
        dlg.geometry(f'720x140+{x}+{y}')
        dlg.minsize(560, 140)

        frame = tk.Frame(dlg, bg=self.colors['surface'], padx=14, pady=12)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Program arguments:",
                  style='Panel.TLabel').pack(anchor=tk.W)
        entry = ttk.Entry(frame, width=90, style='Compact.TEntry')
        entry.insert(0, self._program_args)
        entry.pack(fill=tk.X, expand=True, pady=(6, 10))

        btns = tk.Frame(frame, bg=self.colors['surface'])
        btns.pack(fill=tk.X)

        def accept():
            result['value'] = entry.get()
            dlg.destroy()

        def cancel():
            dlg.destroy()

        ttk.Button(btns, text="Cancel", command=cancel,
                   style='Small.TButton').pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(btns, text="OK", command=accept,
                   style='Primary.Tool.TButton').pack(side=tk.RIGHT)
        entry.bind('<Return>', lambda e: accept())
        entry.bind('<Escape>', lambda e: cancel())
        dlg.protocol("WM_DELETE_WINDOW", cancel)
        dlg.grab_set()
        entry.focus_set()
        entry.selection_range(0, tk.END)
        entry.icursor(tk.END)
        self.wait_window(dlg)
        return result['value']

    def _cmd_run_with_args(self):
        if self.state.pid:
            messagebox.showinfo(
                "Run with Arguments",
                "Stop the current program before running with new arguments.")
            return
        args = self._ask_program_args("Run with Arguments")
        if args is None:
            return
        self._program_args = args.strip()
        self._cmd_run(program_args=self._program_args)

    def _edit_run_args(self):
        args = self._ask_program_args("Edit Arguments")
        if args is not None:
            self._program_args = args.strip()

    def _clear_run_args(self):
        self._program_args = ''

    def _cmd_run(self, program_args=None):
        mode = self._toolbar_mode
        if mode not in ('loaded', 'active'):
            return
        if self.state.running:
            return
        self._stop_requested = False
        self._set_toolbar_mode('active')
        if mode == 'active':
            self.gdb.send_cmd('-exec-continue')
        else:
            self.state.running = True
            def start_program():
                if program_args is not None:
                    args = program_args.strip()
                    if args:
                        self.gdb.send_cmd(f'-exec-arguments {args}')
                    else:
                        self.gdb.send_cmd('-exec-arguments')
                self.gdb.send_cmd('-exec-run')
            self._apply_default_breakpoints(start_program)

    def _apply_default_breakpoints(self, done):
        options = self.__dict__.get('_debug_options', {}).get('default_breakpoints')
        if not options:
            done()
            return
        for key, _label, symbol, _default in self._DEFAULT_BREAKPOINT_OPTIONS:
            if key == 'entry' or not options.get(key):
                continue
            if symbol:
                self._queue_default_breakpoint(symbol)
        if options.get('entry'):
            self._request_entry_breakpoint(done)
        else:
            done()

    def _request_entry_breakpoint(self, done):
        self._entry_bp_attempt = {
            'symbols': list(self._ENTRY_POINT_SYMBOLS),
            'index': 0,
            'done': done,
        }
        self._try_next_entry_symbol_breakpoint()

    def _try_next_entry_symbol_breakpoint(self):
        attempt = self.__dict__.get('_entry_bp_attempt')
        if not attempt:
            return
        symbols = attempt.get('symbols', [])
        while attempt.get('index', 0) < len(symbols):
            idx = attempt.get('index', 0)
            symbol = symbols[idx]
            attempt['index'] = idx + 1
            if self._find_bp_for_symbol(symbol):
                done = attempt.get('done')
                self._entry_bp_attempt = None
                if done:
                    done()
                return
            key = self._default_breakpoint_key(symbol)
            if key in self.__dict__.setdefault('_default_bp_requests', set()):
                continue
            self._default_bp_requests.add(key)
            self.gdb.send_cmd(
                f'-break-insert {symbol}',
                callback=lambda r, loc=symbol, k=key:
                    self._on_entry_symbol_breakpoint_attempt(r, loc, k))
            return
        done = attempt.get('done')
        self._entry_bp_attempt = None
        self._request_info_files_entry_breakpoint(done)

    def _on_entry_symbol_breakpoint_attempt(self, record, location, key):
        if key in self._default_bp_requests:
            self._default_bp_requests.remove(key)
        attempt = self.__dict__.get('_entry_bp_attempt')
        if record.get('cls') == 'done':
            self._entry_bp_attempt = None
            self._on_break_created(record)
            done = attempt.get('done') if attempt else None
            if done:
                done()
            return
        self._try_next_entry_symbol_breakpoint()

    def _request_info_files_entry_breakpoint(self, done):
        self._info_files_capture = {'lines': [], 'done': done}
        self.gdb.send_cmd('-interpreter-exec console "info files"',
                          callback=self._on_info_files_for_entry)

    def _on_info_files_for_entry(self, record):
        capture = self._info_files_capture or {'lines': [], 'done': None}
        self._info_files_capture = None
        entry = self._extract_entry_point_from_info_files(
            ''.join(capture.get('lines', [])))
        if entry:
            self._queue_default_breakpoint(f'*{entry}')
        done = capture.get('done')
        if done:
            done()

    def _extract_entry_point_from_info_files(self, text):
        patterns = (
            r'Entry point:\s*(0x[0-9a-fA-F]+)',
            r'Entry point of executable is\s*(0x[0-9a-fA-F]+)',
            r'Entry point\s*(0x[0-9a-fA-F]+)',
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _queue_default_breakpoint(self, location):
        location = (location or '').strip()
        if not location:
            return
        key = self._default_breakpoint_key(location)
        if key in self.__dict__.setdefault('_default_bp_requests', set()):
            return
        if location.startswith('*'):
            if self._find_bp_at_addr(location[1:]):
                return
        elif self._find_bp_for_symbol(location):
            return
        self._default_bp_requests.add(key)
        self.gdb.send_cmd(
            f'-break-insert {location}',
            callback=lambda r, k=key: self._on_default_break_created(r, k))

    def _default_breakpoint_key(self, location):
        if location.startswith('*'):
            try:
                return f'addr:{int(location[1:], 16):x}'
            except (ValueError, TypeError):
                return f'addr:{location[1:]}'
        return f'sym:{self._normalize_symbol_name(location)}'

    def _on_default_break_created(self, record, key):
        if key in self._default_bp_requests:
            self._default_bp_requests.remove(key)
        self._on_break_created(record)

    def _cmd_break(self):
        if not self._is_debug_active():
            return
        self.gdb.send_cmd('-exec-interrupt')

    def _cmd_step(self, direction):
        if not self._is_debug_active():
            return
        if direction == 'over':
            self.gdb.send_cmd('-exec-next-instruction')
        else:
            self.gdb.send_cmd('-exec-step-instruction')

    def _cmd_step_out(self):
        if not self._is_debug_active():
            return
        self.gdb.send_cmd('-exec-finish')

    def _cmd_stop(self):
        if not self._is_debug_active():
            return
        self._stop_requested = True
        if self._run_btn:
            self._run_btn.config(text="Stopping...")
        if self.state.running:
            self.gdb.send_cmd('-exec-interrupt')
        else:
            self.gdb.send_cmd('-exec-abort', callback=self._finish_stop)

    def _finish_stop(self, record=None):
        self._stop_requested = False
        self.state.running = False
        self.state.pid = None
        if self._run_btn:
            self._run_btn.config(text="▶ Run (F9)")
        self._set_toolbar_mode('loaded')
        self.console_panel.input.state(['!disabled'])
        self.status_state.config(text="Stopped",
                                 foreground=self.colors['muted_fg'])

    def _cmd_restart(self):
        if not self._is_debug_active():
            return
        def after_kill(record):
            self.state.running = False
            self.state.pid = None
            self._stop_requested = False
            self._set_toolbar_mode('loaded')
            self._cmd_run()
            if self._run_btn:
                self._run_btn.config(text="▶ Run (F9)")
        self.gdb.send_cmd('-exec-abort', callback=after_kill)

    def _goto_address(self):
        # Non-modal go-to-address dialog
        if hasattr(self, '_goto_dlg') and self._goto_dlg and self._goto_dlg.winfo_exists():
            self._goto_dlg.lift()
            self._goto_entry.focus_set()
            return
        dlg = tk.Toplevel(self)
        dlg.title("Go to Address")
        dlg.resizable(True, False)
        dlg.transient(self)   # stay in front of parent
        dlg.attributes('-topmost', True)
        self._goto_dlg = dlg
        dlg.protocol("WM_DELETE_WINDOW", self._on_goto_close)

        # Center relative to parent window
        dlg.update_idletasks()
        pw = self.winfo_width()
        ph = self.winfo_height()
        px = self.winfo_x()
        py = self.winfo_y()
        w, h = 380, 80
        dlg.geometry(f'{w}x{h}+{px + (pw - w) // 2}+{py + (ph - h) // 2}')

        frame = tk.Frame(dlg, padx=8, pady=8)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Address / Expression:",
                  ).pack(anchor=tk.W)
        entry_frame = tk.Frame(frame)
        entry_frame.pack(fill=tk.X, pady=(4, 0))

        entry = ttk.Entry(entry_frame, style='Compact.TEntry')
        self._goto_entry = entry
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        def do_go():
            expr = entry.get().strip()
            if not expr:
                return
            # Strip leading * if present (e.g. *main → main)
            clean = expr.lstrip('*').strip()
            # Auto-add $ prefix for register names (rax → $rax)
            if re.match(r'^[a-z]+\d*$|^[er]?[a-z]{2,3}[lh]?$|^\$',
                        clean, re.IGNORECASE) and not clean.startswith('0x'):
                if not clean.startswith('$'):
                    clean = '$' + clean
            # Use GDB to evaluate the expression (handles registers, symbols, math)
            self.gdb.send_cmd(
                f'-data-evaluate-expression {clean}',
                callback=lambda r, e=expr: self._on_goto_eval(r, e))

        go_btn = ttk.Button(entry_frame, text="Go", command=do_go,
                            style='Small.TButton')
        go_btn.pack(side=tk.LEFT)

        entry.bind('<Return>', lambda e: do_go())
        entry.focus_set()

    def _on_goto_close(self):
        self.disasm_panel.clear_goto_highlight()
        self._goto_dlg.destroy()

    def _on_goto_eval(self, record, orig_expr):
        if record.get('cls') != 'done':
            self.console_panel.append_output(
                f"Cannot resolve: {orig_expr}\n")
            return
        payload = record.get('payload', '')
        m = re.search(r'value="([^"]+)"', payload)
        if not m:
            self.console_panel.append_output(
                f"Cannot resolve: {orig_expr}\n")
            return
        val = m.group(1)
        # GDB may return: "0x555555555140", "{int ()} 0x5555555551c9 <main>", "12345"
        addr_match = re.search(r'0x[0-9a-fA-F]+', val)
        if addr_match:
            addr_int = int(addr_match.group(0), 16)
        else:
            try:
                addr_int = int(val, 0)
            except ValueError:
                self.console_panel.append_output(
                    f"Cannot resolve: {orig_expr} = {val}\n")
                return
        s = hex(max(0, addr_int - 64))
        e = hex(addr_int + 128)
        # Set goto address for green highlight
        self.disasm_panel._goto_addr_int = addr_int
        self.gdb.send_cmd(
            f'-data-disassemble -s {s} -e {e} -- 0',
            callback=self._on_disasm_goto)

    def _on_disasm_goto(self, record):
        """Handle disassembly result from goto — highlight and scroll to target."""
        self._on_disasm(record)
        # After rebuild, scroll to the goto address line
        if self.disasm_panel._goto_addr_int is not None:
            addr_hex = f'0x{self.disasm_panel._goto_addr_int:x}'
            self.disasm_panel._scroll_to_addr_line(addr_hex)

    def _navigate_execution_history_back(self, event=None):
        addr = self.state.previous_pc()
        if not addr:
            return 'break'
        self._show_history_pc(addr)
        return 'break'

    def _show_history_pc(self, addr):
        try:
            addr_int = int(addr, 16)
        except (ValueError, TypeError):
            return
        self.disasm_panel._goto_addr_int = addr_int
        if self._disassembly_contains_addr(addr_int):
            self.disasm_panel.refresh(self.state)
            self.disasm_panel._scroll_to_addr_line(addr)
            return
        start = hex(max(0, addr_int - 64))
        end = hex(addr_int + 128)
        self.gdb.send_cmd(
            f'-data-disassemble -s {start} -e {end} -- 0',
            callback=self._on_disasm_goto)

    def _disassembly_contains_addr(self, addr_int):
        for insn in self.state.disassembly:
            try:
                if int(insn.get('addr', ''), 16) == addr_int:
                    return True
            except (ValueError, TypeError):
                continue
        return False

    def _toggle_bp(self):
        if not self._is_debug_active():
            return
        if self.state.pc:
            existing = self._find_bp_at_addr(self.state.pc)
            if existing:
                self.gdb.send_cmd(f'-break-delete {existing}',
                    callback=lambda r, n=existing: self._on_break_deleted(r, n))
            else:
                self.gdb.send_cmd(f'-break-insert *{self.state.pc}',
                    callback=self._on_break_created)

    def _find_bp_at_addr(self, addr):
        try:
            addr_int = int(addr, 16)
        except (ValueError, TypeError):
            return None
        for num, bp in self.state.breakpoints.items():
            try:
                if int(bp['addr'], 16) == addr_int:
                    return num
            except (ValueError, TypeError):
                continue
        return None

    def _normalize_symbol_name(self, name):
        return (name or '').strip().split('@')[0]

    def _find_bp_for_symbol(self, name):
        target = self._normalize_symbol_name(name)
        if not target:
            return None
        for num, bp in self.state.breakpoints.items():
            for key in ('func', 'original_location'):
                if self._normalize_symbol_name(bp.get(key, '')) == target:
                    return num
        return None

    def _on_break_created(self, record):
        """Callback for -break-insert result — updates state, panels, console."""
        if record.get('cls') == 'done':
            payload = record.get('payload', '')
            parsed = parse_mi_tuple(payload)
            bkpt = parsed.get('bkpt', parsed)
            if isinstance(bkpt, dict):
                self.state.update_breakpoints([bkpt])
                self.bp_panel.refresh(self.state)
                self.disasm_panel.refresh(self.state)
                num = bkpt.get('number', '?')
                addr = bkpt.get('addr', '?')
                self.console_panel.append_output(f"Breakpoint {num} at {addr}\n")
        elif record.get('cls') == 'error':
            payload = record.get('payload', '')
            self.console_panel.append_output(f"Error: {payload}\n")

    def _on_break_deleted(self, record, num):
        """Callback for -break-delete result — updates state, panels, console."""
        if record.get('cls') == 'done':
            self.state.remove_breakpoint(num)
            self.bp_panel.refresh(self.state)
            self.disasm_panel.refresh(self.state)
            self.console_panel.append_output(f"Deleted breakpoint {num}\n")

    def _on_break_modified(self, record, num, enabled):
        """Callback for -break-enable/-break-disable — update single breakpoint state."""
        if record.get('cls') == 'done':
            bp = self.state.breakpoints.get(num)
            if bp:
                bp['enabled'] = enabled
                self.bp_panel.refresh(self.state)
                self.disasm_panel.refresh(self.state)
                state_str = "enabled" if enabled else "disabled"
                self.console_panel.append_output(
                    f"Breakpoint {num} {state_str}\n")

    def _poll_queue(self):
        try:
            while True:
                item = self.output_queue.get_nowait()
                if len(item) == 3:
                    rtype, record, cb = item
                    cb(record)
                else:
                    rtype, record = item
                    self._handle_record(rtype, record)
        except Empty:
            pass
        self.after(100, self._poll_queue)

    def _result_error_message(self, payload):
        parsed = parse_mi_tuple(payload)
        msg = parsed.get('msg', '')
        if msg:
            return msg
        return payload.replace('\\n', '\n').replace('\\"', '"')

    def _is_program_not_running_error(self, msg):
        return 'the program is not being run' in (msg or '').lower()

    def _is_program_exit_reason(self, reason):
        return reason in ('exited', 'exited-normally', 'exited-signalled')

    def _restore_loaded_state_after_program_exit(self):
        self._stop_requested = False
        self.state.running = False
        self.state.pid = None
        self.state.current_thread = None
        run_btn = self.__dict__.get('_run_btn')
        if run_btn:
            run_btn.config(text="▶ Run (F9)")
        if self.state.target_path:
            self._set_toolbar_mode('loaded')
        else:
            self._set_toolbar_mode('empty')
        status_pid = self.__dict__.get('status_pid')
        if status_pid:
            status_pid.config(text="PID: -")
        status_thread = self.__dict__.get('status_thread')
        if status_thread:
            status_thread.config(text="Thread: -")
        status_state = self.__dict__.get('status_state')
        if status_state:
            status_state.config(text="Exited",
                                foreground=self.colors['muted_fg'])
        console_panel = self.__dict__.get('console_panel')
        if console_panel:
            console_panel.input.state(['!disabled'])
        mem_panel = self.__dict__.get('mem_panel')
        if mem_panel:
            mem_panel.addr_entry.state(['!disabled'])
            mem_panel._go_btn.state(['!disabled'])

    def _handle_result_error(self, payload):
        msg = self._result_error_message(payload)
        self.console_panel.append_output(f"Error: {msg}\n")
        if self._is_program_not_running_error(msg):
            self._restore_loaded_state_after_program_exit()

    def _handle_record(self, rtype, record):
        if rtype in ('console', 'log', 'target'):
            payload = record.get('payload', '')
            if payload:
                if rtype == 'console' and self._info_files_capture is not None:
                    self._info_files_capture['lines'].append(payload)
                if rtype == 'console' and self.__dict__.get('_memory_map_capture') is not None:
                    self._memory_map_capture['lines'].append(payload)
                self.console_panel.append_output(payload)
                if not payload.endswith('\n'):
                    self.console_panel.append_output('\n')
        elif rtype == 'prompt':
            pass  # GDB MI prompt — no need to display, input label already shows (gdb)
        elif rtype == 'result':
            cls = record.get('cls', '')
            if cls == 'error':
                payload = record.get('payload', '')
                self._handle_result_error(payload)
        elif rtype == 'exec_async':
            self._handle_exec_async(record)
        elif rtype == 'notify_async':
            self._handle_notify_async(record)
        elif rtype == 'status':
            state_val = record.get('state', '')
            msg = record.get('msg', '')
            if state_val == 'exited':
                self.state.running = False
                self.state.pid = None
                if self.state.target_path:
                    self._set_toolbar_mode('loaded')
                else:
                    self._set_toolbar_mode('empty')
                self.status_state.config(text="GDB exited",
                                         foreground=self.colors['status_error'])
                self.console_panel.append_output("[GDB process exited]\n")
                if messagebox.askyesno("GDB Exited",
                                        "GDB process has exited. Restart?"):
                    self.state.running = False
                    self.gdb.start()
                    if self.state.target_path:
                        self._load_program(self.state.target_path)
            elif state_val == 'error':
                self.status_state.config(text="Error",
                                         foreground=self.colors['status_error'])
                self.console_panel.append_output(f"[Error: {msg}]\n")
            elif msg:
                self.console_panel.append_output(f"[{msg}]\n")

    def _handle_exec_async(self, record):
        cls = record.get('cls', '')
        if cls == 'stopped':
            payload = record.get('payload', '')
            parsed = parse_mi_tuple(payload)
            reason = parsed.get('reason', 'unknown')
            if self._is_program_exit_reason(reason):
                self._restore_loaded_state_after_program_exit()
                return
            if self._stop_requested:
                self.state.running = False
                self.gdb.send_cmd('-exec-abort', callback=self._finish_stop)
                return
            self.state.running = False
            self._set_toolbar_mode('active')
            self.status_state.config(text=f"Stopped ({reason})",
                                     foreground=self.colors['status_stopped'])
            if self._run_btn:
                self._run_btn.config(text="▶ Continue (F9)")

            # Extract pid from stopped event directly
            pid = parsed.get('thread-id', '')
            if pid and not self.state.pid:
                self.state.pid = pid
                self.status_pid.config(text=f"PID: {pid}")

            frame = parsed.get('frame', {})
            if frame:
                self.state.pc = frame.get('addr', self.state.pc)
                self.state.remember_pc(self.state.pc)
                self.state.current_thread = parsed.get('thread-id', self.state.current_thread)

            self._refresh_all()
        elif cls == 'running':
            self.state.running = True
            self._set_toolbar_mode('active')
            self.status_state.config(text="Running...",
                                     foreground=self.colors['status_running'])
            if self._run_btn:
                self._run_btn.config(text="▶ Running...")

    def _handle_notify_async(self, record):
        cls = record.get('cls', '')
        payload = record.get('payload', '')
        if 'breakpoint' in cls:
            parsed = parse_mi_tuple(payload)
            if cls in ('breakpoint-created', 'breakpoint-modified'):
                bkpt = parsed.get('bkpt', parsed)
                if isinstance(bkpt, dict):
                    self.state.update_breakpoints([bkpt])
                    self.bp_panel.refresh(self.state)
                    self.disasm_panel.refresh(self.state)
                    num = bkpt.get('number', '?')
                    addr = bkpt.get('addr', '')
                    if cls == 'breakpoint-created' and addr:
                        self.console_panel.append_output(
                            f"Breakpoint {num} at {addr}\n")
                    elif cls == 'breakpoint-modified':
                        enabled = bkpt.get('enabled', 'y')
                        state_str = "enabled" if enabled == 'y' else "disabled"
                        self.console_panel.append_output(
                            f"Breakpoint {num} {state_str}\n")
            elif cls == 'breakpoint-deleted':
                num = parsed.get('id', '')
                self.state.remove_breakpoint(num)
                self.bp_panel.refresh(self.state)
                self.disasm_panel.refresh(self.state)
                self.console_panel.append_output(f"Deleted breakpoint {num}\n")

    def _refresh_all(self):
        self.gdb.send_cmd('-data-list-register-names',
                          callback=self._on_register_names)
        if self.state.pc:
            try:
                pc_int = int(self.state.pc, 16)
                start = hex(max(0, pc_int - 256))
                end = hex(pc_int + 512)
            except (ValueError, TypeError):
                start = self.state.pc
                end = f'"{self.state.pc}+200"'
            self.gdb.send_cmd(
                f'-data-disassemble -s {start} -e {end} -- 0',
                callback=self._on_disasm)
        self.gdb.send_cmd('-stack-list-frames', callback=self._on_frames)
        self.gdb.send_cmd('-stack-list-variables --all-values',
                          callback=self._on_locals)
        self.gdb.send_cmd('-thread-info', callback=self._on_threads)
        self._refresh_libraries()
        self._refresh_import_symbols()

    # x86-64 registers worth displaying
    _X86_64_REGS = {
        'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
        'rip', 'eflags', 'rflags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs',
    }

    def _on_register_names(self, record):
        if record.get('cls') != 'done':
            return
        payload = record.get('payload', '')
        m = re.search(r'register-names=\[(.+)\]', payload)
        if m:
            names = [n.strip().strip('"') for n in m.group(1).split(',')]
            self._reg_names = names
        self.gdb.send_cmd('-data-list-register-values x',
                          callback=self._on_register_values)

    def _on_register_values(self, record):
        if record.get('cls') != 'done':
            return
        payload = record.get('payload', '')
        m = re.search(r'register-values=\[(.+)\]', payload)
        if m:
            items = parse_mi_list(m.group(1))
            reg_list = []
            names = getattr(self, '_reg_names', [])
            for item in items:
                if isinstance(item, dict):
                    num = int(item.get('number', '-1'))
                    val = item.get('value', '')
                    name = names[num] if num < len(names) else ''
                    if name and val and name in self._X86_64_REGS:
                        reg_list.append({'name': name, 'value': val})
            self.state.update_registers(reg_list)
            self.reg_panel.refresh(self.state)

    def _on_disasm(self, record):
        if record.get('cls') != 'done':
            return
        payload = record.get('payload', '')
        m = re.search(r'asm_insns=\[(.+)\]', payload, re.DOTALL)
        if m:
            items = parse_mi_list(m.group(1))
            asm_list = []
            for item in items:
                if isinstance(item, dict):
                    asm_list.append({
                        'addr': item.get('address', ''),
                        'asm': item.get('inst', item.get('line-inst', '')),
                        'func': item.get('func-name', ''),
                    })
            self.state.update_disassembly(asm_list)
            self.disasm_panel.refresh(self.state, follow_pc=True)

    def _on_frames(self, record):
        if record.get('cls') != 'done':
            return
        payload = record.get('payload', '')
        m = re.search(r'stack=\[(.+)\]', payload, re.DOTALL)
        if m:
            inner = m.group(1).replace('frame=', '')
            items = parse_mi_list(inner)
            frames = []
            for item in items:
                if isinstance(item, dict):
                    frames.append({
                        'level': item.get('level', ''),
                        'func': item.get('func', '??'),
                        'file': item.get('file', ''),
                        'line': item.get('line', ''),
                        'addr': item.get('addr', ''),
                    })
            self.state.update_frames(frames)
            self.stack_panel.refresh(self.state)
            self.stack_trace_panel.refresh_frames(self.state)

    def _on_locals(self, record):
        if record.get('cls') != 'done':
            return
        payload = record.get('payload', '')
        m = re.search(r'variables=\[(.+)\]', payload, re.DOTALL)
        if m:
            items = parse_mi_list(m.group(1))
            self.state.locals = items
            self.locals_panel.refresh(self.state)

    def _on_threads(self, record):
        if record.get('cls') != 'done':
            return
        payload = record.get('payload', '')
        m = re.search(r'threads=\[(.+)\]', payload, re.DOTALL)
        if m:
            items = parse_mi_list(m.group(1))
            threads = []
            for item in items:
                if isinstance(item, dict):
                    threads.append({
                        'id': item.get('id', ''),
                        'target_id': item.get('target-id', ''),
                        'state': item.get('state', ''),
                        'func': item.get('frame', {}).get('func', '') if isinstance(item.get('frame'), dict) else '',
                    })
            self.state.update_threads(threads)
            self.thread_panel.refresh(self.state)
        pid_match = re.search(r'pid="(\d+)"', payload)
        if pid_match:
            self.state.pid = pid_match.group(1)
            self.status_pid.config(text=f"PID: {self.state.pid}")


def main():
    app = NGdbApp()
    app.mainloop()


if __name__ == '__main__':
    main()
