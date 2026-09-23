"""Kernel-timestamped CC1101 GDO0 capture. Optional libgpiod v2 dependency."""
from collections import deque
import glob
import threading
import time

from axiora_protocols import OOKFrames


class EdgeCapture:
    def __init__(self, pin=23):
        import gpiod
        if not hasattr(gpiod, 'request_lines'):
            raise RuntimeError('Для OOK нужен Python libgpiod версии 2.x')
        from gpiod.line import Direction, Edge, Clock
        chip_path = None
        for path in sorted(glob.glob('/dev/gpiochip*')):
            try:
                with gpiod.Chip(path) as chip:
                    if 'rp1' in chip.get_info().label.lower():
                        chip_path = path
                        break
            except PermissionError:
                continue
        if not chip_path:
            raise OSError('Нет доступного GPIOchip RP1; проверьте права /dev/gpiochip*')
        self.request = gpiod.request_lines(chip_path, consumer='axiora-ook', event_buffer_size=4096,
            config={pin: gpiod.LineSettings(direction=Direction.INPUT, edge_detection=Edge.BOTH,
                                           event_clock=Clock.MONOTONIC)})
        self.gpiod = gpiod
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.frames = deque(maxlen=64)
        self.lost = 0
        self.error = None
        self.thread = threading.Thread(target=self._run, name='axiora-ook', daemon=True)
        self.thread.start()

    def _run(self):
        decoder = OOKFrames()
        stamp = level = sequence = None
        flushed = False
        try:
            while not self.stop.is_set():
                if not self.request.wait_edge_events(timeout=.02):
                    # End a frame even if the transmitter stops during its sync gap.
                    if stamp and level == 0 and not flushed and time.monotonic_ns() - stamp >= 15_000_000:
                        self._append(decoder.feed(0, (time.monotonic_ns() - stamp) / 1000, time.monotonic()))
                        flushed = True
                    continue
                for event in self.request.read_edge_events(max_events=1024):
                    if sequence is not None and event.line_seqno != sequence + 1:
                        self.lost += max(1, event.line_seqno - sequence - 1)
                        decoder = OOKFrames()
                        stamp = None
                    if stamp is not None and not flushed:
                        self._append(decoder.feed(level, (event.timestamp_ns - stamp) / 1000,
                                                  event.timestamp_ns / 1e9))
                    stamp, sequence = event.timestamp_ns, event.line_seqno
                    level = 1 if event.event_type == self.gpiod.EdgeEvent.Type.RISING_EDGE else 0
                    flushed = False
        except Exception as exc:
            self.error = str(exc)

    def _append(self, frame):
        if frame:
            with self.lock:
                if len(self.frames) == self.frames.maxlen:
                    self.lost += 1
                frame['lost_edges_or_frames'] = self.lost
                self.frames.append(frame)

    def poll(self):
        if self.error:
            raise OSError(self.error)
        with self.lock:
            frames = list(self.frames)
            self.frames.clear()
        return [{'pulse_frame': frame} for frame in frames]

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.request.release()
