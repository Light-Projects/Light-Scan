# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from PySide6.QtCore import QObject, Signal, QProcess, QProcessEnvironment
import re

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

class CaptureWorker(QObject):
    output_ready = Signal(str)
    finished = Signal()
    error_occurred = Signal(str)

    def __init__(self, program, args, parent=None):
        super().__init__(parent)
        self.program = program
        self.args = args
        self.process = None

    def start(self):
        self.process = QProcess(self)

        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)

        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONUNBUFFERED", "1")
        self.process.setProcessEnvironment(env)

        self.process.readyReadStandardOutput.connect(self._on_ready_read)
        self.process.finished.connect(self._on_finished)
        self.process.errorOccurred.connect(self._on_error)

        self.process.start(self.program, self.args)

    def _on_ready_read(self):
        data = self.process.readAllStandardOutput()
        text = bytes(data).decode("utf-8", errors="replace")
        text = ANSI_ESCAPE.sub("", text)

        if text:
            self.output_ready.emit(text)

    def _on_finished(self, exit_code):
        self.output_ready.emit(f"\n[Capture ended — exit code: {exit_code}]\n")
        self.finished.emit()

    def _on_error(self, error):
        error_names = {
            QProcess.ProcessError.FailedToStart: "Failed to start — check path/permissions",
            QProcess.ProcessError.Crashed: "Process crashed",
            QProcess.ProcessError.Timedout: "Process timed out",
            QProcess.ProcessError.ReadError: "Read error",
            QProcess.ProcessError.WriteError: "Write error",
        }
        self.error_occurred.emit(error_names.get(error, f"Unknown error: {error}"))

    def stop(self):
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.terminate()
            if not self.process.waitForFinished(3000):
                self.process.kill()