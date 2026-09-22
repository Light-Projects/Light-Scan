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

"""
LightPanel Results Dashboard
Hand-drawn statistics charts for scan results.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy, QFileDialog
)
from PySide6.QtCore import Qt, QRectF, QPointF, QSize, QRect
from PySide6.QtGui import (
    QFont, QPainter, QColor, QPen, QBrush, QPainterPath,
    QLinearGradient, QFontMetrics, QPixmap
)
from PySide6.QtSvg import QSvgGenerator
from Gui2.OSMenu import parse_multi_target_output


HOST_COLORS = {
    "up":      "#27ae60",
    "down":    "#e74c3c",
    "unknown": "#f39c12",
}

PORT_COLORS = {
    "open":     "#27ae60",
    "closed":   "#e74c3c",
    "filtered": "#f39c12",
    "open_filtered": "#9b59b6",
}

OS_COLORS = {
    "windows":     "#0078d4",
    "linux":       "#e67e22",
    "macos":       "#95a5a6",
    "bsd":         "#8e44ad",
    "android":     "#3ddc84",
    "unix":        "#16a085",
    "centos":      "#932279",
    "ubuntu":      "#e95420",
    "debian":      "#a80030",
    "aws":         "#ff9900",
    "cloudflare":  "#f38020",
    "pantheon":    "#ff4f00",
    "google":      "#4285f4",
}

DEFAULT_COLOR = "#7f8c8d"


class BarChart(QWidget):

    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.title = title
        self.labels = []
        self.values = []
        self.colors = []

        self.dark_mode = False
        self.setMinimumHeight(240)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, labels, values, colors=None):
        self.labels = list(labels)
        self.values = list(values)
        if colors is None:
            colors = [None] * len(values)
        self.colors = list(colors)
        self.update()

    def set_theme(self, dark_mode):
        self.dark_mode = dark_mode
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        self._draw_chart(painter)
        painter.end()

    def render_to(self, painter):
        self._draw_chart(painter)

    def _draw_chart(self, painter):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        bg_color = QColor("#1a1a1a" if self.dark_mode else "#f7f5f0")
        card_color = QColor("#0a0a0a" if self.dark_mode else "#ffffff")
        text_color = QColor("#00ffaa" if self.dark_mode else "#1e6fe0")
        muted_color = QColor("#7f8c8d")
        grid_color = QColor("#2a2a2a" if self.dark_mode else "#e0e0e0")

        painter.fillRect(self.rect(), bg_color)

        margin = 14
        title_h = 30
        pad_top = 24
        pad_bottom = 56
        pad_left = 40
        pad_right = 16

        card_rect = QRectF(
            margin, margin,
            self.width() - 2 * margin,
            self.height() - 2 * margin
        )

        path = QPainterPath()
        path.addRoundedRect(card_rect, 12, 12)
        painter.fillPath(path, card_color)

        title_rect = QRectF(
            card_rect.left() + 14,
            card_rect.top() + 8,
            card_rect.width() - 28,
            title_h
        )
        title_font = QFont("Segoe UI", 11, QFont.Weight.DemiBold)
        painter.setFont(title_font)
        painter.setPen(text_color)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self.title)

        plot_left = card_rect.left() + pad_left
        plot_right = card_rect.right() - pad_right
        plot_top = card_rect.top() + pad_top + title_h
        plot_bottom = card_rect.bottom() - pad_bottom

        plot_width = plot_right - plot_left
        plot_height = plot_bottom - plot_top

        if plot_width <= 10 or plot_height <= 10:
            return

        if not self.values or max(self.values) == 0:
            painter.setPen(muted_color)
            empty_font = QFont("Segoe UI", 11)
            painter.setFont(empty_font)
            painter.drawText(
                QRectF(plot_left, plot_top, plot_width, plot_height),
                Qt.AlignmentFlag.AlignCenter,
                "No data"
            )
            return

        max_val = max(self.values)
        y_steps = 4
        painter.setPen(QPen(grid_color, 1, Qt.PenStyle.DotLine))
        axis_font = QFont("Consolas", 8)
        painter.setFont(axis_font)

        for i in range(y_steps + 1):
            frac = i / y_steps
            y = plot_bottom - frac * plot_height
            painter.drawLine(QPointF(plot_left, y), QPointF(plot_right, y))

            label_val = int(round(frac * max_val))
            painter.setPen(muted_color)
            painter.drawText(
                QRectF(card_rect.left() + 4, y - 8, pad_left - 8, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(label_val)
            )
            painter.setPen(QPen(grid_color, 1, Qt.PenStyle.DotLine))

        n = len(self.values)
        slot_width = plot_width / n
        bar_pad = slot_width * 0.25
        bar_width = slot_width - 2 * bar_pad

        accent = QColor("#00ffaa" if self.dark_mode else "#1e6fe0")

        for i, val in enumerate(self.values):
            x = plot_left + i * slot_width + bar_pad
            frac = val / max_val if max_val else 0
            bar_h = frac * plot_height
            y = plot_bottom - bar_h

            color = QColor(self.colors[i]) if self.colors[i] else accent

            grad = QLinearGradient(x, y, x, plot_bottom)
            grad.setColorAt(0.0, color.lighter(120))
            grad.setColorAt(1.0, color)
            brush = QBrush(grad)

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(brush)

            bar_path = QPainterPath()
            bar_path.addRoundedRect(QRectF(x, y, bar_width, bar_h), 4, 4)
            painter.drawPath(bar_path)

            painter.setPen(QPen(color.darker(140), 1))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(bar_path)

            val_font = QFont("Segoe UI", 9, QFont.Weight.Bold)
            painter.setFont(val_font)
            painter.setPen(QColor("#ffffff" if self.dark_mode else "#1a1a1a"))
            painter.drawText(
                QRectF(x - 4, y - 22, bar_width + 8, 18),
                Qt.AlignmentFlag.AlignCenter,
                str(val)
            )

            label = self.labels[i]
            label_font = QFont("Segoe UI", 8)
            painter.setFont(label_font)
            fm = QFontMetrics(label_font)
            text_w = fm.horizontalAdvance(label)
            available = slot_width - 4

            center_x = x + bar_width / 2
            center_y = plot_bottom + 10

            if text_w <= available:
                painter.setPen(muted_color)
                painter.drawText(
                    QRectF(center_x - slot_width / 2, center_y, slot_width, 20),
                    Qt.AlignmentFlag.AlignCenter,
                    label
                )
            else:
                painter.save()
                painter.translate(center_x, center_y + 4)
                painter.rotate(45)
                painter.setPen(muted_color)
                painter.drawText(0, 0, label)
                painter.restore()


class Dashboard(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.dark_mode = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(12)

        header = QHBoxLayout()
        header.setSpacing(10)

        self.title_label = QLabel("📊 Dashboard")
        title_font = QFont("Segoe UI", 16, QFont.Weight.DemiBold)
        self.title_label.setFont(title_font)
        header.addWidget(self.title_label)

        self.count_label = QLabel("No scan data - Run a scan to populate this chart")
        count_font = QFont("Segoe UI", 10)
        self.count_label.setFont(count_font)
        header.addWidget(self.count_label)

        header.addStretch()

        self.clear_button = QPushButton("Clear Results")
        self.clear_button.setFixedSize(120, 30)
        self.clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_button.clicked.connect(self.clear_results)
        header.addWidget(self.clear_button)

        self.export_chart = QPushButton("Export Chart")
        self.export_chart.setFixedSize(120, 30)
        self.export_chart.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_chart.clicked.connect(self.Export_charts)
        header.addWidget(self.export_chart)

        outer.addLayout(header)

        grid = QHBoxLayout()
        grid.setSpacing(12)

        col1 = QVBoxLayout()
        col1.setSpacing(12)
        col2 = QVBoxLayout()
        col2.setSpacing(12)

        self.chart_host = BarChart("Host Status")
        self.chart_ports = BarChart("Ports by State")
        self.chart_top = BarChart("Top Open Ports")
        self.chart_os = BarChart("OS Distribution")

        col1.addWidget(self.chart_host)
        col1.addWidget(self.chart_top)
        col2.addWidget(self.chart_ports)
        col2.addWidget(self.chart_os)

        grid.addLayout(col1, 1)
        grid.addLayout(col2, 1)

        outer.addLayout(grid, 1)

        self.apply_styles()

    def update_from_output(self, output):
        if not output or not output.strip():
            return

        parsed = parse_multi_target_output(output)
        if not parsed:
            return

        stats = compute_stats(parsed)

        self.chart_host.set_data(*stats["host_status"])
        self.chart_ports.set_data(*stats["port_states"])
        self.chart_top.set_data(*stats["top_ports"])
        self.chart_os.set_data(*stats["os_dist"])

        self.count_label.setText(f"{len(parsed)} target(s) analyzed")

    def clear_results(self):
        self.chart_host.set_data([], [])
        self.chart_ports.set_data([], [])
        self.chart_top.set_data([], [])
        self.chart_os.set_data([], [])
        self.count_label.setText("No scan data yet")

    def Export_charts(self):
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Export Dashboard",
            "dashboard.png",
            "PNG Image (*.png);;"
        )
        if not path:
            return

        if path.lower():
            export_all_charts(self, path)

    def apply_styles(self):
        is_dark = not (hasattr(self.parent, 'dark_mode') and self.parent.dark_mode)
        self.dark_mode = is_dark

        if is_dark:
            self.setStyleSheet("background-color: #1a1a1a ; color: #00ffaa;")
            self.title_label.setStyleSheet("color: #00ffaa;")
            self.count_label.setStyleSheet("color: #00ffaa;")
            self.clear_button.setStyleSheet("""
                QPushButton {
                    background-color: #0a0a0a;
                    color: #00ffaa;
                    border: 1px solid #0a0a0a;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 600;
                }
                QPushButton:hover { background-color: #000000; }
                QPushButton:pressed { background-color: #00ffaa; color: #000000; }
            """)
            self.export_chart.setStyleSheet("""
                QPushButton {
                    background-color: #0a0a0a;
                    color: #00ffaa;
                    border: 1px solid #0a0a0a;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 600;
                }
                QPushButton:hover { background-color: #000000; }
                QPushButton:pressed { background-color: #00ffaa; color: #000000; }
            """)
        else:
            self.setStyleSheet("background-color: #f7f5f0; color: #1e6fe0;")
            self.title_label.setStyleSheet("color: #1e6fe0;")
            self.count_label.setStyleSheet("color: #1e6fe0;")
            self.clear_button.setStyleSheet("""
                QPushButton {
                    background-color: #ffffff;
                    color: #1e6fe0;
                    border: 1px solid #dde2e9;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 600;
                }
                QPushButton:hover { background-color: #eef2f7; }
                QPushButton:pressed { background-color: #1e6fe0; color: #ffffff; }
            """)
            self.export_chart.setStyleSheet("""
                QPushButton {
                    background-color: #ffffff;
                    color: #1e6fe0;
                    border: 1px solid #dde2e9;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 600;
                }
                QPushButton:hover { background-color: #eef2f7; }
                QPushButton:pressed { background-color: #1e6fe0; color: #ffffff; }
            """)

        for chart in (self.chart_host, self.chart_ports, self.chart_top, self.chart_os):
            chart.set_theme(is_dark)


def compute_stats(parsed):
    host_counts = {"up": 0, "down": 0, "unknown": 0}
    open_total = 0
    closed_total = 0
    filtered_total = 0
    open_filtered_total = 0
    port_counter = {}
    os_counter = {}

    for target, data in parsed.items():
        status = (data.get('host_status') or 'unknown').lower()
        if status not in host_counts:
            status = 'unknown'
        host_counts[status] += 1

        open_total += data.get('open_ports_count', 0) or 0
        closed_total += data.get('closed_ports_count', 0) or 0
        filtered_total += data.get('filtered_ports_count', 0) or 0
        open_filtered_total += data.get('open_filtered_ports_count', 0) or 0

        for p in data.get('open_ports', []):
            key = (str(p.get('port', '')), p.get('service', 'unknown'))
            port_counter[key] = port_counter.get(key, 0) + 1

        os_name = data.get('os_fingerprint')
        if os_name:
            label = f"{os_name} ".strip()
            os_counter[label] = os_counter.get(label, 0) + 1

    host_labels = []
    host_values = []
    host_colors = []
    for key in ('up', 'down', 'unknown'):
        count = host_counts[key]
        if count > 0:
            host_labels.append(key.capitalize())
            host_values.append(count)
            host_colors.append(HOST_COLORS[key])

    port_labels = []
    port_values = []
    port_colors = []
    for key, count in (('open', open_total), ('closed', closed_total), ('filtered', filtered_total), ('open_filtered', open_filtered_total)):
        if count > 0:
            port_labels.append(key.capitalize())
            port_values.append(count)
            port_colors.append(PORT_COLORS[key])

    top_sorted = sorted(port_counter.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_labels = [f"{p} ({svc})" for (p, svc), _ in top_sorted]
    top_values = [c for _, c in top_sorted]
    top_colors = [None] * len(top_values)

    os_sorted = sorted(os_counter.items(), key=lambda kv: kv[1], reverse=True)
    os_labels = []
    os_values = []
    os_colors = []
    for name, count in os_sorted:
        os_labels.append(name)
        os_values.append(count)
        lower = name.lower()
        color = None
        for key, val in OS_COLORS.items():
            if key in lower:
                color = val
                break
        os_colors.append(color or DEFAULT_COLOR)

    return {
        "host_status": (host_labels, host_values, host_colors),
        "port_states": (port_labels, port_values, port_colors),
        "top_ports":   (top_labels, top_values, top_colors),
        "os_dist":     (os_labels, os_values, os_colors),
    }


def export_all_charts(dashboard, filepath):
    charts = [
        dashboard.chart_host,
        dashboard.chart_ports,
        dashboard.chart_top,
        dashboard.chart_os,
    ]

    pixmaps = [c.grab() for c in charts]

    w = pixmaps[0].width()
    h = pixmaps[0].height()
    gap = 12

    total_w = w * 2 + gap
    total_h = h * 2 + gap

    canvas = QPixmap(total_w, total_h)
    canvas.fill(QColor("#1a1a1a") if dashboard.dark_mode else QColor("#f7f5f0"))

    painter = QPainter(canvas)
    painter.drawPixmap(0, 0, pixmaps[0])
    painter.drawPixmap(w + gap, 0, pixmaps[1])
    painter.drawPixmap(0, h + gap, pixmaps[2])
    painter.drawPixmap(w + gap, h + gap, pixmaps[3])
    painter.end()

    canvas.save(filepath, "PNG")
