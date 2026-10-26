#!/usr/bin/env python3
"""
Camera Video Resolution & Playback Settings Dialog for IP Scan IGT.
Allows users to configure viewing resolution, transport protocol (TCP/UDP),
low-latency flags, and preferred media player (FFplay / VLC).
"""

import json
import os
from typing import Dict, Optional, Tuple

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

VIDEO_CONFIG_FILE = os.path.expanduser("~/.config/linux-ipscan/video_config.json")

RESOLUTION_PRESETS = [
    ("800x600 (SVGA — Resolução Padrão)", "800x600", 800, 600),
    ("1280x720 (HD 720p)", "1280x720", 1280, 720),
    ("1920x1080 (Full HD 1080p)", "1920x1080", 1920, 1080),
    ("1024x768 (XGA 4:3)", "1024x768", 1024, 768),
    ("640x480 (VGA — Leve / Baixa Carga)", "640x480", 640, 480),
    ("Automático (Resolução Nativa da Câmera)", "auto", 0, 0),
    ("Personalizada (Definir Pixels)...", "custom", 800, 600),
]

DEFAULT_VIDEO_CONFIG = {
    "resolution_preset": "800x600",
    "custom_width": 800,
    "custom_height": 600,
    "transport": "tcp",
    "low_latency": True,
    "auto_exit": True,
    "player": "auto",
}


def get_video_config() -> Dict:
    """Loads persistent camera playback configuration, returning defaults if not found."""
    if not os.path.exists(VIDEO_CONFIG_FILE):
        return dict(DEFAULT_VIDEO_CONFIG)
    try:
        with open(VIDEO_CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            merged = dict(DEFAULT_VIDEO_CONFIG)
            merged.update(cfg)
            return merged
    except Exception:
        return dict(DEFAULT_VIDEO_CONFIG)


def save_video_config(cfg: Dict) -> bool:
    """Saves camera playback configuration to disk."""
    os.makedirs(os.path.dirname(VIDEO_CONFIG_FILE), exist_ok=True)
    try:
        with open(VIDEO_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print("Erro salvando configurações de vídeo:", e)
        return False


def get_video_dimensions() -> Tuple[Optional[int], Optional[int]]:
    """Returns (width, height) or (None, None) if native resolution is chosen."""
    cfg = get_video_config()
    preset = cfg.get("resolution_preset", "800x600")
    if preset == "auto":
        return None, None
    elif preset == "custom":
        w = cfg.get("custom_width", 800)
        h = cfg.get("custom_height", 600)
        return w, h
    else:
        for _, code, w, h in RESOLUTION_PRESETS:
            if code == preset and w > 0 and h > 0:
                return w, h
    return 800, 600


class VideoConfigDialog(QDialog):
    """
    Modal configuration dialog allowing user to set viewing resolution and options.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuração de Câmeras & Resolução de Vídeo")
        self.resize(520, 440)
        self.init_ui()
        self.load_config()

    def init_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(18, 16, 18, 16)
        vbox.setSpacing(12)

        is_dark = getattr(self.parent(), "is_dark_mode", False) if self.parent() else False
        hdr_bg = "#162032" if is_dark else "#d2d2d2"
        hdr_border = "#1f2937" if is_dark else "#a8a8a8"
        title_col = "#38bdf8" if is_dark else "#164e78"
        sub_col = "#94a3b8" if is_dark else "#3b424a"
        prev_bg = "#0f172a" if is_dark else "#d0d0d0"

        # Header card
        hdr = QFrame()
        hdr.setObjectName("videoHeaderFrame")
        hdr.setStyleSheet(f"""
            QFrame#videoHeaderFrame {{
                background-color: {hdr_bg};
                border: 1px solid {hdr_border};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        h_layout = QHBoxLayout(hdr)
        h_layout.setContentsMargins(6, 4, 6, 4)
        h_layout.setSpacing(12)

        lbl_icon = QLabel("🎥")
        lbl_icon.setStyleSheet("font-size: 28px; border: none;")
        h_layout.addWidget(lbl_icon)

        info_box = QVBoxLayout()
        info_box.setSpacing(2)
        lbl_title = QLabel("Configuração de Visualização de Câmeras (RTSP)")
        lbl_title.setStyleSheet(f"font-weight: bold; font-size: 14px; color: {title_col}; border: none;")
        lbl_sub = QLabel("Defina a resolução de exibição, player preferido e parâmetros de latência.")
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {sub_col}; border: none;")
        info_box.addWidget(lbl_title)
        info_box.addWidget(lbl_sub)
        h_layout.addLayout(info_box)
        vbox.addWidget(hdr)

        # Form
        form_frame = QFrame()
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(0, 4, 0, 4)
        form_layout.setSpacing(10)

        # 1. Preset combo
        box_res = QVBoxLayout()
        box_res.setSpacing(4)
        lbl_res = QLabel("Resolução de Exibição da Janela:")
        lbl_res.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.combo_res = QComboBox()
        self.combo_res.setFixedHeight(32)
        for label, code, _, _ in RESOLUTION_PRESETS:
            self.combo_res.addItem(label, code)
        self.combo_res.currentIndexChanged.connect(self.on_preset_changed)
        box_res.addWidget(lbl_res)
        box_res.addWidget(self.combo_res)
        form_layout.addLayout(box_res)

        # 2. Custom dimensions (hidden unless "custom" is selected)
        self.custom_box = QHBoxLayout()
        self.custom_box.setSpacing(10)
        lbl_w = QLabel("Largura (px):")
        lbl_w.setStyleSheet("font-weight: 500; font-size: 12px;")
        self.spin_w = QSpinBox()
        self.spin_w.setRange(320, 7680)
        self.spin_w.setValue(800)
        self.spin_w.setFixedHeight(30)
        self.spin_w.valueChanged.connect(self.update_preview)

        lbl_h = QLabel("Altura (px):")
        lbl_h.setStyleSheet("font-weight: 500; font-size: 12px;")
        self.spin_h = QSpinBox()
        self.spin_h.setRange(240, 4320)
        self.spin_h.setValue(600)
        self.spin_h.setFixedHeight(30)
        self.spin_h.valueChanged.connect(self.update_preview)

        self.custom_box.addWidget(lbl_w)
        self.custom_box.addWidget(self.spin_w)
        self.custom_box.addWidget(lbl_h)
        self.custom_box.addWidget(self.spin_h)
        self.custom_box.addStretch()
        form_layout.addLayout(self.custom_box)

        # 3. Transport protocol
        box_trans = QVBoxLayout()
        box_trans.setSpacing(4)
        lbl_trans = QLabel("Protocolo de Transporte RTSP:")
        lbl_trans.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.combo_trans = QComboBox()
        self.combo_trans.setFixedHeight(32)
        self.combo_trans.addItem("TCP (Recomendado — Sem perda de quadros ou artefatos)", "tcp")
        self.combo_trans.addItem("UDP (Menor sobrecarga de rede)", "udp")
        self.combo_trans.currentIndexChanged.connect(self.update_preview)
        box_trans.addWidget(lbl_trans)
        box_trans.addWidget(self.combo_trans)
        form_layout.addLayout(box_trans)

        # 4. Player selection
        box_player = QVBoxLayout()
        box_player.setSpacing(4)
        lbl_player = QLabel("Player de Vídeo Preferido:")
        lbl_player.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.combo_player = QComboBox()
        self.combo_player.setFixedHeight(32)
        self.combo_player.addItem("Automático (FFplay ou VLC detectado)", "auto")
        self.combo_player.addItem("FFplay (Ultra baixa latência / Recomendado)", "ffplay")
        self.combo_player.addItem("VLC Media Player", "vlc")
        self.combo_player.currentIndexChanged.connect(self.update_preview)
        box_player.addWidget(lbl_player)
        box_player.addWidget(self.combo_player)
        form_layout.addLayout(box_player)

        # 5. Checkboxes
        self.chk_latency = QCheckBox("Modo Baixa Latência (Buffer zero / Descarte de quadros atrasados)")
        self.chk_latency.setChecked(True)
        self.chk_latency.setStyleSheet("font-weight: 500; font-size: 12px;")
        self.chk_latency.toggled.connect(self.update_preview)
        form_layout.addWidget(self.chk_latency)

        self.chk_autoexit = QCheckBox("Fechar player automaticamente se o fluxo RTSP for interrompido")
        self.chk_autoexit.setChecked(True)
        self.chk_autoexit.setStyleSheet("font-weight: 500; font-size: 12px;")
        self.chk_autoexit.toggled.connect(self.update_preview)
        form_layout.addWidget(self.chk_autoexit)

        # Preview label
        self.lbl_preview = QLabel("Comando: ffplay -rtsp_transport tcp -x 800 -y 600 ...")
        self.lbl_preview.setStyleSheet(
            f"font-family: monospace; font-size: 11px; color: {title_col}; background: {prev_bg}; padding: 6px; border-radius: 4px; border: 1px solid {hdr_border};"
        )
        self.lbl_preview.setWordWrap(True)
        form_layout.addWidget(self.lbl_preview)

        vbox.addWidget(form_frame)

        # Action Buttons
        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        btn_reset = QPushButton("Restaurar Padrões")
        btn_reset.setFixedHeight(34)
        btn_reset.setStyleSheet("color: #94a3b8;")
        btn_reset.clicked.connect(self.reset_to_defaults)
        btn_box.addWidget(btn_reset)
        btn_box.addStretch()

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.setFixedHeight(34)
        btn_cancel.setFixedWidth(100)
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        self.btn_save = QPushButton("✔  Salvar")
        self.btn_save.setObjectName("btnStart")
        self.btn_save.setFixedHeight(34)
        self.btn_save.setFixedWidth(115)
        self.btn_save.setDefault(True)
        self.btn_save.clicked.connect(self.save_and_accept)
        btn_box.addWidget(self.btn_save)

        vbox.addLayout(btn_box)

    def on_preset_changed(self):
        preset = self.combo_res.currentData()
        is_custom = (preset == "custom")
        self.spin_w.setEnabled(is_custom)
        self.spin_h.setEnabled(is_custom)
        if not is_custom and preset != "auto":
            for _, code, w, h in RESOLUTION_PRESETS:
                if code == preset:
                    self.spin_w.setValue(w)
                    self.spin_h.setValue(h)
                    break
        self.update_preview()

    def update_preview(self):
        preset = self.combo_res.currentData()
        player = self.combo_player.currentData() or "ffplay"
        transport = self.combo_trans.currentData() or "tcp"
        low_lat = self.chk_latency.isChecked()
        auto_exit = self.chk_autoexit.isChecked()

        if preset == "auto":
            res_str = ""
        elif preset == "custom":
            res_str = f"-x {self.spin_w.value()} -y {self.spin_h.value()}" if player != "vlc" else f"--width={self.spin_w.value()} --height={self.spin_h.value()}"
        else:
            w, h = 800, 600
            for _, c, pw, ph in RESOLUTION_PRESETS:
                if c == preset:
                    w, h = pw, ph
                    break
            res_str = f"-x {w} -y {h}" if player != "vlc" else f"--width={w} --height={h}"

        if player == "vlc":
            cmd = f"vlc --rtsp-{transport} {'--network-caching=300 ' if low_lat else ''}{res_str} rtsp://<ip>:554/live"
        else:
            flags = "-fflags nobuffer -flags low_delay -framedrop -infbuf" if low_lat else ""
            exit_flag = "-autoexit" if auto_exit else ""
            cmd = f"ffplay -rtsp_transport {transport} {flags} {exit_flag} {res_str} -window_title \"Câmera IP\" rtsp://<ip>:554/live"

        self.lbl_preview.setText(f"Prévia do Comando:\n{' '.join(cmd.split())}")

    def load_config(self):
        cfg = get_video_config()
        preset = cfg.get("resolution_preset", "800x600")
        idx = self.combo_res.findData(preset)
        if idx >= 0:
            self.combo_res.setCurrentIndex(idx)
        else:
            self.combo_res.setCurrentIndex(0)

        self.spin_w.setValue(cfg.get("custom_width", 800))
        self.spin_h.setValue(cfg.get("custom_height", 600))

        trans = cfg.get("transport", "tcp")
        t_idx = self.combo_trans.findData(trans)
        if t_idx >= 0:
            self.combo_trans.setCurrentIndex(t_idx)

        player = cfg.get("player", "auto")
        p_idx = self.combo_player.findData(player)
        if p_idx >= 0:
            self.combo_player.setCurrentIndex(p_idx)

        self.chk_latency.setChecked(cfg.get("low_latency", True))
        self.chk_autoexit.setChecked(cfg.get("auto_exit", True))
        self.on_preset_changed()

    def reset_to_defaults(self):
        idx = self.combo_res.findData(DEFAULT_VIDEO_CONFIG["resolution_preset"])
        if idx >= 0:
            self.combo_res.setCurrentIndex(idx)
        self.spin_w.setValue(DEFAULT_VIDEO_CONFIG["custom_width"])
        self.spin_h.setValue(DEFAULT_VIDEO_CONFIG["custom_height"])
        self.combo_trans.setCurrentIndex(0)
        self.combo_player.setCurrentIndex(0)
        self.chk_latency.setChecked(True)
        self.chk_autoexit.setChecked(True)
        self.on_preset_changed()

    def save_and_accept(self):
        cfg = {
            "resolution_preset": self.combo_res.currentData(),
            "custom_width": self.spin_w.value(),
            "custom_height": self.spin_h.value(),
            "transport": self.combo_trans.currentData(),
            "player": self.combo_player.currentData(),
            "low_latency": self.chk_latency.isChecked(),
            "auto_exit": self.chk_autoexit.isChecked(),
        }
        ok = save_video_config(cfg)
        if ok:
            QMessageBox.information(
                self,
                "Configurações Salvas",
                "As configurações de resolução e reprodução de câmeras foram salvas com sucesso!"
            )
            self.accept()
        else:
            QMessageBox.critical(self, "Erro", "Não foi possível gravar o arquivo de configurações.")
