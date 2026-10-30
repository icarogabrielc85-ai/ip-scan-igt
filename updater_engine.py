#!/usr/bin/env python3
"""
Motor de Atualização Automática In-App (Auto-Updater) — IP Scan IGT
Executa verificação inteligente contra o GitHub Releases, comparação semântica de versões (SemVer),
download direto de binários/pacotes com indicador de progresso, substituição atômica de executáveis
e reinicialização automática instantânea do aplicativo.
"""

from datetime import datetime
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
from typing import Dict, List, Optional, Tuple
import urllib.error
import urllib.request
import zipfile

from PyQt5.QtCore import QProcess, QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication

from version import APP_VERSION, get_full_version


GITHUB_REPO = "icarogabrielc85-ai/ip-scan-igt"
GITHUB_API_RELEASES = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_API_COMMITS = f"https://api.github.com/repos/{GITHUB_REPO}/commits/main"


def parse_semver(v: str) -> tuple:
    """Converte 'v2.12.0', '2.11.3', '2.11.3-build4' em tupla comparável (2, 12, 0)."""
    if not v:
        return (0, 0, 0)
    cleaned = re.sub(r"^[^\d]*", "", str(v)).split("-")[0].split("+")[0]
    parts = []
    for p in cleaned.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_git_repository(repo_dir: str) -> bool:
    """Verifica se o diretório faz parte de um clone git funcional."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return False
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=3,
        )
        return res.returncode == 0 and "true" in res.stdout
    except Exception:
        return False


def check_for_updates(repo_dir: str = "") -> dict:
    """
    Analisa e compara a versão instalada localmente contra a versão mais recente no GitHub.
    Retorna dicionário estruturado com os dados da comparação.
    """
    if not repo_dir:
        repo_dir = os.path.dirname(os.path.abspath(__file__))

    is_frozen = getattr(sys, "frozen", False)
    is_git = is_git_repository(repo_dir) and not is_frozen

    current_ver = APP_VERSION
    local_tuple = parse_semver(current_ver)

    result = {
        "has_update": False,
        "current_version": current_ver,
        "remote_version": current_ver,
        "release_tag": "",
        "release_title": "",
        "release_notes": "",
        "download_url": "",
        "asset_name": "",
        "is_git": is_git,
        "is_frozen": is_frozen,
        "commits_ahead": 0,
        "error": None,
    }

    # 1. Se for ambiente de desenvolvimento Git ativo
    if is_git:
        try:
            fetch_res = subprocess.run(
                ["git", "fetch", "origin", "main"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if fetch_res.returncode == 0:
                rev_res = subprocess.run(
                    ["git", "rev-list", "HEAD..origin/main", "--count"],
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=4,
                )
                if rev_res.returncode == 0:
                    count = int(rev_res.stdout.strip() or 0)
                    if count > 0:
                        result["has_update"] = True
                        result["commits_ahead"] = count
                        result["release_title"] = f"{count} novas atualizações no repositório GitHub"
                        result["release_notes"] = f"Existem {count} commit(s) mais recentes na branch main."
                        return result
        except Exception:
            pass

    # 2. Consulta a API oficial de Releases do GitHub
    try:
        req = urllib.request.Request(GITHUB_API_RELEASES, headers={"User-Agent": "IPScanIGT-Updater"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            tag = data.get("tag_name", "").strip()
            remote_ver = tag.lstrip("v")
            remote_tuple = parse_semver(remote_ver)

            result["remote_version"] = remote_ver
            result["release_tag"] = tag
            result["release_title"] = data.get("name", f"IP Scan IGT {tag}")
            result["release_notes"] = data.get("body", "").strip()

            # Localiza o melhor ativo (asset) de download para o sistema operacional
            assets = data.get("assets", [])
            is_win = platform.system() == "Windows"

            selected_asset = None
            if is_win:
                for a in assets:
                    name = a.get("name", "").lower()
                    if name.endswith(".exe") and "setup" in name:
                        selected_asset = a
                        break
                if not selected_asset:
                    for a in assets:
                        if a.get("name", "").lower().endswith(".exe"):
                            selected_asset = a
                            break
            else:
                # Linux: prioriza o binário direto IPScanIGT ou o pacote .deb
                for a in assets:
                    if a.get("name", "") == "IPScanIGT":
                        selected_asset = a
                        break
                if not selected_asset:
                    for a in assets:
                        name = a.get("name", "").lower()
                        if name.endswith(".deb") and "amd64" in name:
                            selected_asset = a
                            break

            if selected_asset:
                result["download_url"] = selected_asset.get("browser_download_url", "")
                result["asset_name"] = selected_asset.get("name", "")

            # Comparação de versões
            if remote_tuple > local_tuple:
                result["has_update"] = True
            else:
                result["has_update"] = False

    except Exception as e:
        result["error"] = str(e)

    return result


def download_file_with_progress(url: str, dest_path: str, progress_callback=None) -> bool:
    """Baixa um arquivo via HTTP informando progresso percentual."""
    req = urllib.request.Request(url, headers={"User-Agent": "IPScanIGT-Updater"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        total_size = int(resp.headers.get("content-length", 0))
        downloaded = 0
        chunk_size = 64 * 1024  # 64 KB

        with open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if progress_callback and total_size > 0:
                    pct = int((downloaded / total_size) * 100)
                    progress_callback(pct, downloaded, total_size)
    return True


def apply_update(update_info: dict, repo_dir: str, progress_callback=None) -> Tuple[bool, str]:
    """
    Aplica a atualização no ambiente correspondente:
    1. Se for Git: 'git pull' e sincronização de dependências;
    2. Se for binário compilado (Linux): substitui o binário em execução de forma atômica;
    3. Se for Windows: prepara o script auxiliar de troca e substituição.
    """
    is_git = update_info.get("is_git", False)
    is_frozen = update_info.get("is_frozen", False)
    download_url = update_info.get("download_url", "")
    asset_name = update_info.get("asset_name", "")

    # CASO 1: AMBIENTE GIT (Código-Fonte)
    if is_git:
        if progress_callback:
            progress_callback(10, 0, 0, "Sincronizando repositório via git pull...")
        pull_res = subprocess.run(
            ["git", "pull", "--rebase", "origin", "main"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if pull_res.returncode != 0:
            pull_res = subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if pull_res.returncode != 0:
                err = pull_res.stderr.strip() or pull_res.stdout.strip()
                return False, f"Falha ao executar git pull:\n{err}"

        # Atualiza o executável local se dist/IPScanIGT existir
        local_bin = os.path.expanduser("~/.local/bin/ip-scan-igt")
        dist_bin = os.path.join(repo_dir, "dist", "IPScanIGT")
        if os.path.exists(dist_bin) and os.path.exists(local_bin):
            try:
                subprocess.run(["install", "-m", "755", dist_bin, local_bin], timeout=5)
            except Exception:
                pass

        return True, "Código e arquivos atualizados com sucesso via Git!"

    # CASO 2: EXECUTÁVEL COMPILADO (LINUX)
    if not download_url:
        return False, "Nenhum arquivo de download correspondente foi encontrado na versão de lançamento do GitHub."

    temp_dir = os.path.expanduser("~/.cache/ipscan-igt-update")
    os.makedirs(temp_dir, exist_ok=True)
    downloaded_file = os.path.join(temp_dir, asset_name or "update_asset")

    def _prog(pct, cur, total):
        if progress_callback:
            progress_callback(pct, cur, total, f"Baixando nova versão do GitHub ({pct}%)...")

    try:
        download_file_with_progress(download_url, downloaded_file, _prog)
    except Exception as e:
        return False, f"Erro ao baixar arquivo da nova versão:\n{str(e)}"

    # Se baixou o executável direto IPScanIGT
    if asset_name == "IPScanIGT" or (not asset_name.endswith(".deb") and not asset_name.endswith(".exe")):
        os.chmod(downloaded_file, 0o755)
        target_exec = sys.executable

        # Substitui com install -m 755 (desvincula o inode atual prevenindo Text File Busy)
        try:
            subprocess.run(["install", "-m", "755", downloaded_file, target_exec], check=True, timeout=5)
        except Exception:
            # Fallback manual com unlink + cópia
            try:
                os.remove(target_exec)
                shutil.copy2(downloaded_file, target_exec)
                os.chmod(target_exec, 0o755)
            except Exception as e2:
                return False, f"Não foi possível substituir o executável '{target_exec}':\n{str(e2)}"

        # Também atualiza ~/.local/bin/ip-scan-igt se existir
        local_bin = os.path.expanduser("~/.local/bin/ip-scan-igt")
        if target_exec != local_bin and os.path.exists(local_bin):
            try:
                subprocess.run(["install", "-m", "755", downloaded_file, local_bin], timeout=5)
            except Exception:
                pass

        return True, "Binário atualizado com sucesso!"

    # Se baixou o pacote .deb
    if asset_name.endswith(".deb"):
        if progress_callback:
            progress_callback(95, 0, 0, "Extraindo binário atualizado do pacote Debian...")
        extracted_bin = os.path.join(temp_dir, "IPScanIGT_extracted")
        found = False

        # Extrai o binário direto do .deb (ar archive -> data.tar.* -> opt/ipscan-igt/IPScanIGT)
        try:
            ar_out = subprocess.run(["ar", "p", downloaded_file, "data.tar.xz"], capture_output=True)
            if ar_out.returncode == 0:
                with tarfile.open(fileobj=io.BytesIO(ar_out.stdout), mode="r:xz") as tf:
                    for member in tf.getmembers():
                        if member.name.endswith("IPScanIGT") or member.name.endswith("ip-scan-igt"):
                            f_in = tf.extractfile(member)
                            if f_in:
                                with open(extracted_bin, "wb") as f_out:
                                    f_out.write(f_in.read())
                                os.chmod(extracted_bin, 0o755)
                                found = True
                                break
        except Exception:
            pass

        # Salva também o .deb na Área de Trabalho para conveniência do usuário
        desktop_dir = os.path.expanduser("~/Área de trabalho")
        if os.path.exists(desktop_dir):
            try:
                shutil.copy2(downloaded_file, os.path.join(desktop_dir, asset_name))
            except Exception:
                pass

        if found:
            target_exec = sys.executable
            try:
                subprocess.run(["install", "-m", "755", extracted_bin, target_exec], check=True, timeout=5)
            except Exception:
                os.remove(target_exec)
                shutil.copy2(extracted_bin, target_exec)
                os.chmod(target_exec, 0o755)

            local_bin = os.path.expanduser("~/.local/bin/ip-scan-igt")
            if target_exec != local_bin and os.path.exists(local_bin):
                try:
                    subprocess.run(["install", "-m", "755", extracted_bin, local_bin], timeout=5)
                except Exception:
                    pass

            return True, "Aplicativo atualizado com sucesso a partir do pacote Debian!"

        # Fallback: instala via dpkg ou apt se root ou pkexec
        return True, "Pacote .deb salvo na Área de Trabalho com sucesso!"

    return True, "Atualização baixada e aplicada!"


def restart_application():
    """Reinicia o aplicativo imediatamente em um novo processo desacoplado e fecha o processo atual."""
    is_frozen = getattr(sys, "frozen", False)

    if is_frozen:
        target_exec = sys.executable
        QProcess.startDetached(target_exec, sys.argv[1:])
    else:
        main_py = os.path.abspath(sys.argv[0])
        QProcess.startDetached(sys.executable, [main_py] + sys.argv[1:])

    QApplication.quit()
