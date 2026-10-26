"""
Manual Oficial do Usuário — IP Scan IGT
Inclui Visualizador Interativo com Índice Navegável, Busca Integrada e Gerador/Exportador Direto para PDF.
"""
import os
import subprocess
import sys
from typing import List, Tuple

from PyQt5.QtCore import QSizeF, Qt, QUrl
from PyQt5.QtGui import QDesktopServices, QFont, QTextCursor, QTextDocument
from PyQt5.QtPrintSupport import QPrintDialog, QPrinter
from PyQt5.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
)

from version import APP_RELEASE_DATE, APP_VERSION

MANUAL_SECTIONS: List[Tuple[str, str]] = [
    ("sec1", "1. Visão Geral e Interface Principal"),
    ("sec2", "2. Tabela de Dispositivos e Coluna 'Apelido'"),
    ("sec3", "3. Motor de Varredura e Placas de Rede"),
    ("sec4", "4. Menus do Sistema (Organização Completa)"),
    ("sec5", "5. Câmeras IP, NVRs e Vídeo (ONVIF / RTSP)"),
    ("sec6", "6. Acesso Remoto (RDP, SSH, Wake-on-LAN, Web)"),
    ("sec7", "7. Segurança: CVEs, Nmap e Network Guard (L2)"),
    ("sec8", "8. Monitoramento: Watchdog, SNMP e UPnP"),
    ("sec9", "9. Topologia Visual (NOC) e Traceroute TTL"),
    ("sec10", "10. Snapshots (Diff) e Relatórios Executivos"),
    ("sec11", "11. Teste de Internet, DNS e System Doctor"),
    ("sec12", "12. Atalhos de Teclado e Dicas Rápidas"),
]


def generate_user_manual_html(is_dark: bool = False, for_pdf: bool = False) -> str:
    """Gera o conteúdo HTML completo do Manual do Usuário (para tela ou exportação PDF)."""
    if for_pdf:
        bg = "#ffffff"
        card_bg = "#f4f6f8"
        text_col = "#1e242b"
        sub_col = "#475569"
        accent = "#164e78"
        border = "#cbd5e1"
        tbl_hdr = "#e2e8f0"
        code_bg = "#e8eef3"
    elif is_dark:
        bg = "#0e141f"
        card_bg = "#162032"
        text_col = "#f1f5f9"
        sub_col = "#94a3b8"
        accent = "#38bdf8"
        border = "#243447"
        tbl_hdr = "#1e293b"
        code_bg = "#0f172a"
    else:
        # Paleta Cinza Estilo VirtualBox
        bg = "#e2e2e2"
        card_bg = "#d6d6d6"
        text_col = "#1e242b"
        sub_col = "#3b424a"
        accent = "#164e78"
        border = "#a8a8a8"
        tbl_hdr = "#c8d4e0"
        code_bg = "#cecece"

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>Manual do Usuário — IP Scan IGT v{APP_VERSION}</title>
<style>
    body {{
        font-family: "Segoe UI", "Ubuntu", "Noto Sans", Arial, sans-serif;
        background-color: {bg};
        color: {text_col};
        line-height: 1.55;
        font-size: 13px;
        margin: 16px;
    }}
    h1 {{
        color: {accent};
        font-size: 22px;
        border-bottom: 2px solid {accent};
        padding-bottom: 6px;
        margin-top: 0px;
    }}
    h2 {{
        color: {accent};
        font-size: 16px;
        border-bottom: 1px solid {border};
        padding-bottom: 4px;
        margin-top: 22px;
    }}
    h3 {{
        color: {text_col};
        font-size: 14px;
        margin-top: 14px;
        margin-bottom: 4px;
    }}
    .cover-box {{
        background-color: {card_bg};
        border: 1px solid {border};
        border-left: 5px solid {accent};
        padding: 14px 18px;
        border-radius: 6px;
        margin-bottom: 18px;
    }}
    .toc-box {{
        background-color: {card_bg};
        border: 1px solid {border};
        padding: 12px 18px;
        border-radius: 6px;
        margin-bottom: 20px;
    }}
    .toc-box a {{
        color: {accent};
        text-decoration: none;
        font-weight: bold;
    }}
    .note-box {{
        background-color: {card_bg};
        border: 1px solid {border};
        border-left: 4px solid {accent};
        padding: 10px 14px;
        border-radius: 4px;
        margin: 10px 0;
    }}
    code {{
        background-color: {code_bg};
        padding: 2px 5px;
        border-radius: 3px;
        font-family: "JetBrains Mono", "Consolas", monospace;
        font-size: 12px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 10px 0 16px 0;
    }}
    th {{
        background-color: {tbl_hdr};
        color: {text_col};
        text-align: left;
        padding: 7px 10px;
        border: 1px solid {border};
        font-size: 12px;
    }}
    td {{
        padding: 6px 10px;
        border: 1px solid {border};
        font-size: 12px;
        vertical-align: top;
    }}
    ul, ol {{
        margin-top: 4px;
        margin-bottom: 10px;
    }}
    li {{
        margin-bottom: 4px;
    }}
</style>
</head>
<body>

<div class="cover-box">
    <h1>📘 MANUAL OFICIAL DO USUÁRIO — IP SCAN IGT</h1>
    <p><b>Versão:</b> v{APP_VERSION} &nbsp;|&nbsp; <b>Data de Lançamento:</b> {APP_RELEASE_DATE} &nbsp;|&nbsp; <b>Plataformas:</b> Linux (.deb / Binário) &amp; Windows (.exe / .msi)</p>
    <p style="color:{sub_col}; margin-bottom:0;">
        Guia completo de operação, descoberta de ativos, personalização de apelidos, auditoria de vulnerabilidades (CVEs),
        monitoramento contínuo (Watchdog), proteção contra intrusos (Network Guard), telemetria SNMP/UPnP, câmeras ONVIF/RTSP e mapeamento de topologia.
    </p>
</div>

<div class="toc-box">
    <h3>📑 ÍNDICE ANALÍTICO (SUMÁRIO)</h3>
    <ol>
        <li><a href="#sec1">Visão Geral e Interface Principal</a></li>
        <li><a href="#sec2">Tabela de Dispositivos e Coluna Editável "Apelido"</a></li>
        <li><a href="#sec3">Motor de Varredura Híbrida e Seleção de Placas de Rede</a></li>
        <li><a href="#sec4">Menus do Sistema (Organização em Varredura, Ferramentas e Segurança)</a></li>
        <li><a href="#sec5">Câmeras IP, NVRs e Configuração de Vídeo (ONVIF / RTSP)</a></li>
        <li><a href="#sec6">Acesso Remoto e Controle (RDP, Terminal SSH, Wake-on-LAN, Web)</a></li>
        <li><a href="#sec7">Segurança de Rede: Correlação de CVEs, Auditoria Nmap e Network Guard (L2)</a></li>
        <li><a href="#sec8">Monitoramento e Infraestrutura: Watchdog Contínuo, SNMP (UDP 161) e UPnP</a></li>
        <li><a href="#sec9">Mapeamento Visual de Topologia (NOC) e Traceroute Visual (TTL)</a></li>
        <li><a href="#sec10">Snapshots de Auditoria (Baseline Diff) e Relatórios Executivos (HTML/PDF/CSV)</a></li>
        <li><a href="#sec11">Diagnóstico de Internet, Benchmark Global de DNS e System Doctor</a></li>
        <li><a href="#sec12">Tabela Completa de Atalhos de Teclado</a></li>
    </ol>
</div>

<a name="sec1"></a>
<h2>1. Visão Geral e Interface Principal</h2>
<p>
O <b>IP Scan IGT</b> é uma suíte corporativa de descoberta, diagnóstico, monitoramento e segurança de redes locais (LAN/VLAN).
O programa inicia automaticamente em <b>tela cheia (maximizado)</b> e utiliza por padrão o <b>Tema Claro em tons neutros de cinza (estilo VirtualBox)</b> para reduzir a fadiga visual durante operações prolongadas em centros de operações de rede (NOC/SOC), contando também com <b>Modo Escuro</b> (<code>Ctrl+T</code>).
</p>
<ul>
    <li><b>Barra Superior (Tier 1):</b> Contém o botão principal <b>▶ Verificar</b> (<code>F5</code>), seletor rápido de placa de rede (<b>🖧 IP ▾</b>), campos de <b>Faixa de IP Inicial e Final</b>, seletor de <b>Máscara CIDR</b> (de <code>/8</code> a <code>/30</code>), campo de <b>Busca Instantânea</b> e botão de <b>Atualização em 1 Clique</b>.</li>
    <li><b>Barra de Ferramentas Ribbon (Tier 2):</b> Botões de expansão/recolhimento da árvore (<code>⊞ Expandir</code> / <code>⊟ Recolher</code>), chave de descoberta <code>🎥 ONVIF</code>, <code>⚙️ Vídeo</code>, <code>🔍 Nmap</code>, <code>🌐 Internet</code>, <code>🛡️ Watchdog</code>, <code>🚨 Guard</code>, <code>📸 Snapshots</code>, <code>📑 Relatório ▾</code>, seletor de idioma (9 idiomas) e indicadores KPI em tempo real (<i>Online, Latência Média, Serviços e CVEs</i>).</li>
    <li><b>Área Central em Abas:</b>
        <ul>
            <li><b>Resultado Scan:</b> Lista hierárquica compacta de todos os dispositivos encontrados na varredura atual.</li>
            <li><b>Favoritos:</b> Lista persistente de servidores e equipamentos críticos monitorados pelo usuário.</li>
            <li><b>🗺️ Topologia:</b> Grafo visual interativo da malha de rede centrada no Gateway padrão.</li>
        </ul>
    </li>
    <li><b>Painel Inferior Retrátil (Osciloscópio &amp; Inspetor):</b> Exibe o gráfico dinâmico de latência (Ping em tempo real com Mín/Méd/Máx/TTL), botões rápidos de ação e tabela técnica detalhada do host selecionado.</li>
</ul>

<a name="sec2"></a>
<h2>2. Tabela de Dispositivos e Coluna Editável "Apelido"</h2>
<p>
A grade de dispositivos possui espaçamento compacto otimizado para exibir dezenas de ativos simultaneamente e conta com <b>8 colunas classificáveis</b> (clique no título de qualquer coluna para ordenar em ordem crescente ▲ ou decrescente ▼):
</p>
<table>
    <tr>
        <th>Coluna</th>
        <th>Descrição Técnica</th>
        <th>Como Utilizar</th>
    </tr>
    <tr>
        <td><b>1. Status</b></td>
        <td>Indicador luminoso de disponibilidade (<code>●</code> verde online / <code>○</code> offline).</td>
        <td>Atualizado em tempo real pelo varredor silencioso de fundo.</td>
    </tr>
    <tr>
        <td><b>2. Nome</b></td>
        <td>Hostname detectado via DNS reverso, NetBIOS, mDNS ou SNMP/UPnP.</td>
        <td>Clique no sinal <code>[+]</code> ao lado do nome para expandir todas as portas, serviços Web e CVEs do host.</td>
    </tr>
    <tr>
        <td><b>3. Apelido (Editável)</b></td>
        <td><b>Nome personalizado definido por você</b> (ex: <i>"PC Recepção"</i>, <i>"Câmera Portaria"</i>, <i>"Servidor ERP"</i>).</td>
        <td><b>Dê duplo-clique diretamente na célula da coluna "Apelido"</b> (ou pressione <code>F2</code> / botão direito ➔ <i>Editar Apelido</i>) e digite o texto desejado. O apelido fica salvo automaticamente por endereço MAC e IP!</td>
    </tr>
    <tr>
        <td><b>4. IP</b></td>
        <td>Endereço IPv4 do ativo na sub-rede.</td>
        <td>Ordenação numérica inteligente (ex: <code>.2</code> vem antes de <code>.10</code>).</td>
    </tr>
    <tr>
        <td><b>5. Fabricante</b></td>
        <td>Fabricante da placa de rede identificado pela base IEEE OUI local + UPnP.</td>
        <td>Identifica marcas como Intelbras, Hikvision, Dell, Cisco, Mikrotik, Proxmox, TP-Link, etc.</td>
    </tr>
    <tr>
        <td><b>6. Endereço MAC</b></td>
        <td>Endereço físico de camada 2 (Ethernet / Wi-Fi).</td>
        <td>Usado também para Wake-on-LAN, fixação de Apelido e detecção de intrusos no Network Guard.</td>
    </tr>
    <tr>
        <td><b>7. Ping</b></td>
        <td>Tempo de resposta (RTT) em milissegundos (<code>ms</code>).</td>
        <td>Colorido automaticamente: Verde (&lt;2ms), Azul (&lt;25ms) e Âmbar (&gt;25ms).</td>
    </tr>
    <tr>
        <td><b>8. Comentários</b></td>
        <td>Resumo automático de tipo de equipamento, banners HTTP/SSH, SNMP, UPnP, portas abertas e alertas de segurança (CVEs / ARP Spoofing).</td>
        <td>Destaca em vermelho dispositivos com vulnerabilidades críticas ou conflito de IP.</td>
    </tr>
</table>

<div class="note-box">
    <b>💡 Dica sobre a Coluna "Apelido":</b> Sempre que você edita o campo <b>Apelido</b> de um computador, impressora ou câmera, o IP Scan IGT vincula esse apelido tanto ao <b>Endereço MAC</b> quanto ao <b>IP</b> em <code>~/.config/ipscan-igt/device_aliases.json</code>. Assim, mesmo que o roteador troque o IP do computador via DHCP no futuro, o programa reconhecerá o MAC e manterá o seu Apelido automaticamente!
</div>

<a name="sec3"></a>
<h2>3. Motor de Varredura Híbrida e Seleção de Placas de Rede</h2>
<ul>
    <li><b>Seleção de Placa de Rede (<code>🖧 IP ▾</code> ou <code>Ctrl+I</code>):</b> Detecta todas as interfaces Ethernet, Wi-Fi, Bridges, VLANs e VPNs ativas na máquina, preenchendo automaticamente a faixa de IP e a máscara de sub-rede.</li>
    <li><b>Descoberta Multi-Camada:</b> Combina simultaneamente tabela ARP do kernel, Ping ICMP nativo, sondagem TCP assíncrona em 21 portas corporativas (21, 22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 554, 631, 2443, 3306, 3389, 5060, 5900, 8000, 8006, 8080, 8443, 8899, 9100), NetBIOS (UDP 137), mDNS (UDP 5353), SNMP (UDP 161), UPnP/SSDP (UDP 1900) e WS-Discovery ONVIF (UDP 3702).</li>
</ul>

<a name="sec4"></a>
<h2>4. Menus do Sistema (Organização Completa)</h2>
<p>Para facilitar a navegação, os comandos do topo da janela estão divididos em <b>7 menus temáticos</b>:</p>
<ol>
    <li><b>Arquivo:</b> Exportação de Relatório Executivo HTML/PDF (<code>Ctrl+H</code>), Planilha CSV (<code>Ctrl+S</code>), JSON, TXT e comando Sair (<code>Ctrl+Q</code>).</li>
    <li><b>Varredura:</b> Iniciar Varredura (<code>F5</code>), Parar (<code>Esc</code>), Selecionar Placa de Rede (<code>Ctrl+I</code>), Expandir Todos (<code>Ctrl+E</code>), Recolher Todos (<code>Ctrl+R</code>), Editar Apelido (<code>F2</code>), Adicionar aos Favoritos (<code>Ctrl+D</code>) e Verificar Apenas Favoritos.</li>
    <li><b>Ferramentas:</b> Conexão RDP, Terminal SSH, Wake-on-LAN (WoL), Configuração de Vídeo/Câmeras, Teste de Internet &amp; DNS, Traceroute Visual (TTL) e Diagnóstico System Doctor.</li>
    <li><b>Segurança &amp; Auditoria:</b> Console Nmap (<code>Ctrl+N</code>), Network Guard (Intrusos &amp; ARP Spoofing), Watchdog Contínuo e Snapshots &amp; Comparador de Mudanças (Diff).</li>
    <li><b>Exibir:</b> Mostrar/Ocultar Painel Inferior de Osciloscópio (<code>Ctrl+P</code>) e Alternar Tema Claro/Escuro (<code>Ctrl+T</code>).</li>
    <li><b>Idioma / Language:</b> Alternância instantânea entre Português, Inglês, Espanhol, Italiano, Ucraniano, Russo, Chinês Simplificado, Polonês e Francês.</li>
    <li><b>Ajuda:</b> Manual do Usuário (<code>F1</code>), Download Direto do Manual em PDF, Teste de Internet, System Doctor, Atualização Automática, Histórico de Versões e Sobre.</li>
</ol>

<a name="sec5"></a>
<h2>5. Câmeras IP, NVRs e Configuração de Vídeo (ONVIF / RTSP)</h2>
<ul>
    <li><b>Descoberta Automática ONVIF:</b> Quando a caixa <code>🎥 ONVIF</code> está marcada, o scanner envia pacotes multicast WS-Discovery na rede para localizar câmeras IP e gravadores DVR/NVR mesmo em portas HTTP/RTSP não padronizadas.</li>
    <li><b>Reprodução de Vídeo em Baixa Latência:</b> Ao clicar em <b>▶ Assistir Câmera (RTSP)</b> no painel de detalhes ou menu de contexto, o sistema abre o fluxo de vídeo usando FFplay, MPV ou VLC com flags de latência zero (<code>-fflags nobuffer</code>).</li>
    <li><b>Configuração de Vídeo (<code>⚙️ Vídeo</code>):</b> Permite definir a resolução da janela de vídeo (ex: HD 1280x720, Full HD 1920x1080), protocolo de transporte (TCP ou UDP) e reprodutor multimídia preferido.</li>
</ul>

<a name="sec6"></a>
<h2>6. Acesso Remoto e Controle (RDP, Terminal SSH, Wake-on-LAN, Web)</h2>
<ul>
    <li><b>Área de Trabalho Remota (RDP - Porta 3389):</b> Inicia conexão remota com servidores e estações Windows usando FreeRDP (<code>xfreerdp</code>), Remmina, rdesktop ou <code>mstsc.exe</code> (no Windows).</li>
    <li><b>Terminal SSH Integrado (Porta 22):</b> Abre janela de conexão SSH para servidores Linux, switches, roteadores Mikrotik/Ubiquiti e hipervisores Proxmox.</li>
    <li><b>Wake-on-LAN (WoL - UDP Porta 9):</b> Envia o pacote mágico (<i>Magic Packet</i>) para o endereço MAC selecionado, permitindo ligar computadores remotamente pela placa de rede.</li>
    <li><b>Acesso Web HTTP / HTTPS / Proxmox (80, 443, 8006, 8080):</b> Duplo-clique em qualquer sub-item de serviço Web abre diretamente o painel de gerência no navegador padrão.</li>
</ul>

<a name="sec7"></a>
<h2>7. Segurança de Rede: Correlação de CVEs, Auditoria Nmap e Network Guard (L2)</h2>
<h3>7.1 Correlação Automática de Vulnerabilidades (CVEs SQLite)</h3>
<p>
O motor <code>cve_engine.py</code> cruza automaticamente os banners HTTP, SSH, SMB, RTSP e versões do Nmap com uma base SQLite embarcada de vulnerabilidades críticas conhecidas (como EternalBlue MS17-010, BlueKeep, OpenSSH regreSSHion, Hikvision/Dahua Command Injection, Apache Path Traversal, Proxmox/Jetty/ipp). Dispositivos vulneráveis recebem selos de risco (<b>CRÍTICO</b>, <b>ALTO</b>, <b>MÉDIO</b>) e links diretos para o boletim oficial no NIST NVD.
</p>
<h3>7.2 Console de Auditoria Avançada Nmap (<code>Ctrl+N</code>)</h3>
<p>
Executa varreduras profundas no ativo selecionado com 5 perfis prontos: <i>Scan Rápido (-T4 -F)</i>, <i>Portas Comuns + Serviços (-sV)</i>, <i>Auditoria Completa de OS + Versões (-A)</i>, <i>Todas as 65535 Portas (-p-)</i> e <i>Auditoria de Vulnerabilidades (Scripts NSE <code>--script vuln</code>)</i>. Ao finalizar, todas as portas e CVEs descobertas são mescladas automaticamente na árvore principal.
</p>
<h3>7.3 Network Guard — Proteção Camada 2 (<code>🚨 Guard</code>)</h3>
<ul>
    <li><b>Detecção de ARP Spoofing (MITM):</b> Alerta imediatamente se o MAC do Gateway padrão mudar ou se outro IP na rede assumir o endereço MAC do roteador principal.</li>
    <li><b>Detecção de Conflito de IP / Troca de MAC:</b> Identifica quando um endereço IP ativo passa a responder com uma placa de rede (MAC) diferente da registrada.</li>
    <li><b>Detecção de Intrusos (Novos Dispositivos):</b> Compara cada varredura com a sua <b>Lista de Confiança (Whitelist)</b> e destaca qualquer dispositivo desconhecido que tenha se conectado à rede corporativa.</li>
</ul>

<a name="sec8"></a>
<h2>8. Monitoramento e Infraestrutura: Watchdog Contínuo, SNMP (UDP 161) e UPnP</h2>
<ul>
    <li><b>Watchdog Contínuo em 2º Plano (<code>🛡️ Watchdog</code>):</b> Monitora silenciosamente todos os dispositivos salvos na aba <b>Favoritos</b> em intervalos configuráveis (ex: a cada 15 segundos). Se um servidor crítico cair ou voltar a responder, emite notificações nativas na área de trabalho e registra o evento no Histórico de Incidentes.</li>
    <li><b>Auditoria via SNMP v1/v2c (UDP 161):</b> Consulta ativos de infraestrutura sem depender de bibliotecas externas (codificador ASN.1 BER nativo), extraindo descrição do hardware (<code>sysDescr</code>), nome (<code>sysName</code>), tempo de atividade (<code>sysUpTime</code>), localização, interfaces de switches e alertas de suprimentos/toner de impressoras.</li>
    <li><b>Descoberta UPnP / SSDP (UDP 1900):</b> Localiza roteadores, Smart TVs, NAS e dispositivos IoT via multicast SSDP e lê o descritor XML para exibir modelo exato, fabricante, firmware e número de série.</li>
</ul>

<a name="sec9"></a>
<h2>9. Mapeamento Visual de Topologia (NOC) e Traceroute Visual (TTL)</h2>
<ul>
    <li><b>Aba 🗺️ Topologia:</b> Desenha automaticamente a topologia lógica da sub-rede posicionando o <b>Gateway Padrão</b> no centro, <b>Switches / Hipervisores Proxmox / NVRs / Máquina Local</b> no anel intermediário e os <b>Endpoints / Câmeras / Impressoras</b> nas extremidades, com linhas coloridas conforme a saúde do link (verde &lt;5ms, azul &lt;35ms, âmbar &gt;35ms). Suporta zoom com a roda do mouse, arraste de nós, filtros por categoria e exportação para imagem PNG.</li>
    <li><b>Traceroute Visual por Saltos (TTL):</b> Acessível pelo menu <i>Ferramentas ➔ Traceroute Visual</i> ou clicando com o botão direito em um host. Mapeia cada roteador intermediário até o destino (LAN ou Internet) exibindo tabela de saltos e gráfico visual de latência por salto.</li>
</ul>

<a name="sec10"></a>
<h2>10. Snapshots de Auditoria (Baseline Diff) e Relatórios Executivos</h2>
<ul>
    <li><b>Snapshots &amp; Comparador de Mudanças (<code>📸 Snapshots</code>):</b> Permite salvar uma "fotografia" (Baseline) do estado atual da rede e compará-la em qualquer data futura, listando separadamente: <b>🟢 Novos Dispositivos</b>, <b>🔴 Dispositivos Ausentes (Offline)</b> e <b>🟠 Ativos Modificados</b> (novas portas abertas, novas CVEs, troca de MAC ou hostname).</li>
    <li><b>Relatório Executivo Autocontido (HTML / PDF):</b> Gera um documento executivo pronto para auditoria e impressão contendo o <b>Score de Segurança da Rede (0 a 100)</b>, <b>Mapa Visual da Topologia embutido</b>, <b>Matriz de Vulnerabilidades (CVEs)</b>, <b>Telemetria SNMP/UPnP</b> e inventário completo (incluindo a coluna <b>Apelido</b>).</li>
</ul>

<a name="sec11"></a>
<h2>11. Diagnóstico de Internet, Benchmark Global de DNS e System Doctor</h2>
<ul>
    <li><b>Teste de Internet &amp; DNS (<code>🌐 Internet</code>):</b> Avalia a saúde do Gateway local, perda de pacotes WAN, velocidade de resolução do DNS atual da placa de rede e executa um benchmark comparativo em tempo real contra os principais servidores DNS mundiais (Cloudflare, Google, Quad9, OpenDNS, AdGuard), permitindo adicionar servidores DNS próprios da sua empresa.</li>
    <li><b>System Doctor (Diagnóstico de Dependências):</b> Verifica se utilitários externos opcionais (Nmap, FFplay, VLC, Remmina, FreeRDP, ARP/IP) estão instalados no sistema operacional e fornece o comando exato de instalação em 1 clique caso algum esteja ausente.</li>
</ul>

<a name="sec12"></a>
<h2>12. Tabela Completa de Atalhos de Teclado</h2>
<table>
    <tr>
        <th>Atalho</th>
        <th>Ação Executada</th>
    </tr>
    <tr><td><code>F1</code></td><td>Abrir este Manual do Usuário (com opção de baixar em PDF)</td></tr>
    <tr><td><code>F2</code></td><td>Editar o <b>Apelido</b> do dispositivo selecionado na tabela</td></tr>
    <tr><td><code>F5</code></td><td>Iniciar varredura da faixa de IP configurada</td></tr>
    <tr><td><code>Esc</code></td><td>Interromper / parar a varredura em andamento</td></tr>
    <tr><td><code>Ctrl + I</code></td><td>Abrir seletor detalhado de Placas de Rede e Sub-redes</td></tr>
    <tr><td><code>Ctrl + E</code></td><td>Expandir todos os serviços e portas de todos os dispositivos <code>[+]</code></td></tr>
    <tr><td><code>Ctrl + R</code></td><td>Recolher todos os itens da árvore <code>[-]</code></td></tr>
    <tr><td><code>Ctrl + D</code></td><td>Adicionar o dispositivo selecionado à aba <b>Favoritos</b></td></tr>
    <tr><td><code>Ctrl + N</code></td><td>Abrir o Console de Auditoria Avançada com <b>Nmap</b></td></tr>
    <tr><td><code>Ctrl + P</code></td><td>Mostrar ou ocultar o Painel Inferior de Osciloscópio e Detalhes</td></tr>
    <tr><td><code>Ctrl + T</code></td><td>Alternar entre o Tema Claro (Cinza VirtualBox) e o Tema Escuro</td></tr>
    <tr><td><code>Ctrl + H</code></td><td>Exportar Relatório Executivo completo em HTML / PDF</td></tr>
    <tr><td><code>Ctrl + S</code></td><td>Exportar planilha da varredura em formato CSV</td></tr>
    <tr><td><code>Ctrl + Q</code></td><td>Encerrar o IP Scan IGT com segurança</td></tr>
</table>

<p style="text-align:center; color:{sub_col}; margin-top:24px; font-size:11px;">
    IP Scan IGT v{APP_VERSION} — Desenvolvido para Administração Profissional de Redes, Infraestrutura e Segurança da Informação.
</p>
</body>
</html>
"""


def export_manual_to_pdf(pdf_path: str) -> bool:
    """Renderiza o Manual do Usuário diretamente em um arquivo PDF nativo A4."""
    try:
        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(pdf_path)
        printer.setPageSize(QPrinter.A4)
        printer.setPageMargins(12, 12, 12, 12, QPrinter.Millimeter)

        doc = QTextDocument()
        doc.setHtml(generate_user_manual_html(is_dark=False, for_pdf=True))
        doc.setPageSize(QSizeF(printer.pageRect().size()))
        doc.print_(printer)
        return os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0
    except Exception:
        return False


def get_default_manual_pdf_path() -> str:
    """Retorna o caminho padrão onde o PDF do manual é gerado automaticamente."""
    cfg_dir = os.path.expanduser("~/.config/ipscan-igt")
    os.makedirs(cfg_dir, exist_ok=True)
    return os.path.join(cfg_dir, f"Manual_Usuario_IP_Scan_IGT_v{APP_VERSION}.pdf")


class UserManualDialog(QDialog):
    """
    Janela do Manual do Usuário com Índice Interativo Lateral, Busca Rápida,
    Visualização Direta, Abertura em Leitor de PDF Nativo e Download Direto em PDF.
    """

    def __init__(self, parent=None, is_dark: bool = False):
        super().__init__(parent)
        self.is_dark = is_dark
        self.setWindowTitle(f"📖 Manual do Usuário — IP Scan IGT v{APP_VERSION}")
        self.resize(1100, 740)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Barra de Topo: Título + Busca + Botões de PDF (Download Direto & Abrir PDF)
        top_frame = QFrame()
        top_bg = "#162032" if self.is_dark else "#d2d2d2"
        border_col = "#243447" if self.is_dark else "#a8a8a8"
        top_frame.setStyleSheet(
            f"QFrame {{ background-color: {top_bg}; border: 1px solid {border_col}; border-radius: 6px; padding: 6px; }}"
        )
        top_layout = QHBoxLayout(top_frame)
        top_layout.setContentsMargins(8, 4, 8, 4)
        top_layout.setSpacing(8)

        lbl_title = QLabel(f"📘 Manual do Usuário (v{APP_VERSION})")
        lbl_title.setStyleSheet("font-weight: 800; font-size: 14px; border: none;")
        top_layout.addWidget(lbl_title)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Pesquisar função, ferramenta ou atalho no manual...")
        self.txt_search.setClearButtonEnabled(True)
        self.txt_search.setFixedHeight(30)
        self.txt_search.setMinimumWidth(240)
        self.txt_search.returnPressed.connect(self.find_next_in_manual)
        self.txt_search.textChanged.connect(self.find_in_manual)
        top_layout.addWidget(self.txt_search, 1)

        btn_find_next = QPushButton("Próximo ▾")
        btn_find_next.setFixedHeight(30)
        btn_find_next.clicked.connect(self.find_next_in_manual)
        top_layout.addWidget(btn_find_next)

        self.btn_open_pdf = QPushButton("📄 Abrir como PDF")
        self.btn_open_pdf.setFixedHeight(30)
        self.btn_open_pdf.setToolTip("Gerar e abrir o arquivo PDF imediatamente no leitor de PDF padrão do sistema")
        self.btn_open_pdf.setStyleSheet(
            "QPushButton { background-color: #2b6595; color: #ffffff; font-weight: bold; padding: 4px 12px; border-radius: 5px; }"
            "QPushButton:hover { background-color: #1d4f7a; }"
        )
        self.btn_open_pdf.clicked.connect(self.open_pdf_directly)
        top_layout.addWidget(self.btn_open_pdf)

        self.btn_download_pdf = QPushButton("📥 Baixar / Salvar PDF...")
        self.btn_download_pdf.setFixedHeight(30)
        self.btn_download_pdf.setToolTip("Fazer download / salvar uma cópia do Manual Completo em formato PDF no seu computador")
        self.btn_download_pdf.setStyleSheet(
            "QPushButton { background-color: #107c41; color: #ffffff; font-weight: bold; padding: 4px 12px; border-radius: 5px; }"
            "QPushButton:hover { background-color: #0c6334; }"
        )
        self.btn_download_pdf.clicked.connect(self.download_pdf_as)
        top_layout.addWidget(self.btn_download_pdf)

        self.btn_print = QPushButton("🖨️ Imprimir")
        self.btn_print.setFixedHeight(30)
        self.btn_print.clicked.connect(self.print_manual)
        top_layout.addWidget(self.btn_print)

        layout.addWidget(top_frame)

        # Divisor Central: Índice Lateral (Esquerda) + Conteúdo Completo do Manual (Direita)
        splitter = QSplitter(Qt.Horizontal)

        toc_container = QFrame()
        toc_layout = QVBoxLayout(toc_container)
        toc_layout.setContentsMargins(0, 0, 0, 0)
        toc_layout.setSpacing(4)

        lbl_toc = QLabel("📑 Índice de Capítulos")
        lbl_toc.setStyleSheet("font-weight: bold; font-size: 12px; padding: 2px 4px;")
        toc_layout.addWidget(lbl_toc)

        self.list_toc = QListWidget()
        self.list_toc.setMinimumWidth(255)
        self.list_toc.setMaximumWidth(310)
        for anchor, title in MANUAL_SECTIONS:
            item = QListWidgetItem(title)
            item.setData(Qt.UserRole, anchor)
            self.list_toc.addItem(item)
        self.list_toc.itemClicked.connect(self.on_toc_item_clicked)
        toc_layout.addWidget(self.list_toc, 1)

        splitter.addWidget(toc_container)

        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.browser.anchorClicked.connect(self.on_anchor_clicked)
        self.browser.setHtml(generate_user_manual_html(is_dark=self.is_dark, for_pdf=False))
        splitter.addWidget(self.browser)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([270, 810])
        layout.addWidget(splitter, 1)

        # Rodapé
        bottom_bar = QHBoxLayout()
        lbl_hint = QLabel(
            "💡 Dica: Clique em qualquer capítulo no Índice à esquerda para navegar ou clique em '📥 Baixar / Salvar PDF...' para salvar o manual."
        )
        lbl_hint.setStyleSheet("font-size: 11px;")
        bottom_bar.addWidget(lbl_hint)
        bottom_bar.addStretch()

        btn_close = QPushButton("Fechar")
        btn_close.setFixedHeight(30)
        btn_close.clicked.connect(self.accept)
        bottom_bar.addWidget(btn_close)
        layout.addLayout(bottom_bar)

    def on_toc_item_clicked(self, item: QListWidgetItem):
        anchor = item.data(Qt.UserRole)
        if anchor:
            self.browser.scrollToAnchor(anchor)

    def on_anchor_clicked(self, url: QUrl):
        frag = url.fragment()
        if frag:
            self.browser.scrollToAnchor(frag)
        elif url.scheme() in ("http", "https"):
            QDesktopServices.openUrl(url)

    def find_in_manual(self, text: str):
        query = text.strip()
        # Move o cursor para o início antes de procurar
        cursor = self.browser.textCursor()
        cursor.movePosition(QTextCursor.Start)
        self.browser.setTextCursor(cursor)
        if query:
            self.browser.find(query)

    def find_next_in_manual(self):
        query = self.txt_search.text().strip()
        if not query:
            return
        if not self.browser.find(query):
            # Se chegou ao final, volta ao topo
            cursor = self.browser.textCursor()
            cursor.movePosition(QTextCursor.Start)
            self.browser.setTextCursor(cursor)
            self.browser.find(query)

    def open_pdf_directly(self):
        pdf_path = get_default_manual_pdf_path()
        if export_manual_to_pdf(pdf_path):
            try:
                if sys.platform.startswith("win"):
                    os.startfile(pdf_path)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", pdf_path])
                else:
                    subprocess.Popen(["xdg-open", pdf_path])
            except Exception:
                QDesktopServices.openUrl(QUrl.fromLocalFile(pdf_path))
        else:
            QMessageBox.warning(self, "Aviso", "Não foi possível gerar o arquivo PDF temporário.")

    def download_pdf_as(self):
        default_dir = os.path.expanduser("~/Downloads")
        if not os.path.isdir(default_dir):
            default_dir = os.path.expanduser("~")
        default_file = os.path.join(default_dir, f"Manual_Usuario_IP_Scan_IGT_v{APP_VERSION}.pdf")

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Baixar / Salvar Manual do Usuário em PDF",
            default_file,
            "Documento PDF (*.pdf)",
        )
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        if export_manual_to_pdf(path):
            reply = QMessageBox.question(
                self,
                "Manual em PDF Salvo com Sucesso",
                f"O Manual do Usuário em PDF foi salvo em:\n{path}\n\nDeseja abrir o arquivo PDF agora?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Yes:
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        else:
            QMessageBox.critical(self, "Erro ao Salvar PDF", "Ocorreu um erro ao gerar o arquivo PDF.")

    def print_manual(self):
        printer = QPrinter(QPrinter.HighResolution)
        dlg = QPrintDialog(printer, self)
        if dlg.exec_() == QDialog.Accepted:
            doc = QTextDocument()
            doc.setHtml(generate_user_manual_html(is_dark=False, for_pdf=True))
            doc.print_(printer)
