#!/usr/bin/env python3
"""
Banco de Dados de Scripts NSE (Nmap Scripting Engine) — IP Scan IGT
Catálogo oficial sincronizado com https://github.com/nmap/nmap/tree/master/scripts (605 scripts).
Permite seleção intuitiva por categorias, busca instantânea, presets de 1 clique e execução direta.
"""
import re
from typing import Dict, List, Optional

NSE_PRESETS = {
    "vuln": {
        "id": "vuln",
        "name": "🛡️ Todas as Vulnerabilidades (vuln)",
        "desc": "Auditoria automatizada de todas as vulnerabilidades e CVEs conhecidas sem causar indisponibilidade.",
        "arg": "vuln",
        "badge": "CVE / Vuln",
        "color": "#ef4444",
        "key_scripts": [
            "smb-vuln-ms17-010",
            "ssl-heartbleed",
            "ssl-poodle",
            "http-shellshock",
            "rdp-vuln-ms12-020"
        ]
    },
    "discovery": {
        "id": "discovery",
        "name": "🔍 Descoberta & Banners (discovery)",
        "desc": "Enumeração detalhada de hostnames, NetBIOS, mDNS, UPnP, banners e SO do alvo.",
        "arg": "discovery,safe",
        "badge": "Reconhecimento",
        "color": "#38bdf8",
        "key_scripts": [
            "nbstat",
            "smb-os-discovery",
            "dns-service-discovery",
            "upnp-info",
            "banner"
        ]
    },
    "web": {
        "id": "web",
        "name": "🌐 Auditoria Web & APIs (http-*)",
        "desc": "Captura títulos HTML, cabeçalhos, diretórios ocultos, métodos inseguros e caminhos robots.txt.",
        "arg": "http-title,http-headers,http-enum,http-methods,http-robots.txt,http-auth",
        "badge": "Web / HTTP",
        "color": "#0284c7",
        "key_scripts": [
            "http-title",
            "http-headers",
            "http-enum",
            "http-methods",
            "http-robots.txt",
            "http-auth"
        ]
    },
    "ssl": {
        "id": "ssl",
        "name": "🔒 Criptografia SSL/TLS (ssl-*)",
        "desc": "Avaliação de cifras suportadas com nota de A a F, expiração de certificados e testes Heartbleed/POODLE.",
        "arg": "ssl-enum-ciphers,ssl-cert,ssl-date,ssl-heartbleed,ssl-poodle",
        "badge": "Criptografia",
        "color": "#10b981",
        "key_scripts": [
            "ssl-enum-ciphers",
            "ssl-cert",
            "ssl-date",
            "ssl-heartbleed",
            "ssl-poodle"
        ]
    },
    "smb": {
        "id": "smb",
        "name": "🪟 Windows & Redes SMB (smb-*)",
        "desc": "Audita falha EternalBlue (MS17-010), versão do Windows, compartilhamentos de rede e assinatura SMB.",
        "arg": "smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares,smb-vuln-ms17-010",
        "badge": "Windows / SMB",
        "color": "#6366f1",
        "key_scripts": [
            "smb-os-discovery",
            "smb-security-mode",
            "smb2-security-mode",
            "smb-enum-shares",
            "smb-vuln-ms17-010"
        ]
    },
    "auth": {
        "id": "auth",
        "name": "🔑 Credenciais & Contas Fracas (auth)",
        "desc": "Identifica acessos anônimos (FTP), credenciais de fábrica comuns e serviços sem senha.",
        "arg": "auth,default",
        "badge": "Autenticação",
        "color": "#f59e0b",
        "key_scripts": [
            "ftp-anon",
            "ssh-auth-methods",
            "http-default-accounts",
            "snmp-info",
            "mysql-empty-password"
        ]
    },
    "cameras": {
        "id": "cameras",
        "name": "📹 Câmeras IP & CFTV (onvif / rtsp)",
        "desc": "Varredura de canais de streaming RTSP (/live, /ch0), serviços WS-Discovery ONVIF e painéis de vídeo.",
        "arg": "rtsp-url-brute,broadcast-ws-discovery,http-title",
        "badge": "CFTV / IoT",
        "color": "#ec4899",
        "key_scripts": [
            "rtsp-url-brute",
            "broadcast-ws-discovery",
            "http-title"
        ]
    },
    "safe_default": {
        "id": "safe_default",
        "name": "⚡ Padrão Seguro Oficial (-sC)",
        "desc": "Conjunto oficial de scripts recomendados pelo Nmap que não causam risco ou lentidão ao dispositivo.",
        "arg": "default,safe",
        "badge": "Padrão Oficial",
        "color": "#10b981",
        "key_scripts": [
            "banner",
            "http-title",
            "ssl-cert",
            "nbstat",
            "smb-os-discovery"
        ]
    },
    "malware": {
        "id": "malware",
        "name": "🦠 Detecção de Malware & Backdoors",
        "desc": "Varre portas e comportamentos de backdoors conhecidos, trojans e botnets.",
        "arg": "malware,safe",
        "badge": "Malware / Botnet",
        "color": "#8b5cf6",
        "key_scripts": [
            "auth-spoof",
            "backorifice-info"
        ]
    }
}

NSE_SCRIPTS_CATALOG = [
    {
        "name": "acarsd-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from a listening acarsd daemon. Acarsd decodes ACARS (Aircraft Communication Addressing and Reporting System) data in real time."
    },
    {
        "name": "address-info",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Shows extra information about IPv6 addresses, such as embedded MAC or IPv4 addresses when available."
    },
    {
        "name": "afp-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs password guessing against Apple Filing Protocol (AFP)."
    },
    {
        "name": "afp-ls",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to get useful information about files from AFP volumes. The output is intended to resemble the output of <code>ls</code>."
    },
    {
        "name": "afp-path-vuln",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533."
    },
    {
        "name": "afp-serverinfo",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Shows AFP server information. This information includes the server's hostname, IPv4 and IPv6 addresses, and hardware type (for example <code>Macmini</"
    },
    {
        "name": "afp-showmount",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Shows AFP shares and ACLs."
    },
    {
        "name": "ajp-auth",
        "categories": [
            "auth",
            "default",
            "safe"
        ],
        "desc": "Retrieves the authentication scheme and realm of an AJP service (Apache JServ Protocol) that requires authentication."
    },
    {
        "name": "ajp-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force passwords auditing against the Apache JServ protocol. The Apache JServ Protocol is commonly used by web servers to communicate wi"
    },
    {
        "name": "ajp-headers",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Performs a HEAD or GET request against either the root directory or any optional directory of an Apache JServ Protocol server and returns the server r"
    },
    {
        "name": "ajp-methods",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Discovers which options are supported by the AJP (Apache JServ Protocol) server by sending an OPTIONS request and lists potentially risky methods."
    },
    {
        "name": "ajp-request",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Requests a URI over the Apache JServ Protocol and displays the result (or stores it in a file). Different AJP methods such as; GET, HEAD, TRACE, PUT o"
    },
    {
        "name": "allseeingeye-info",
        "categories": [
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Detects the All-Seeing Eye service. Provided by some game servers for querying the server's status."
    },
    {
        "name": "amqp-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Gathers information (a list of all server properties) from an AMQP (advanced message queuing protocol) server."
    },
    {
        "name": "asn-query",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Maps IP addresses to autonomous system (AS) numbers."
    },
    {
        "name": "auth-owners",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Attempts to find the owner of an open TCP port by querying an auth daemon which must also be open on the target system. The auth service, also known a"
    },
    {
        "name": "auth-spoof",
        "categories": [
            "malware",
            "safe"
        ],
        "desc": "Checks for an identd (auth) server which is spoofing its replies."
    },
    {
        "name": "backorifice-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the BackOrifice service. The <code>backorifice-brute.ports</code> script argument is mandatory (it spec"
    },
    {
        "name": "backorifice-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Connects to a BackOrifice service and gathers information about the host and the BackOrifice service itself."
    },
    {
        "name": "bacnet-info",
        "categories": [
            "discovery",
            "version"
        ],
        "desc": "Discovers and enumerates BACNet Devices collects device information based off standard requests. In some cases, devices may not strictly follow the sp"
    },
    {
        "name": "banner",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Conecta e coleta banners de identificação em serviços TCP abertos."
    },
    {
        "name": "bitcoin-getaddr",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Queries a Bitcoin server for a list of known Bitcoin nodes"
    },
    {
        "name": "bitcoin-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Extracts version and node information from a Bitcoin server"
    },
    {
        "name": "bitcoinrpc-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Obtains information from a Bitcoin server by calling <code>getinfo</code> on its JSON-RPC interface."
    },
    {
        "name": "bittorrent-discovery",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Discovers bittorrent peers sharing a file based on a user-supplied torrent file or magnet link. Peers implement the Bittorrent protocol and share the "
    },
    {
        "name": "bjnp-discover",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves printer or scanner information from a remote device supporting the BJNP protocol. The protocol is known to be supported by network based Can"
    },
    {
        "name": "broadcast-ataoe-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers servers supporting the ATA over Ethernet protocol. ATA over Ethernet is an ethernet protocol developed by the Brantley Coile Company and all"
    },
    {
        "name": "broadcast-avahi-dos",
        "categories": [
            "broadcast",
            "dos",
            "intrusive",
            "vuln"
        ],
        "desc": "Attempts to discover hosts in the local network using the DNS Service Discovery protocol and sends a NULL UDP packet to each host to test if it is vul"
    },
    {
        "name": "broadcast-bjnp-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Attempts to discover Canon devices (Printers/Scanners) supporting the BJNP protocol by sending BJNP Discover requests to the network broadcast address"
    },
    {
        "name": "broadcast-db2-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Attempts to discover DB2 servers on the network by sending a broadcast request to port 523/udp."
    },
    {
        "name": "broadcast-dhcp-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Sends a DHCP request to the broadcast address (255.255.255.255) and reports the results. By default, the script uses a static MAC address (DE:AD:CO:DE"
    },
    {
        "name": "broadcast-dhcp6-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Sends a DHCPv6 request (Solicit) to the DHCPv6 multicast address, parses the response, then extracts and prints the address along with any options ret"
    },
    {
        "name": "broadcast-dns-service-discovery",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Attempts to discover hosts' services using the DNS Service Discovery protocol. It sends a multicast DNS-SD query and collects all the responses."
    },
    {
        "name": "broadcast-dropbox-listener",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Listens for the LAN sync information broadcasts that the Dropbox.com client broadcasts every 20 seconds, then prints all the discovered client IP addr"
    },
    {
        "name": "broadcast-eigrp-discovery",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Performs network discovery and routing information gathering through Cisco's Enhanced Interior Gateway Routing Protocol (EIGRP)."
    },
    {
        "name": "broadcast-hid-discoveryd",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Discovers HID devices on a LAN by sending a discoveryd network broadcast probe."
    },
    {
        "name": "broadcast-igmp-discovery",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Discovers targets that have IGMP Multicast memberships and grabs interesting information."
    },
    {
        "name": "broadcast-jenkins-discover",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Discovers Jenkins servers on a LAN by sending a discovery broadcast probe."
    },
    {
        "name": "broadcast-listener",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Sniffs the network for incoming broadcast communication and attempts to decode the received packets. It supports protocols like CDP, HSRP, Spotify, Dr"
    },
    {
        "name": "broadcast-ms-sql-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers Microsoft SQL servers in the same broadcast domain."
    },
    {
        "name": "broadcast-netbios-master-browser",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Attempts to discover master browsers and the domains they manage."
    },
    {
        "name": "broadcast-networker-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers EMC Networker backup software servers on a LAN by sending a network broadcast query."
    },
    {
        "name": "broadcast-novell-locate",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Attempts to use the Service Location Protocol to discover Novell NetWare Core Protocol (NCP) servers."
    },
    {
        "name": "broadcast-ospf2-discover",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Discover IPv4 networks using Open Shortest Path First version 2(OSPFv2) protocol."
    },
    {
        "name": "broadcast-pc-anywhere",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Sends a special broadcast probe to discover PC-Anywhere hosts running on a LAN."
    },
    {
        "name": "broadcast-pc-duo",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers PC-DUO remote control hosts and gateways running on a LAN by sending a special broadcast UDP probe."
    },
    {
        "name": "broadcast-pim-discovery",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Discovers routers that are running PIM (Protocol Independent Multicast)."
    },
    {
        "name": "broadcast-ping",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Sends broadcast pings on a selected interface using raw ethernet packets and outputs the responding hosts' IP and MAC addresses or (if requested) adds"
    },
    {
        "name": "broadcast-pppoe-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers PPPoE (Point-to-Point Protocol over Ethernet) servers using the PPPoE Discovery protocol (PPPoED). PPPoE is an ethernet based protocol so th"
    },
    {
        "name": "broadcast-rip-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers hosts and routing information from devices running RIPv2 on the LAN. It does so by sending a RIPv2 Request command and collects the response"
    },
    {
        "name": "broadcast-ripng-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers hosts and routing information from devices running RIPng on the LAN by sending a broadcast RIPng Request command and collecting any response"
    },
    {
        "name": "broadcast-sonicwall-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers Sonicwall firewalls which are directly attached (not routed) using the same method as the manufacturers own 'SetupTool'. An interface needs "
    },
    {
        "name": "broadcast-sybase-asa-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers Sybase Anywhere servers on the LAN by sending broadcast discovery messages."
    },
    {
        "name": "broadcast-tellstick-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers Telldus Technologies TellStickNet devices on the LAN. The Telldus TellStick is used to wirelessly control electric devices such as lights, d"
    },
    {
        "name": "broadcast-upnp-info",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Attempts to extract system information from the UPnP service by sending a multicast query, then collecting, parsing, and displaying all responses."
    },
    {
        "name": "broadcast-versant-locate",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers Versant object databases using the broadcast srvloc protocol."
    },
    {
        "name": "broadcast-wake-on-lan",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Wakes a remote system up from sleep by sending a Wake-On-Lan packet."
    },
    {
        "name": "broadcast-wpad-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Retrieves a list of proxy servers on a LAN using the Web Proxy Autodiscovery Protocol (WPAD). It implements both the DHCP and DNS methods of doing so "
    },
    {
        "name": "broadcast-wsdd-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Uses a multicast query to discover devices supporting the Web Services Dynamic Discovery (WS-Discovery) protocol. It also attempts to locate any publi"
    },
    {
        "name": "broadcast-xdmcp-discover",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Discovers servers running the X Display Manager Control Protocol (XDMCP) by sending a XDMCP broadcast request to the LAN. Display managers allowing ac"
    },
    {
        "name": "cassandra-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the Cassandra database."
    },
    {
        "name": "cassandra-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to get basic info and server status from a Cassandra database."
    },
    {
        "name": "cccam-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the CCcam service (software for sharing subscription TV among multiple receivers)."
    },
    {
        "name": "cics-enum",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "CICS transaction ID enumerator for IBM mainframes. This script is based on mainframe_brute by Dominic White (https://github.com/sensepost/mainframe_br"
    },
    {
        "name": "cics-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Using the CICS transaction CEMT, this script attempts to gather information about the current CICS transaction server region. It gathers OS informatio"
    },
    {
        "name": "cics-user-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "CICS User ID brute forcing script for the CESL login screen."
    },
    {
        "name": "cics-user-enum",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "CICS User ID enumeration script for the CESL/CESN Login screen."
    },
    {
        "name": "citrix-brute-xml",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Attempts to guess valid credentials for the Citrix PN Web Agent XML Service. The XML service authenticates against the local Windows server or the Act"
    },
    {
        "name": "citrix-enum-apps-xml",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Extracts a list of applications, ACLs, and settings from the Citrix XML service."
    },
    {
        "name": "citrix-enum-apps",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Extracts a list of published applications from the ICA Browser service."
    },
    {
        "name": "citrix-enum-servers-xml",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Extracts the name of the server farm and member servers from Citrix XML service."
    },
    {
        "name": "citrix-enum-servers",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Extracts a list of Citrix servers from the ICA Browser service."
    },
    {
        "name": "clamav-exec",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution."
    },
    {
        "name": "clock-skew",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Analyzes the clock skew between the scanner and various services that report timestamps."
    },
    {
        "name": "coap-resources",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Dumps list of available resources from CoAP endpoints."
    },
    {
        "name": "couchdb-databases",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Gets database tables from a CouchDB database."
    },
    {
        "name": "couchdb-stats",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Gets database statistics from a CouchDB database."
    },
    {
        "name": "creds-summary",
        "categories": [
            "auth",
            "default",
            "safe"
        ],
        "desc": "Lists all discovered credentials (e.g. from brute force and default password checking scripts) at end of scan."
    },
    {
        "name": "cups-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Lists printers managed by the CUPS printing service."
    },
    {
        "name": "cups-queue-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Lists currently queued print jobs of the remote CUPS service grouped by printer."
    },
    {
        "name": "cvs-brute-repository",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Attempts to guess the name of the CVS repositories hosted on the remote server. With knowledge of the correct repository name, usernames and passwords"
    },
    {
        "name": "cvs-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against CVS pserver authentication."
    },
    {
        "name": "daap-get-library",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves a list of music from a DAAP server. The list includes artist names and album and song titles."
    },
    {
        "name": "daytime",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves the day and time from the Daytime service."
    },
    {
        "name": "db2-das-info",
        "categories": [
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Connects to the IBM DB2 Administration Server (DAS) on TCP or UDP port 523 and exports the server profile. No authentication is required for this requ"
    },
    {
        "name": "deluge-rpc-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the DelugeRPC daemon."
    },
    {
        "name": "dhcp-discover",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Sends a DHCPINFORM request to a host on UDP port 67 to obtain all the local configuration parameters without allocating a new address."
    },
    {
        "name": "dicom-brute",
        "categories": [
            "auth",
            "brute"
        ],
        "desc": "Attempts to brute force the Application Entity Title of a DICOM server (DICOM Service Provider)."
    },
    {
        "name": "dicom-ping",
        "categories": [
            "auth",
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to discover DICOM servers (DICOM Service Provider) through a partial C-ECHO request. It also detects if the server allows any called Applicat"
    },
    {
        "name": "dict-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Connects to a dictionary server using the DICT protocol, runs the SHOW SERVER command, and displays the result. The DICT protocol is defined in RFC 22"
    },
    {
        "name": "distcc-cve2004-2687",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detects and exploits a remote code execution vulnerability in the distributed compiler daemon distcc. The vulnerability was disclosed in 2002, but is "
    },
    {
        "name": "dns-blacklist",
        "categories": [
            "external",
            "safe"
        ],
        "desc": "Checks target IP addresses against multiple DNS anti-spam and open proxy blacklists and returns a list of services for which an IP has been flagged. C"
    },
    {
        "name": "dns-brute",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Attempts to enumerate DNS hostnames by brute force guessing of common subdomains. With the <code>dns-brute.srv</code> argument, dns-brute will also tr"
    },
    {
        "name": "dns-cache-snoop",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Performs DNS cache snooping against a DNS server."
    },
    {
        "name": "dns-check-zone",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Checks DNS zone configuration against best practices, including RFC 1912. The configuration checks are divided into categories which each have a numbe"
    },
    {
        "name": "dns-client-subnet-scan",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Performs a domain lookup using the edns-client-subnet option which allows clients to specify the subnet that queries supposedly originate from. The sc"
    },
    {
        "name": "dns-fuzz",
        "categories": [
            "fuzzer",
            "intrusive"
        ],
        "desc": "Launches a DNS fuzzing attack against DNS servers."
    },
    {
        "name": "dns-ip6-arpa-scan",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Performs a quick reverse DNS lookup of an IPv6 network using a technique which analyzes DNS server response codes to dramatically reduce the number of"
    },
    {
        "name": "dns-nsec-enum",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumerates DNS names using the DNSSEC NSEC-walking technique."
    },
    {
        "name": "dns-nsec3-enum",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Tries to enumerate domain names from the DNS server that supports DNSSEC NSEC3 records."
    },
    {
        "name": "dns-nsid",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from a DNS nameserver by requesting its nameserver ID (nsid) and asking for its id.server and version.bind values. This script p"
    },
    {
        "name": "dns-random-srcport",
        "categories": [
            "external",
            "intrusive"
        ],
        "desc": "Checks a DNS server for the predictable-port recursion vulnerability. Predictable source ports can make a DNS server vulnerable to cache poisoning att"
    },
    {
        "name": "dns-random-txid",
        "categories": [
            "external",
            "intrusive"
        ],
        "desc": "Checks a DNS server for the predictable-TXID DNS recursion vulnerability. Predictable TXID values can make a DNS server vulnerable to cache poisoning "
    },
    {
        "name": "dns-recursion",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Checks if a DNS server allows queries for third-party names. It is expected that recursion will be enabled on your own internal nameservers."
    },
    {
        "name": "dns-service-discovery",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Enumera serviços locais anunciados via mDNS / DNS-SD (Bonjour / Apple / Linux)."
    },
    {
        "name": "dns-srv-enum",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Enumerates various common service (SRV) records for a given domain name. The service records contain the hostname, port and priority of servers for a "
    },
    {
        "name": "dns-update",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Attempts to perform a dynamic DNS update without authentication."
    },
    {
        "name": "dns-zeustracker",
        "categories": [
            "discovery",
            "external",
            "malware",
            "safe"
        ],
        "desc": "Checks if the target IP range is part of a Zeus botnet by querying ZTDNS @ abuse.ch. Please review the following information before you start to scan:"
    },
    {
        "name": "dns-zone-transfer",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Requests a zone transfer (AXFR) from a DNS server."
    },
    {
        "name": "docker-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the Docker service version."
    },
    {
        "name": "domcon-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the Lotus Domino Console."
    },
    {
        "name": "domcon-cmd",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Runs a console command on the Lotus Domino Console using the given authentication credentials (see also: domcon-brute)"
    },
    {
        "name": "domino-enum-users",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Attempts to discover valid IBM Lotus Domino users and download their ID files by exploiting the CVE-2006-5835 vulnerability."
    },
    {
        "name": "dpap-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against an iPhoto Library."
    },
    {
        "name": "drda-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby"
    },
    {
        "name": "drda-info",
        "categories": [
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Attempts to extract information from database servers supporting the DRDA protocol. The script sends a DRDA EXCSAT (exchange server attributes) comman"
    },
    {
        "name": "duplicates",
        "categories": [
            "safe"
        ],
        "desc": "Attempts to discover multihomed systems by analysing and comparing information collected by other scripts. The information analyzed currently includes"
    },
    {
        "name": "eap-info",
        "categories": [
            "broadcast",
            "safe"
        ],
        "desc": "Enumerates the authentication methods offered by an EAP (Extensible Authentication Protocol) authenticator for a given identity or for the anonymous i"
    },
    {
        "name": "enip-info",
        "categories": [
            "discovery",
            "version"
        ],
        "desc": "This NSE script is used to send a EtherNet/IP packet to a remote device that has TCP 44818 open. The script will send a Request Identity Packet and on"
    },
    {
        "name": "epmd-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Connects to Erlang Port Mapper Daemon (epmd) and retrieves a list of nodes with their respective port numbers."
    },
    {
        "name": "eppc-enum-processes",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to enumerate process info over the Apple Remote Event protocol. When accessing an application over the Apple Remote Event protocol the servic"
    },
    {
        "name": "fcrdns",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Performs a Forward-confirmed Reverse DNS lookup and reports anomalous results."
    },
    {
        "name": "finger",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to retrieve a list of usernames using the finger service."
    },
    {
        "name": "fingerprint-strings",
        "categories": [
            "version"
        ],
        "desc": "Prints the readable strings from service fingerprints of unknown services."
    },
    {
        "name": "firewalk",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Tries to discover firewall rules using an IP TTL expiration technique known as firewalking."
    },
    {
        "name": "firewall-bypass",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Detects a vulnerability in netfilter and other firewalls that use helpers to dynamically open ports for protocols such as ftp and sip."
    },
    {
        "name": "flume-master-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from Flume master HTTP pages."
    },
    {
        "name": "fox-info",
        "categories": [
            "discovery",
            "version"
        ],
        "desc": "Tridium Niagara Fox is a protocol used within Building Automation Systems. Based off Billy Rios and Terry McCorkle's work this Nmap NSE will collect i"
    },
    {
        "name": "freelancer-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Detects the Freelancer game server (FLServer.exe) service by sending a status query UDP probe."
    },
    {
        "name": "ftp-anon",
        "categories": [
            "auth",
            "default",
            "safe"
        ],
        "desc": "Verifica se o servidor FTP permite login anônimo (anonymous) sem senha."
    },
    {
        "name": "ftp-bounce",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Verifica se o servidor FTP permite ataques de bounce scan via comando PORT."
    },
    {
        "name": "ftp-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against FTP servers."
    },
    {
        "name": "ftp-libopie",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow), a vulnerability discovered by Maksymilian Arciemowicz and Adam \"pi3\" Zab"
    },
    {
        "name": "ftp-proftpd-backdoor",
        "categories": [
            "exploit",
            "intrusive",
            "malware",
            "vuln"
        ],
        "desc": "Tests for the presence of the ProFTPD 1.3.3c backdoor reported as BID 45150. This script attempts to exploit the backdoor using the innocuous <code>id"
    },
    {
        "name": "ftp-syst",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Sends FTP SYST and STAT commands and returns the result."
    },
    {
        "name": "ftp-vsftpd-backdoor",
        "categories": [
            "exploit",
            "intrusive",
            "malware",
            "vuln"
        ],
        "desc": "Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04 (CVE-2011-2523). This script attempts to exploit the backdoor using the inn"
    },
    {
        "name": "ftp-vuln-cve2010-4221",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks for a stack-based buffer overflow in the ProFTPD server, version between 1.3.2rc3 and 1.3.3b. By sending a large number of TELNET_IAC escape se"
    },
    {
        "name": "ganglia-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves system information (OS version, available memory, etc.) from a listening Ganglia Monitoring Daemon or Ganglia Meta Daemon."
    },
    {
        "name": "giop-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Queries a CORBA naming server for a list of objects."
    },
    {
        "name": "gkrellm-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Queries a GKRellM service for monitoring information. A single round of collection is made, showing a snapshot of information at the time of the reque"
    },
    {
        "name": "gopher-ls",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Lists files and directories at the root of a gopher service."
    },
    {
        "name": "gpsd-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves GPS time, coordinates and speed from the GPSD network daemon."
    },
    {
        "name": "hadoop-datanode-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Discovers information such as log directories from an Apache Hadoop DataNode HTTP status page."
    },
    {
        "name": "hadoop-jobtracker-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from an Apache Hadoop JobTracker HTTP status page."
    },
    {
        "name": "hadoop-namenode-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from an Apache Hadoop NameNode HTTP status page."
    },
    {
        "name": "hadoop-secondary-namenode-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from an Apache Hadoop secondary NameNode HTTP status page."
    },
    {
        "name": "hadoop-tasktracker-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from an Apache Hadoop TaskTracker HTTP status page."
    },
    {
        "name": "hbase-master-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from an Apache HBase (Hadoop database) master HTTP status page."
    },
    {
        "name": "hbase-region-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information from an Apache HBase (Hadoop database) region server HTTP status page."
    },
    {
        "name": "hddtemp-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Reads hard disk information (such as brand, model, and sometimes temperature) from a listening hddtemp service."
    },
    {
        "name": "hnap-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Retrieve hardwares details and configuration information utilizing HNAP, the \"Home Network Administration Protocol\". It is an HTTP-Simple Object Acces"
    },
    {
        "name": "hostmap-bfk",
        "categories": [
            "discovery",
            "external"
        ],
        "desc": "Discovers hostnames that resolve to the target's IP address by querying the online database at http://www.bfk.de/bfk_dnslogger.html."
    },
    {
        "name": "hostmap-crtsh",
        "categories": [
            "discovery",
            "external"
        ],
        "desc": "Finds subdomains of a web server by querying Google's Certificate Transparency logs database (https://crt.sh)."
    },
    {
        "name": "hostmap-robtex",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Discovers hostnames that resolve to the target's IP address by querying the online Robtex service at http://ip.robtex.com/."
    },
    {
        "name": "http-adobe-coldfusion-apsa1301",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Attempts to exploit an authentication bypass vulnerability in Adobe Coldfusion servers to retrieve a valid administrator's session cookie."
    },
    {
        "name": "http-affiliate-id",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Grabs affiliate network IDs (e.g. Google AdSense or Analytics, Amazon Associates, etc.) from a web page. These can be used to identify pages with the "
    },
    {
        "name": "http-apache-negotiation",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Checks if the target http server has mod_negotiation enabled. This feature can be leveraged to find hidden resources and spider a web site using fewer"
    },
    {
        "name": "http-apache-server-status",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to retrieve the server-status page for Apache webservers that have mod_status enabled. If the server-status page exists and appears to be fro"
    },
    {
        "name": "http-aspnet-debug",
        "categories": [
            "discovery",
            "vuln"
        ],
        "desc": "Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG request."
    },
    {
        "name": "http-auth-finder",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Procura formulários de autenticação ou login em páginas web."
    },
    {
        "name": "http-auth",
        "categories": [
            "auth",
            "default",
            "safe"
        ],
        "desc": "Detecta esquemas de autenticação web suportados (Basic, Digest, NTLM)."
    },
    {
        "name": "http-avaya-ipoffice-users",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Attempts to enumerate users in Avaya IP Office systems 7.x."
    },
    {
        "name": "http-awstatstotals-exec",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14 and possibly other products based on it (CVE: 2008-3922)."
    },
    {
        "name": "http-axis2-dir-traversal",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by sending a specially crafted request to the parameter <code>xsd</code> (B"
    },
    {
        "name": "http-backup-finder",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Spiders a website and attempts to identify backup copies of discovered files. It does so by requesting a number of different combinations of the filen"
    },
    {
        "name": "http-barracuda-dir-traversal",
        "categories": [
            "auth",
            "exploit",
            "intrusive"
        ],
        "desc": "Attempts to retrieve the configuration settings from a Barracuda Networks Spam & Virus Firewall device using the directory traversal vulnerability des"
    },
    {
        "name": "http-bigip-cookie",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Decodes any unencrypted F5 BIG-IP cookies in the HTTP response. BIG-IP cookies contain information on backend systems such as internal IP addresses an"
    },
    {
        "name": "http-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against http basic, digest and ntlm authentication."
    },
    {
        "name": "http-cakephp-version",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Obtains the CakePHP version of a web application built with the CakePHP framework by fingerprinting default files shipped with the CakePHP framework."
    },
    {
        "name": "http-chrono",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Measures the time a website takes to deliver a web page and returns the maximum, minimum and average time it took to fetch a page."
    },
    {
        "name": "http-cisco-anyconnect",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Connect as Cisco AnyConnect client to a Cisco SSL VPN and retrieves version and tunnel information."
    },
    {
        "name": "http-coldfusion-subzero",
        "categories": [
            "exploit"
        ],
        "desc": "Attempts to retrieve version, absolute path of administration panel and the file 'password.properties' from vulnerable installations of ColdFusion 9 a"
    },
    {
        "name": "http-comments-displayer",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Extracts and outputs HTML and JavaScript comments from HTTP responses."
    },
    {
        "name": "http-config-backup",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Checks for backups and swap files of common content management system and web server configuration files."
    },
    {
        "name": "http-cookie-flags",
        "categories": [
            "default",
            "safe",
            "vuln"
        ],
        "desc": "Examines cookies set by HTTP services. Reports any session cookies set without the httponly flag. Reports any session cookies set over SSL without the"
    },
    {
        "name": "http-cors",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Tests an http server for Cross-Origin Resource Sharing (CORS), a way for domains to explicitly opt in to having certain methods invoked by another dom"
    },
    {
        "name": "http-cross-domain-policy",
        "categories": [
            "external",
            "safe",
            "vuln"
        ],
        "desc": "Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml) in web applications and lists the tr"
    },
    {
        "name": "http-csrf",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "This script detects Cross Site Request Forgeries (CSRF) vulnerabilities."
    },
    {
        "name": "http-date",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Gets the date from HTTP-like services. Also prints how much the date differs from local time. Local time is the time the HTTP request was sent, so the"
    },
    {
        "name": "http-default-accounts",
        "categories": [
            "auth",
            "discovery",
            "intrusive"
        ],
        "desc": "Testa credenciais padrão de fábrica comuns em roteadores, switches e impressoras."
    },
    {
        "name": "http-devframework",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Tries to find out the technology behind the target website."
    },
    {
        "name": "http-dlink-backdoor",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Detects a firmware backdoor on some D-Link routers by changing the User-Agent to a \"secret\" value. Using the \"secret\" User-Agent bypasses authenticati"
    },
    {
        "name": "http-dombased-xss",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "It looks for places where attacker-controlled information in the DOM may be used to affect JavaScript execution in certain ways. The attack is explain"
    },
    {
        "name": "http-domino-enum-passwords",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Attempts to enumerate the hashed Domino Internet Passwords that are (by default) accessible by all authenticated users. This script can also download "
    },
    {
        "name": "http-drupal-enum-users",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumerates Drupal users by exploiting an information disclosure vulnerability in Views, Drupal's most popular module."
    },
    {
        "name": "http-drupal-enum",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumerates the installed Drupal modules/themes by using a list of known modules and themes."
    },
    {
        "name": "http-enum",
        "categories": [
            "discovery",
            "intrusive",
            "vuln"
        ],
        "desc": "Enumera diretórios e arquivos comuns em servidores web (/admin, /login, /phpmyadmin, etc.)."
    },
    {
        "name": "http-errors",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "This script crawls through the website and returns any error pages."
    },
    {
        "name": "http-exif-spider",
        "categories": [
            "intrusive"
        ],
        "desc": "Spiders a site's images looking for interesting exif data embedded in .jpg files. Displays the make and model of the camera, the date the photo was ta"
    },
    {
        "name": "http-favicon",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Gets the favicon (\"favorites icon\") from a web page and matches it against a database of the icons of known web applications. If there is a match, the"
    },
    {
        "name": "http-feed",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "This script crawls through the website to find any rss or atom feeds."
    },
    {
        "name": "http-fetch",
        "categories": [
            "safe"
        ],
        "desc": "The script is used to fetch files from servers."
    },
    {
        "name": "http-fileupload-exploiter",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits insecure file upload forms in web applications using various techniques like changing the Content-type header or creating valid image files c"
    },
    {
        "name": "http-form-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Script NSE oficial do Nmap da categoria brute."
    },
    {
        "name": "http-form-fuzzer",
        "categories": [
            "fuzzer",
            "intrusive"
        ],
        "desc": "Performs a simple form fuzzing against forms found on websites. Tries strings and numbers of increasing length and attempts to determine if the fuzzin"
    },
    {
        "name": "http-frontpage-login",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Checks whether target machines are vulnerable to anonymous Frontpage login."
    },
    {
        "name": "http-generator",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Displays the contents of the \"generator\" meta tag of a web page (default: /) if there is one."
    },
    {
        "name": "http-git",
        "categories": [
            "default",
            "safe",
            "vuln"
        ],
        "desc": "Verifica se o repositório .git está exposto publicamente na raiz do servidor web."
    },
    {
        "name": "http-gitweb-projects-enum",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves a list of Git projects, owners and descriptions from a gitweb (web interface to the Git revision control system)."
    },
    {
        "name": "http-google-malware",
        "categories": [
            "discovery",
            "external",
            "malware",
            "safe"
        ],
        "desc": "Checks if hosts are on Google's blacklist of suspected malware and phishing servers. These lists are constantly updated and are part of Google's Safe "
    },
    {
        "name": "http-grep",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Spiders a website and attempts to match all pages and urls against a given string. Matches are counted and grouped per url under which they were disco"
    },
    {
        "name": "http-headers",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Analisa cabeçalhos HTTP do servidor (Server, X-Powered-By, HSTS, CSP, Cookies)."
    },
    {
        "name": "http-hp-ilo-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to extract information from HP iLO boards including versions and addresses."
    },
    {
        "name": "http-huawei-hg5xx-vuln",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Detects Huawei modems models HG530x, HG520x, HG510x (and possibly others...) vulnerable to a remote credential and information disclosure vulnerabilit"
    },
    {
        "name": "http-icloud-findmyiphone",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Retrieves the locations of all \"Find my iPhone\" enabled iOS devices by querying the MobileMe web service (authentication required)."
    },
    {
        "name": "http-icloud-sendmsg",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Sends a message to a iOS device through the Apple MobileMe web service. The device has to be registered with an Apple ID using the Find My Iphone appl"
    },
    {
        "name": "http-iis-short-name-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Attempts to brute force the 8.3 filenames (commonly known as short names) of files and directories in the root folder of vulnerable IIS servers. This "
    },
    {
        "name": "http-iis-webdav-vuln",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access secured WebDAV folders by searching for a password-protected folder an"
    },
    {
        "name": "http-internal-ip-disclosure",
        "categories": [
            "discovery",
            "safe",
            "vuln"
        ],
        "desc": "Determines if the web server leaks its internal IP address when sending an HTTP/1.0 request without a Host header."
    },
    {
        "name": "http-joomla-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against Joomla web CMS installations."
    },
    {
        "name": "http-jsonp-detection",
        "categories": [
            "discovery",
            "safe",
            "vuln"
        ],
        "desc": "Attempts to discover JSONP endpoints in web servers. JSONP endpoints can be used to bypass Same-origin Policy restrictions in web browsers."
    },
    {
        "name": "http-litespeed-sourcecode-download",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x before 4.0.15 to retrieve the target script's source code by sending a HTT"
    },
    {
        "name": "http-ls",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Shows the content of an \"index\" Web page."
    },
    {
        "name": "http-majordomo2-dir-traversal",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files. (CVE-2011-0049)."
    },
    {
        "name": "http-malware-host",
        "categories": [
            "malware",
            "safe"
        ],
        "desc": "Looks for signature of known server compromises."
    },
    {
        "name": "http-mcmp",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Checks if the webserver allows mod_cluster management protocol (MCMP) methods."
    },
    {
        "name": "http-method-tamper",
        "categories": [
            "auth",
            "vuln"
        ],
        "desc": "Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering. If an array of paths to check is not set, it will"
    },
    {
        "name": "http-methods",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Identifica métodos HTTP permitidos (GET, POST, PUT, DELETE, TRACE) e opções inseguras."
    },
    {
        "name": "http-mobileversion-checker",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Checks if the website holds a mobile version."
    },
    {
        "name": "http-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote HTTP services with NTLM authentication enabled."
    },
    {
        "name": "http-open-proxy",
        "categories": [
            "default",
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Checks if an HTTP proxy is open."
    },
    {
        "name": "http-open-redirect",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Spiders a website and attempts to identify open redirects. Open redirects are handlers which commonly take a URL as a parameter and responds with a HT"
    },
    {
        "name": "http-passwd",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks if a web server is vulnerable to directory traversal by attempting to retrieve <code>/etc/passwd</code> or <code>\\boot.ini</code>."
    },
    {
        "name": "http-php-version",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to retrieve the PHP version from a web server. PHP has a number of magic queries that return images or text that can vary with the PHP versio"
    },
    {
        "name": "http-phpmyadmin-dir-traversal",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and possibly other versions) to retrieve remote files on the web server."
    },
    {
        "name": "http-phpself-xss",
        "categories": [
            "fuzzer",
            "intrusive",
            "vuln"
        ],
        "desc": "Crawls a web server and attempts to find PHP files vulnerable to reflected cross site scripting via the variable <code>$_SERVER[\"PHP_SELF\"]</code>."
    },
    {
        "name": "http-proxy-brute",
        "categories": [
            "brute",
            "external",
            "intrusive"
        ],
        "desc": "Performs brute force password guessing against HTTP proxy servers."
    },
    {
        "name": "http-put",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Uploads a local file to a remote web server using the HTTP PUT method. You must specify the filename and URL path with NSE arguments."
    },
    {
        "name": "http-qnap-nas-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to retrieve the model, firmware version, and enabled services from a QNAP Network Attached Storage (NAS) device."
    },
    {
        "name": "http-referer-checker",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Informs about cross-domain include of scripts. Websites that include external javascript scripts are delegating part of their security to third-party "
    },
    {
        "name": "http-rfi-spider",
        "categories": [
            "intrusive"
        ],
        "desc": "Crawls webservers in search of RFI (remote file inclusion) vulnerabilities. It tests every form field it finds and every parameter of a URL containing"
    },
    {
        "name": "http-robots.txt",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Lê o arquivo robots.txt para descobrir caminhos e URLs restritas pelo desenvolvedor."
    },
    {
        "name": "http-robtex-reverse-ip",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Obtains up to 100 forward DNS names for a target IP address by querying the Robtex service (https://www.robtex.com/ip-lookup/)."
    },
    {
        "name": "http-robtex-shared-ns",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Finds up to 100 domain names which use the same name server as the target by querying the Robtex service at http://www.robtex.com/dns/."
    },
    {
        "name": "http-sap-netweaver-leak",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Detects SAP Netweaver Portal instances that allow anonymous access to the KM unit navigation page. This page leaks file names, ldap users, etc."
    },
    {
        "name": "http-security-headers",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Checks for the HTTP response headers related to security given in OWASP Secure Headers Project and gives a brief description of the header and its con"
    },
    {
        "name": "http-server-header",
        "categories": [
            "version"
        ],
        "desc": "Uses the HTTP Server header for missing version info. This is currently infeasible with version probes because of the need to match non-HTTP services "
    },
    {
        "name": "http-shellshock",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Verifica vulnerabilidade Shellshock em CGIs Bash (CVE-2014-6271)."
    },
    {
        "name": "http-sitemap-generator",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Spiders a web server and displays its directory structure along with number and types of files in each folder. Note that files listed as having an 'Ot"
    },
    {
        "name": "http-slowloris-check",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Testa se o servidor web é suscetível a ataques de negação de serviço Slowloris."
    },
    {
        "name": "http-slowloris",
        "categories": [
            "dos",
            "intrusive"
        ],
        "desc": "Tests a web server for vulnerability to the Slowloris DoS attack by launching a Slowloris attack."
    },
    {
        "name": "http-sql-injection",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL injection attack. It also extracts forms from found websites and tries"
    },
    {
        "name": "http-stored-xss",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Posts specially crafted strings to every form it encounters and then searches through the website for those strings to determine whether the payloads "
    },
    {
        "name": "http-svn-enum",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Enumerates users of a Subversion repository by examining logs of most recent commits."
    },
    {
        "name": "http-svn-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Requests information from a Subversion repository."
    },
    {
        "name": "http-title",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Captura o título HTML da página web ou painel de gerenciamento do dispositivo."
    },
    {
        "name": "http-tplink-dir-traversal",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Exploits a directory traversal vulnerability existing in several TP-Link wireless routers. Attackers may exploit this vulnerability to read any of the"
    },
    {
        "name": "http-trace",
        "categories": [
            "discovery",
            "safe",
            "vuln"
        ],
        "desc": "Sends an HTTP TRACE request and shows if the method TRACE is enabled. If debug is enabled, it returns the header fields that were modified in the resp"
    },
    {
        "name": "http-traceroute",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Exploits the Max-Forwards HTTP header to detect the presence of reverse proxies."
    },
    {
        "name": "http-trane-info",
        "categories": [
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Attempts to obtain information from Trane Tracer SC devices. Trane Tracer SC is an intelligent field panel for communicating with HVAC equipment contr"
    },
    {
        "name": "http-unsafe-output-escaping",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Spiders a website and attempts to identify output escaping problems where content is reflected back to the user. This script locates all parameters, ?"
    },
    {
        "name": "http-useragent-tester",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Checks if various crawling utilities are allowed by the host."
    },
    {
        "name": "http-userdir-enum",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Attempts to enumerate valid usernames on web servers running with the mod_userdir module or similar enabled."
    },
    {
        "name": "http-vhosts",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Searches for web virtual hostnames by making a large number of HEAD requests against http servers using common hostnames."
    },
    {
        "name": "http-virustotal",
        "categories": [
            "external",
            "malware",
            "safe"
        ],
        "desc": "Checks whether a file has been determined as malware by Virustotal. Virustotal is a service that provides the capability to scan a file or check a che"
    },
    {
        "name": "http-vlcstreamer-ls",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Connects to a VLC Streamer helper service and lists directory contents. The VLC Streamer helper service is used by the iOS VLC Streamer application to"
    },
    {
        "name": "http-vmware-path-vuln",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server (CVE-2009-3733)."
    },
    {
        "name": "http-vuln-cve2006-3392",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)"
    },
    {
        "name": "http-vuln-cve2009-3960",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits cve-2009-3960 also known as Adobe XML External Entity Injection."
    },
    {
        "name": "http-vuln-cve2010-0738",
        "categories": [
            "auth",
            "safe",
            "vuln"
        ],
        "desc": "Tests whether a JBoss target is vulnerable to jmx console authentication bypass (CVE-2010-0738)."
    },
    {
        "name": "http-vuln-cve2010-2861",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Executes a directory traversal attack against a ColdFusion server and tries to grab the password hash for the administrator user. It then uses the sal"
    },
    {
        "name": "http-vuln-cve2011-3192",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detects a denial of service vulnerability in the way the Apache web server handles requests for multiple overlapping/simple ranges of a page."
    },
    {
        "name": "http-vuln-cve2011-3368",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Tests for the CVE-2011-3368 (Reverse Proxy Bypass) vulnerability in Apache HTTP server's reverse proxy mode. The script will run 3 tests: * the loopba"
    },
    {
        "name": "http-vuln-cve2012-1823",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This critical vulnerability allows attackers to retrieve source code and execute c"
    },
    {
        "name": "http-vuln-cve2013-0156",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Detects Ruby on Rails servers vulnerable to object injection, remote command executions and denial of service attacks. (CVE-2013-0156)"
    },
    {
        "name": "http-vuln-cve2013-6786",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Detects a URL redirection and reflected XSS vulnerability in Allegro RomPager Web server. The vulnerability has been assigned CVE-2013-6786."
    },
    {
        "name": "http-vuln-cve2013-7091",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "An 0 day was released on the 6th December 2013 by rubina119, and was patched in Zimbra 7.2.6."
    },
    {
        "name": "http-vuln-cve2014-2126",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA ASDM Privilege Escalation Vulnerability (CVE-2014-2126)."
    },
    {
        "name": "http-vuln-cve2014-2127",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN Privilege Escalation Vulnerability (CVE-2014-2127)."
    },
    {
        "name": "http-vuln-cve2014-2128",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN Authentication Bypass Vulnerability (CVE-2014-2128)."
    },
    {
        "name": "http-vuln-cve2014-2129",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SIP Denial of Service Vulnerability (CVE-2014-2129)."
    },
    {
        "name": "http-vuln-cve2014-3704",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions < 7.32 of Drupal core are known to be affected."
    },
    {
        "name": "http-vuln-cve2014-8877",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Exploits a remote code injection vulnerability (CVE-2014-8877) in Wordpress CM Download Manager plugin. Versions <= 2.0.0 are known to be affected."
    },
    {
        "name": "http-vuln-cve2015-1427",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "This script attempts to detect a vulnerability, CVE-2015-1427, which allows attackers to leverage features of this API to gain unauthenticated remote "
    },
    {
        "name": "http-vuln-cve2015-1635",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Checks for a remote code execution vulnerability (MS15-034) in Microsoft Windows systems (CVE2015-2015-1635)."
    },
    {
        "name": "http-vuln-cve2017-1001000",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Attempts to detect a privilege escalation vulnerability in Wordpress 4.7.0 and 4.7.1 that allows unauthenticated users to inject content in posts."
    },
    {
        "name": "http-vuln-cve2017-5638",
        "categories": [
            "vuln"
        ],
        "desc": "Detects whether the specified URL is vulnerable to the Apache Struts Remote Code Execution Vulnerability (CVE-2017-5638)."
    },
    {
        "name": "http-vuln-cve2017-5689",
        "categories": [
            "auth",
            "exploit",
            "vuln"
        ],
        "desc": "Detects if a system with Intel Active Management Technology is vulnerable to the INTEL-SA-00075 privilege escalation vulnerability (CVE2017-5689)."
    },
    {
        "name": "http-vuln-cve2017-8917",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "An SQL Injection vulnerability affecting Joomla! 3.7.x before 3.7.1 allows for unauthenticated users to execute arbitrary SQL commands. This vulnerabi"
    },
    {
        "name": "http-vuln-misfortune-cookie",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Detects the RomPager 4.07 Misfortune Cookie vulnerability by safely exploiting it."
    },
    {
        "name": "http-vuln-wnr1000-creds",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "A vulnerability has been discovered in WNR 1000 series that allows an attacker to retrieve administrator credentials with the router interface. Tested"
    },
    {
        "name": "http-waf-detect",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Attempts to determine whether a web server is protected by an IPS (Intrusion Prevention System), IDS (Intrusion Detection System) or WAF (Web Applicat"
    },
    {
        "name": "http-waf-fingerprint",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Tries to detect the presence of a web application firewall and its type and version."
    },
    {
        "name": "http-webdav-scan",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "A script to detect WebDAV installations. Uses the OPTIONS and PROPFIND methods."
    },
    {
        "name": "http-wordpress-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "performs brute force password auditing against Wordpress CMS/blog installations."
    },
    {
        "name": "http-wordpress-enum",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumerates themes and plugins of Wordpress installations. The script can also detect outdated plugins by comparing version numbers with information pu"
    },
    {
        "name": "http-wordpress-users",
        "categories": [
            "auth",
            "intrusive",
            "vuln"
        ],
        "desc": "Enumerates usernames in Wordpress blog/CMS installations by exploiting an information disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1, 3"
    },
    {
        "name": "http-xssed",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "This script searches the xssed.com database and outputs the result."
    },
    {
        "name": "https-redirect",
        "categories": [
            "version"
        ],
        "desc": "Check for HTTP services that redirect to the HTTPS on the same port."
    },
    {
        "name": "iax2-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the Asterisk IAX2 protocol. Guessing fails when a large number of attempts is made due to the maxcallnu"
    },
    {
        "name": "iax2-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the UDP IAX2 service."
    },
    {
        "name": "icap-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Tests a list of known ICAP service names and prints information about any it detects. The Internet Content Adaptation Protocol (ICAP) is used to exten"
    },
    {
        "name": "iec-identify",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Attempts to identify IEC 60870-5-104 ICS protocol."
    },
    {
        "name": "ike-version",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Obtains information (such as vendor and device type where available) from an IKE service by sending four packets to the host. This scripts tests with "
    },
    {
        "name": "imap-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication."
    },
    {
        "name": "imap-capabilities",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Retrieves IMAP email server capabilities."
    },
    {
        "name": "imap-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote IMAP services with NTLM authentication enabled."
    },
    {
        "name": "impress-remote-discover",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Tests for the presence of the LibreOffice Impress Remote server. Checks if a PIN is valid if provided and will bruteforce the PIN if requested."
    },
    {
        "name": "informix-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against IBM Informix Dynamic Server."
    },
    {
        "name": "informix-query",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Runs a query against IBM Informix Dynamic Server using the given authentication credentials (see also: informix-brute)."
    },
    {
        "name": "informix-tables",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Retrieves a list of tables and column definitions for each database on an Informix server."
    },
    {
        "name": "ip-forwarding",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Detects whether the remote device has ip forwarding or \"Internet connection sharing\" enabled, by sending an ICMP echo request to a given target using "
    },
    {
        "name": "ip-geolocation-geoplugin",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Tries to identify the physical location of an IP address using the Geoplugin geolocation web service (http://www.geoplugin.com/). There is no limit on"
    },
    {
        "name": "ip-geolocation-ipinfodb",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Tries to identify the physical location of an IP address using the IPInfoDB geolocation web service (http://ipinfodb.com/ip_location_api.php)."
    },
    {
        "name": "ip-geolocation-map-bing",
        "categories": [
            "external",
            "safe"
        ],
        "desc": "This script queries the Nmap registry for the GPS coordinates of targets stored by previous geolocation scripts and renders a Bing Map of markers repr"
    },
    {
        "name": "ip-geolocation-map-google",
        "categories": [
            "external",
            "safe"
        ],
        "desc": "This script queries the Nmap registry for the GPS coordinates of targets stored by previous geolocation scripts and renders a Google Map of markers re"
    },
    {
        "name": "ip-geolocation-map-kml",
        "categories": [
            "safe"
        ],
        "desc": "This script queries the Nmap registry for the GPS coordinates of targets stored by previous geolocation scripts and produces a KML file of points repr"
    },
    {
        "name": "ip-geolocation-maxmind",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Tries to identify the physical location of an IP address using a Geolocation Maxmind database file (available from http://www.maxmind.com/app/ip-locat"
    },
    {
        "name": "ip-https-discover",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Checks if the IP over HTTPS (IP-HTTPS) Tunneling Protocol [1] is supported."
    },
    {
        "name": "ipidseq",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Classifies a host's IP ID sequence (test for susceptibility to idle scan)."
    },
    {
        "name": "ipmi-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against IPMI RPC server."
    },
    {
        "name": "ipmi-cipher-zero",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "IPMI 2.0 Cipher Zero Authentication Bypass Scanner. This module identifies IPMI 2.0 compatible systems that are vulnerable to an authentication bypass"
    },
    {
        "name": "ipmi-version",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Performs IPMI Information Discovery through Channel Auth probes."
    },
    {
        "name": "ipv6-multicast-mld-list",
        "categories": [
            "broadcast",
            "discovery"
        ],
        "desc": "Uses Multicast Listener Discovery to list the multicast addresses subscribed to by IPv6 multicast listeners on the link-local scope. Addresses in the "
    },
    {
        "name": "ipv6-node-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Obtains hostnames, IPv4 and IPv6 addresses through IPv6 Node Information Queries."
    },
    {
        "name": "ipv6-ra-flood",
        "categories": [
            "dos",
            "intrusive"
        ],
        "desc": "Generates a flood of Router Advertisements (RA) with random source MAC addresses and IPv6 prefixes. Computers, which have stateless autoconfiguration "
    },
    {
        "name": "irc-botnet-channels",
        "categories": [
            "discovery",
            "safe",
            "vuln"
        ],
        "desc": "Checks an IRC server for channels that are commonly used by malicious botnets."
    },
    {
        "name": "irc-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against IRC (Internet Relay Chat) servers."
    },
    {
        "name": "irc-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Gathers information from an IRC server."
    },
    {
        "name": "irc-sasl-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication."
    },
    {
        "name": "irc-unrealircd-backdoor",
        "categories": [
            "exploit",
            "intrusive",
            "malware",
            "vuln"
        ],
        "desc": "Checks if an IRC server is backdoored by running a time-based command (ping) and checking how long it takes to respond."
    },
    {
        "name": "iscsi-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against iSCSI targets."
    },
    {
        "name": "iscsi-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Collects and displays information from remote iSCSI targets."
    },
    {
        "name": "isns-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Lists portals and iSCSI nodes registered with the Internet Storage Name Service (iSNS)."
    },
    {
        "name": "jdwp-exec",
        "categories": [
            "exploit",
            "intrusive"
        ],
        "desc": "Attempts to exploit java's remote debugging port. When remote debugging port is left open, it is possible to inject java bytecode and achieve remote c"
    },
    {
        "name": "jdwp-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to exploit java's remote debugging port. When remote debugging port is left open, it is possible to inject java bytecode and achieve remote c"
    },
    {
        "name": "jdwp-inject",
        "categories": [
            "exploit",
            "intrusive"
        ],
        "desc": "Attempts to exploit java's remote debugging port. When remote debugging port is left open, it is possible to inject java bytecode and achieve remote c"
    },
    {
        "name": "jdwp-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the Java Debug Wire Protocol. This protocol is used by Java programs to be debugged via the network. It should not be open to the public Inter"
    },
    {
        "name": "knx-gateway-discover",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Discovers KNX gateways by sending a KNX Search Request to the multicast address 224.0.23.12 including a UDP payload with destination port 3671. KNX ga"
    },
    {
        "name": "knx-gateway-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Identifies a KNX gateway on UDP port 3671 by sending a KNX Description Request."
    },
    {
        "name": "krb5-enum-users",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Discovers valid usernames by brute force querying likely usernames against a Kerberos service. When an invalid username is requested the server will r"
    },
    {
        "name": "ldap-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Attempts to brute-force LDAP authentication. By default it uses the built-in username and password lists. In order to use your own lists use the <code"
    },
    {
        "name": "ldap-novell-getpass",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to retrieve the Novell Universal Password for a user. You must already have (and include in script arguments) the username and password for a"
    },
    {
        "name": "ldap-rootdse",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves the LDAP root DSA-specific Entry (DSE)"
    },
    {
        "name": "ldap-search",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to perform an LDAP search and returns all matches."
    },
    {
        "name": "lexmark-config",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves configuration information from a Lexmark S300-S400 printer."
    },
    {
        "name": "llmnr-resolve",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Resolves a hostname by using the LLMNR (Link-Local Multicast Name Resolution) protocol."
    },
    {
        "name": "lltd-discovery",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Uses the Microsoft LLTD protocol to discover hosts on a local network."
    },
    {
        "name": "lu-enum",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Attempts to enumerate Logical Units (LU) of TN3270E servers."
    },
    {
        "name": "maxdb-info",
        "categories": [
            "default",
            "safe",
            "version"
        ],
        "desc": "Retrieves version and database information from a SAP Max DB database."
    },
    {
        "name": "mcafee-epo-agent",
        "categories": [
            "safe",
            "version"
        ],
        "desc": "Check if ePO agent is running on port 8081 or port identified as ePO Agent port."
    },
    {
        "name": "membase-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against Couchbase Membase servers."
    },
    {
        "name": "membase-http-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information (hostname, OS, uptime, etc.) from the CouchBase Web Administration port. The information retrieved by this script does not requi"
    },
    {
        "name": "memcached-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information (including system architecture, process ID, and server time) from distributed memory object caching system memcached."
    },
    {
        "name": "metasploit-info",
        "categories": [
            "intrusive",
            "safe"
        ],
        "desc": "Gathers info from the Metasploit rpc service. It requires a valid login pair. After authentication it tries to determine Metasploit version and deduce"
    },
    {
        "name": "metasploit-msgrpc-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force username and password auditing against Metasploit msgrpc interface."
    },
    {
        "name": "metasploit-xmlrpc-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against a Metasploit RPC server using the XMLRPC protocol."
    },
    {
        "name": "mikrotik-routeros-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled."
    },
    {
        "name": "mmouse-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the RPA Tech Mobile Mouse servers."
    },
    {
        "name": "mmouse-exec",
        "categories": [
            "intrusive"
        ],
        "desc": "Connects to an RPA Tech Mobile Mouse server, starts an application and sends a sequence of keys to it. Any application that the user has access to can"
    },
    {
        "name": "modbus-discover",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumerates SCADA Modbus slave ids (sids) and collects their device information."
    },
    {
        "name": "mongodb-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the MongoDB database."
    },
    {
        "name": "mongodb-databases",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to get a list of tables from a MongoDB database."
    },
    {
        "name": "mongodb-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to get build info and server status from a MongoDB database."
    },
    {
        "name": "mqtt-subscribe",
        "categories": [
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Dumps message traffic from MQTT brokers."
    },
    {
        "name": "mrinfo",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Queries targets for multicast routing information."
    },
    {
        "name": "ms-sql-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs password guessing against Microsoft SQL Server (ms-sql). Works best in conjunction with the <code>broadcast-ms-sql-discover</code> script."
    },
    {
        "name": "ms-sql-config",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Queries Microsoft SQL Server (ms-sql) instances for a list of databases, linked servers, and configuration settings."
    },
    {
        "name": "ms-sql-dac",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Queries the Microsoft SQL Browser service for the DAC (Dedicated Admin Connection) port of a given (or all) SQL Server instance. The DAC port is used "
    },
    {
        "name": "ms-sql-dump-hashes",
        "categories": [
            "auth",
            "discovery",
            "safe"
        ],
        "desc": "Dumps the password hashes from an MS-SQL server in a format suitable for cracking by tools such as John-the-ripper. In order to do so the user needs t"
    },
    {
        "name": "ms-sql-empty-password",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Attempts to authenticate to Microsoft SQL Servers using an empty password for the sysadmin (sa) account."
    },
    {
        "name": "ms-sql-hasdbaccess",
        "categories": [
            "auth",
            "discovery",
            "safe"
        ],
        "desc": "Queries Microsoft SQL Server (ms-sql) instances for a list of databases a user has access to."
    },
    {
        "name": "ms-sql-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Script NSE oficial do Nmap da categoria default."
    },
    {
        "name": "ms-sql-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote Microsoft SQL services with NTLM authentication enabled."
    },
    {
        "name": "ms-sql-query",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Runs a query against Microsoft SQL Server (ms-sql)."
    },
    {
        "name": "ms-sql-tables",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Script NSE oficial do Nmap da categoria discovery."
    },
    {
        "name": "ms-sql-xp-cmdshell",
        "categories": [
            "intrusive"
        ],
        "desc": "Attempts to run a command using the command shell of Microsoft SQL Server (ms-sql)."
    },
    {
        "name": "msrpc-enum",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Queries an MSRPC endpoint mapper for a list of mapped services and displays the gathered information."
    },
    {
        "name": "mtrace",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Queries for the multicast path from a source to a destination host."
    },
    {
        "name": "murmur-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the Murmur service (server for the Mumble voice communication client) versions 1.2.X."
    },
    {
        "name": "mysql-audit",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Audits MySQL database server security configuration against parts of the CIS MySQL v1.0.2 benchmark (the engine can be used for other MySQL audits by "
    },
    {
        "name": "mysql-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs password guessing against MySQL."
    },
    {
        "name": "mysql-databases",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Attempts to list all databases on a MySQL server."
    },
    {
        "name": "mysql-dump-hashes",
        "categories": [
            "auth",
            "discovery",
            "safe"
        ],
        "desc": "Dumps the password hashes from an MySQL server in a format suitable for cracking by tools such as John the Ripper. Appropriate DB privileges (root) ar"
    },
    {
        "name": "mysql-empty-password",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Verifica se contas administrativas root do MySQL estão sem senha."
    },
    {
        "name": "mysql-enum",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists.org/fulldisclosure/2012/Dec/9)."
    },
    {
        "name": "mysql-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Coleta versão, salt e recursos suportados pelo banco de dados MySQL."
    },
    {
        "name": "mysql-query",
        "categories": [
            "auth",
            "discovery",
            "safe"
        ],
        "desc": "Runs a query against a MySQL database and returns the results as a table."
    },
    {
        "name": "mysql-users",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Attempts to list all users on a MySQL server."
    },
    {
        "name": "mysql-variables",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Attempts to show all variables on a MySQL server."
    },
    {
        "name": "mysql-vuln-cve2012-2122",
        "categories": [
            "discovery",
            "intrusive",
            "vuln"
        ],
        "desc": "Attempts to bypass authentication in MySQL and MariaDB servers by exploiting CVE2012-2122. If its vulnerable, it will also attempt to dump the MySQL u"
    },
    {
        "name": "nat-pmp-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Gets the routers WAN IP using the NAT Port Mapping Protocol (NAT-PMP). The NAT-PMP protocol is supported by a broad range of routers including: * Appl"
    },
    {
        "name": "nat-pmp-mapport",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Maps a WAN port on the router to a local port on the client using the NAT Port Mapping Protocol (NAT-PMP). It supports the following operations: * map"
    },
    {
        "name": "nbd-info",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Displays protocol and block device information from NBD servers."
    },
    {
        "name": "nbns-interfaces",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves IP addresses of the target's network interfaces via NetBIOS NS. Additional network interfaces may reveal more information about the target, "
    },
    {
        "name": "nbstat",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Coleta nome NetBIOS, domínio Windows e endereço MAC da estação via UDP 137."
    },
    {
        "name": "ncp-enum-users",
        "categories": [
            "auth",
            "safe"
        ],
        "desc": "Retrieves a list of all eDirectory users from the Novell NetWare Core Protocol (NCP) service."
    },
    {
        "name": "ncp-serverinfo",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves eDirectory server information (OS version, server name, mounts, etc.) from the Novell NetWare Core Protocol (NCP) service."
    },
    {
        "name": "ndmp-fs-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Lists remote file systems by querying the remote device using the Network Data Management Protocol (ndmp). NDMP is a protocol intended to transport da"
    },
    {
        "name": "ndmp-version",
        "categories": [
            "version"
        ],
        "desc": "Retrieves version information from the remote Network Data Management Protocol (ndmp) service. NDMP is a protocol intended to transport data between a"
    },
    {
        "name": "nessus-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against a Nessus vulnerability scanning daemon using the NTP 1.2 protocol."
    },
    {
        "name": "nessus-xmlrpc-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol."
    },
    {
        "name": "netbus-auth-bypass",
        "categories": [
            "auth",
            "safe",
            "vuln"
        ],
        "desc": "Checks if a NetBus server is vulnerable to an authentication bypass vulnerability which allows full access without knowing the password."
    },
    {
        "name": "netbus-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the Netbus backdoor (\"remote administration\") service."
    },
    {
        "name": "netbus-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Opens a connection to a NetBus server and extracts information about the host and the NetBus service itself."
    },
    {
        "name": "netbus-version",
        "categories": [
            "version"
        ],
        "desc": "Extends version detection to detect NetBuster, a honeypot service that mimes NetBus."
    },
    {
        "name": "nexpose-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against a Nexpose vulnerability scanner using the API 1.1."
    },
    {
        "name": "nfs-ls",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to get useful information about files from NFS exports. The output is intended to resemble the output of <code>ls</code>."
    },
    {
        "name": "nfs-showmount",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Shows NFS exports, like the <code>showmount -e</code> command."
    },
    {
        "name": "nfs-statfs",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves disk space statistics and information from a remote NFS share. The output is intended to resemble the output of <code>df</code>."
    },
    {
        "name": "nje-node-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "z/OS JES Network Job Entry (NJE) target node name brute force."
    },
    {
        "name": "nje-pass-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "z/OS JES Network Job Entry (NJE) 'I record' password brute forcer."
    },
    {
        "name": "nntp-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote NNTP services with NTLM authentication enabled."
    },
    {
        "name": "nping-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against an Nping Echo service."
    },
    {
        "name": "nrpe-enum",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Queries Nagios Remote Plugin Executor (NRPE) daemons to obtain information such as load averages, process counts, logged in user information, etc."
    },
    {
        "name": "ntp-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Gets the time and configuration variables from an NTP server. We send two requests: a time request and a \"read variables\" (opcode 2) control message. "
    },
    {
        "name": "ntp-monlist",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Script NSE oficial do Nmap da categoria discovery."
    },
    {
        "name": "omp2-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the OpenVAS manager using OMPv2."
    },
    {
        "name": "omp2-enum-targets",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to retrieve the list of target systems and networks from an OpenVAS Manager server."
    },
    {
        "name": "omron-info",
        "categories": [
            "discovery",
            "version"
        ],
        "desc": "This NSE script is used to send a FINS packet to a remote device. The script will send a Controller Data Read Command and once a response is received,"
    },
    {
        "name": "openflow-info",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Queries OpenFlow controllers for information. Newer versions of the OpenFlow protocol (1.3 and greater) will return a list of all protocol versions su"
    },
    {
        "name": "openlookup-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Parses and displays the banner information of an OpenLookup (network key-value store) server."
    },
    {
        "name": "openvas-otp-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1.0 protocol."
    },
    {
        "name": "openwebnet-discovery",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "OpenWebNet is a communications protocol developed by Bticino since 2000. Retrieves device identifying information and number of connected devices."
    },
    {
        "name": "oracle-brute-stealth",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's O5LOGIN authentication scheme. The vulnerability exists in Oracle 11g R1/R2 and allow"
    },
    {
        "name": "oracle-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against Oracle servers."
    },
    {
        "name": "oracle-enum-users",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Attempts to enumerate valid Oracle user names against unpatched Oracle 11g servers (this bug was fixed in Oracle's October 2009 Critical Patch Update)"
    },
    {
        "name": "oracle-sid-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Guesses Oracle instance/SID names against the TNS-listener."
    },
    {
        "name": "oracle-tns-version",
        "categories": [
            "safe",
            "version"
        ],
        "desc": "Decodes the VSNNUM version number from an Oracle TNS listener."
    },
    {
        "name": "ovs-agent-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the version of an Oracle Virtual Server Agent by fingerprinting responses to an HTTP GET request and an XML-RPC method call."
    },
    {
        "name": "p2p-conficker",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Checks if a host is infected with Conficker.C or higher, based on Conficker's peer to peer communication."
    },
    {
        "name": "path-mtu",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Performs simple Path MTU Discovery to target hosts."
    },
    {
        "name": "pcanywhere-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the pcAnywhere remote access protocol."
    },
    {
        "name": "pcworx-info",
        "categories": [
            "discovery"
        ],
        "desc": "This NSE script will query and parse pcworx protocol to a remote PLC. The script will send a initial request packets and once a response is received, "
    },
    {
        "name": "pgsql-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs password guessing against PostgreSQL."
    },
    {
        "name": "pjl-ready-message",
        "categories": [
            "intrusive"
        ],
        "desc": "Retrieves or sets the ready message on printers that support the Printer Job Language. This includes most PostScript printers that listen on port 9100"
    },
    {
        "name": "pop3-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Tries to log into a POP3 account by guessing usernames and passwords."
    },
    {
        "name": "pop3-capabilities",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves POP3 email server capabilities."
    },
    {
        "name": "pop3-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote POP3 services with NTLM authentication enabled."
    },
    {
        "name": "port-states",
        "categories": [
            "safe"
        ],
        "desc": "Prints a list of ports found in each state."
    },
    {
        "name": "pptp-version",
        "categories": [
            "version"
        ],
        "desc": "Attempts to extract system information from the point-to-point tunneling protocol (PPTP) service."
    },
    {
        "name": "puppet-naivesigning",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Detects if naive signing is enabled on a Puppet server. This enables attackers to create any Certificate Signing Request and have it signed, allowing "
    },
    {
        "name": "qconn-exec",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Attempts to identify whether a listening QNX QCONN daemon allows unauthenticated users to execute arbitrary operating system commands."
    },
    {
        "name": "qscan",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Repeatedly probe open and/or closed ports on a host to obtain a series of round-trip time values for each port. These values are used to group collect"
    },
    {
        "name": "quake1-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Extracts information from Quake game servers and other game servers which use the same protocol."
    },
    {
        "name": "quake3-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Extracts information from a Quake3 game server and other games which use the same protocol."
    },
    {
        "name": "quake3-master-getservers",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Queries Quake3-style master servers for game servers (many games other than Quake 3 use this same protocol)."
    },
    {
        "name": "rdp-enum-encryption",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Enumera tipos de criptografia suportados pelo serviço RDP (CredSSP, TLS, RDP nativo)."
    },
    {
        "name": "rdp-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote RDP services with CredSSP (NLA) authentication enabled."
    },
    {
        "name": "rdp-vuln-ms12-020",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Verifica vulnerabilidade crítica de DoS/RCE no serviço de Área de Trabalho Remota (RDP)."
    },
    {
        "name": "realvnc-auth-bypass",
        "categories": [
            "auth",
            "safe",
            "vuln"
        ],
        "desc": "Checks if a VNC server is vulnerable to the RealVNC authentication bypass (CVE-2006-2369)."
    },
    {
        "name": "redis-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force passwords auditing against a Redis key-value store."
    },
    {
        "name": "redis-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information (such as version number and architecture) from a Redis key-value store."
    },
    {
        "name": "resolveall",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "NOTE: This script has been replaced by the <code>--resolve-all</code> command-line option in Nmap 7.70"
    },
    {
        "name": "reverse-index",
        "categories": [
            "safe"
        ],
        "desc": "Creates a reverse index at the end of scan output showing which hosts run a particular service. This is in addition to Nmap's normal output listing th"
    },
    {
        "name": "rexec-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the classic UNIX rexec (remote exec) service."
    },
    {
        "name": "rfc868-time",
        "categories": [
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Retrieves the day and time from the Time service."
    },
    {
        "name": "riak-http-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves information (such as node name and architecture) from a Basho Riak distributed database using the HTTP protocol."
    },
    {
        "name": "rlogin-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the classic UNIX rlogin (remote login) service. This script must be run in privileged mode on UNIX beca"
    },
    {
        "name": "rmi-dumpregistry",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Connects to a remote RMI registry and attempts to dump all of its objects."
    },
    {
        "name": "rmi-vuln-classloader",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Tests whether Java rmiregistry allows class loading. The default configuration of rmiregistry allows loading classes from remote URLs, which can lead "
    },
    {
        "name": "rpc-grind",
        "categories": [
            "version"
        ],
        "desc": "Fingerprints the target RPC port to extract the target service, RPC number and version."
    },
    {
        "name": "rpcap-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the WinPcap Remote Capture Daemon (rpcap)."
    },
    {
        "name": "rpcap-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Connects to the rpcap service (provides remote sniffing capabilities through WinPcap) and retrieves interface information. The service can either be s"
    },
    {
        "name": "rpcinfo",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Connects to portmapper and fetches a list of all registered programs. It then prints out a table including (for each program) the RPC program number, "
    },
    {
        "name": "rsa-vuln-roca",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detects RSA keys vulnerable to Return Of Coppersmith Attack (ROCA) factorization."
    },
    {
        "name": "rsync-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the rsync remote file syncing protocol."
    },
    {
        "name": "rsync-list-modules",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Lists modules available for rsync (remote file sync) synchronization."
    },
    {
        "name": "rtsp-methods",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Determines which methods are supported by the RTSP (real time streaming protocol) server."
    },
    {
        "name": "rtsp-url-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Testa URLs e canais de streaming RTSP comuns em câmeras IP (/live, /h264, /ch0_0)."
    },
    {
        "name": "rusers",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Connects to rusersd RPC service and retrieves a list of logged-in users."
    },
    {
        "name": "s7-info",
        "categories": [
            "discovery",
            "version"
        ],
        "desc": "Enumerates Siemens S7 PLC Devices and collects their device information. This script is based off PLCScan that was developed by Positive Research and "
    },
    {
        "name": "samba-vuln-cve-2012-1182",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks if target machines are vulnerable to the Samba heap overflow vulnerability CVE-2012-1182."
    },
    {
        "name": "servicetags",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to extract system information (OS, hardware, etc.) from the Sun Service Tags service agent (UDP port 6481)."
    },
    {
        "name": "shodan-api",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Queries Shodan API for given targets and produces similar output to a -sV nmap scan. The ShodanAPI key can be set with the 'apikey' script argument, o"
    },
    {
        "name": "sip-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against Session Initiation Protocol (SIP) accounts. This protocol is most commonly associated with VoIP session"
    },
    {
        "name": "sip-call-spoof",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Spoofs a call to a SIP phone and detects the action taken by the target (busy, declined, hung up, etc.)"
    },
    {
        "name": "sip-enum-users",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Enumerates a SIP server's valid extensions (users)."
    },
    {
        "name": "sip-methods",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Enumerates a SIP Server's allowed methods (INVITE, OPTIONS, SUBSCRIBE, etc.)"
    },
    {
        "name": "skypev2-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the Skype version 2 service."
    },
    {
        "name": "smb-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Script NSE oficial do Nmap da categoria brute."
    },
    {
        "name": "smb-double-pulsar-backdoor",
        "categories": [
            "malware",
            "safe",
            "vuln"
        ],
        "desc": "Checks if the target machine is running the Double Pulsar SMB backdoor."
    },
    {
        "name": "smb-enum-domains",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Attempts to enumerate domains on a system, along with their policies. This generally requires credentials, except against Windows 2000. In addition to"
    },
    {
        "name": "smb-enum-groups",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Obtains a list of groups from the remote Windows system, as well as a list of the group's users. This works similarly to <code>enum.exe</code> with th"
    },
    {
        "name": "smb-enum-processes",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Pulls a list of processes from the remote server over SMB. This will determine all running processes, their process IDs, and their parent processes. I"
    },
    {
        "name": "smb-enum-services",
        "categories": [
            "discovery",
            "intrusive",
            "safe"
        ],
        "desc": "Retrieves the list of services running on a remote Windows system. Each service attribute contains service name, display name and service status of ea"
    },
    {
        "name": "smb-enum-sessions",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Script NSE oficial do Nmap da categoria discovery."
    },
    {
        "name": "smb-enum-shares",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumera pastas compartilhadas na rede e permissões anônimas de leitura/escrita."
    },
    {
        "name": "smb-enum-users",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Enumera contas de usuários locais ou de domínio via protocolo SAM/LSA."
    },
    {
        "name": "smb-flood",
        "categories": [
            "dos",
            "intrusive"
        ],
        "desc": "Exhausts a remote SMB server's connection limit by by opening as many connections as we can. Most implementations of SMB have a hard global limit of 1"
    },
    {
        "name": "smb-ls",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to retrieve useful information about files shared on SMB volumes. The output is intended to resemble the output of the UNIX <code>ls</code> c"
    },
    {
        "name": "smb-mbenum",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Queries information managed by the Windows Master Browser."
    },
    {
        "name": "smb-os-discovery",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Descobre versão exata do Windows/Samba, nome do computador e domínio de rede."
    },
    {
        "name": "smb-print-text",
        "categories": [
            "intrusive"
        ],
        "desc": "Attempts to print text on a shared printer by calling Print Spooler Service RPC functions."
    },
    {
        "name": "smb-protocols",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Lista dialetos SMB suportados (alerta se SMBv1 obsoleto estiver ativo)."
    },
    {
        "name": "smb-psexec",
        "categories": [
            "intrusive"
        ],
        "desc": "Script NSE oficial do Nmap da categoria intrusive."
    },
    {
        "name": "smb-security-mode",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Verifica se a assinatura digital SMB está habilitada ou é obrigatória."
    },
    {
        "name": "smb-server-stats",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Attempts to grab the server's statistics over SMB and MSRPC, which uses TCP ports 445 or 139."
    },
    {
        "name": "smb-system-info",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Pulls back information about the remote system from the registry. Getting all of the information requires an administrative account, although a user a"
    },
    {
        "name": "smb-vuln-conficker",
        "categories": [
            "dos",
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detects Microsoft Windows systems infected by the Conficker worm. This check is dangerous and it may crash systems."
    },
    {
        "name": "smb-vuln-cve-2017-7494",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Script NSE oficial do Nmap da categoria intrusive."
    },
    {
        "name": "smb-vuln-cve2009-3103",
        "categories": [
            "dos",
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detects Microsoft Windows systems vulnerable to denial of service (CVE-2009-3103). This script will crash the service if it is vulnerable."
    },
    {
        "name": "smb-vuln-ms06-025",
        "categories": [
            "dos",
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detects Microsoft Windows systems with Ras RPC service vulnerable to MS06-025."
    },
    {
        "name": "smb-vuln-ms07-029",
        "categories": [
            "dos",
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detects Microsoft Windows systems with Dns Server RPC vulnerable to MS07-029."
    },
    {
        "name": "smb-vuln-ms08-067",
        "categories": [
            "dos",
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Detecta falha crítica histórica de execução remota de código no serviço SMB do Windows."
    },
    {
        "name": "smb-vuln-ms10-054",
        "categories": [
            "dos",
            "intrusive",
            "vuln"
        ],
        "desc": "Tests whether target machines are vulnerable to the ms10-054 SMB remote memory corruption vulnerability."
    },
    {
        "name": "smb-vuln-ms10-061",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Tests whether target machines are vulnerable to ms10-061 Printer Spooler impersonation vulnerability."
    },
    {
        "name": "smb-vuln-ms17-010",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Audita vulnerabilidade crítica EternalBlue / WannaCry no Windows SMBv1 (MS17-010 / RCE)."
    },
    {
        "name": "smb-vuln-regsvc-dos",
        "categories": [
            "dos",
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Checks if a Microsoft Windows 2000 system is vulnerable to a crash in regsvc caused by a null pointer dereference. This check will crash the service i"
    },
    {
        "name": "smb-vuln-webexec",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks whether the WebExService is installed and allows us to run code."
    },
    {
        "name": "smb-webexec-exploit",
        "categories": [
            "exploit",
            "intrusive"
        ],
        "desc": "Attempts to run a command via WebExService, using the WebExec vulnerability. Given a Windows account (local or domain), this will start an arbitrary e"
    },
    {
        "name": "smb2-capabilities",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Attempts to list the supported capabilities in a SMBv2 server for each enabled dialect."
    },
    {
        "name": "smb2-security-mode",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Avalia o modo de segurança e obrigatoriedade de assinatura do protocolo SMBv2."
    },
    {
        "name": "smb2-time",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to obtain the current system date and the start date of a SMB2 server."
    },
    {
        "name": "smb2-vuln-uptime",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Attempts to detect missing patches in Windows systems by checking the uptime returned during the SMB2 protocol negotiation."
    },
    {
        "name": "smtp-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication."
    },
    {
        "name": "smtp-commands",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to use EHLO and HELP to gather the Extended commands supported by an SMTP server."
    },
    {
        "name": "smtp-enum-users",
        "categories": [
            "auth",
            "external",
            "intrusive"
        ],
        "desc": "Attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user ac"
    },
    {
        "name": "smtp-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote SMTP services with NTLM authentication enabled."
    },
    {
        "name": "smtp-open-relay",
        "categories": [
            "discovery",
            "external",
            "intrusive"
        ],
        "desc": "Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal of this script is to tell if a SMTP server is vulnerable to mail"
    },
    {
        "name": "smtp-strangeport",
        "categories": [
            "malware",
            "safe"
        ],
        "desc": "Checks if SMTP is running on a non-standard port."
    },
    {
        "name": "smtp-vuln-cve2010-4344",
        "categories": [
            "exploit",
            "intrusive",
            "vuln"
        ],
        "desc": "Checks for and/or exploits a heap overflow within versions of Exim prior to version 4.69 (CVE-2010-4344) and a privilege escalation vulnerability in E"
    },
    {
        "name": "smtp-vuln-cve2011-1720",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks for a memory corruption in the Postfix SMTP server when it uses Cyrus SASL library authentication mechanisms (CVE-2011-1720). This vulnerabilit"
    },
    {
        "name": "smtp-vuln-cve2011-1764",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Checks for a format string vulnerability in the Exim SMTP server (version 4.70 through 4.75) with DomainKeys Identified Mail (DKIM) support (CVE-2011-"
    },
    {
        "name": "sniffer-detect",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Checks if a target on a local Ethernet has its network card in promiscuous mode."
    },
    {
        "name": "snmp-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Attempts to find an SNMP community string by brute force guessing."
    },
    {
        "name": "snmp-hh3c-logins",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to enumerate Huawei / HP/H3C Locally Defined Users through the hh3c-user.mib OID"
    },
    {
        "name": "snmp-info",
        "categories": [
            "default",
            "safe",
            "version"
        ],
        "desc": "Coleta informações de gerenciamento SNMP usando a community padrão public."
    },
    {
        "name": "snmp-interfaces",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to enumerate network interfaces through SNMP."
    },
    {
        "name": "snmp-ios-config",
        "categories": [
            "intrusive"
        ],
        "desc": "Attempts to downloads Cisco router IOS configuration files using SNMP RW (v1) and display or save them."
    },
    {
        "name": "snmp-netstat",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to query SNMP for a netstat like output. The script can be used to identify and automatically add new targets to the scan by supplying the ne"
    },
    {
        "name": "snmp-processes",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to enumerate running processes through SNMP."
    },
    {
        "name": "snmp-sysdescr",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Extrai a descrição do sistema, SO e hardware via MIB-II SNMP."
    },
    {
        "name": "snmp-win32-services",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to enumerate Windows services through SNMP."
    },
    {
        "name": "snmp-win32-shares",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to enumerate Windows Shares through SNMP."
    },
    {
        "name": "snmp-win32-software",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Attempts to enumerate installed software through SNMP."
    },
    {
        "name": "snmp-win32-users",
        "categories": [
            "auth",
            "default",
            "safe"
        ],
        "desc": "Attempts to enumerate Windows user accounts through SNMP"
    },
    {
        "name": "socks-auth-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Determines the supported authentication mechanisms of a remote SOCKS proxy server. Starting with SOCKS version 5 socks servers may support authenticat"
    },
    {
        "name": "socks-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against SOCKS 5 proxy servers."
    },
    {
        "name": "socks-open-proxy",
        "categories": [
            "default",
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Checks if an open socks proxy is running on the target."
    },
    {
        "name": "ssh-auth-methods",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "Enumera métodos de autenticação aceitos pelo servidor SSH (password, publickey)."
    },
    {
        "name": "ssh-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute-force password guessing against ssh servers."
    },
    {
        "name": "ssh-hostkey",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Extrai a chave pública do host SSH (tipo de chave e fingerprint RSA/ECDSA/ED25519)."
    },
    {
        "name": "ssh-publickey-acceptance",
        "categories": [
            "auth",
            "intrusive"
        ],
        "desc": "This script takes a table of paths to private keys, passphrases, and usernames and checks each pair to see if the target ssh server accepts them for p"
    },
    {
        "name": "ssh-run",
        "categories": [
            "intrusive"
        ],
        "desc": "Runs remote command on ssh server and returns command output."
    },
    {
        "name": "ssh2-enum-algos",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Reports the number of algorithms (for encryption, compression, etc.) that the target SSH2 server offers. If verbosity is set, the offered algorithms a"
    },
    {
        "name": "sshv1",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Verifica se o servidor SSH suporta a versão 1 do protocolo, obsoleta e insegura."
    },
    {
        "name": "ssl-ccs-injection",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detecta injeção de ChangeCipherSpec no OpenSSL (CVE-2014-0224)."
    },
    {
        "name": "ssl-cert-intaddr",
        "categories": [
            "discovery",
            "safe",
            "vuln"
        ],
        "desc": "Reports any private (RFC1918) IPv4 addresses found in the various fields of an SSL service's certificate. These will only be reported if the target ad"
    },
    {
        "name": "ssl-cert",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Extrai dados do certificado SSL/TLS (Common Name, SANs, emissor e expiração)."
    },
    {
        "name": "ssl-date",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Verifica data e sincronismo de relógio via resposta do handshake TLS."
    },
    {
        "name": "ssl-dh-params",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services."
    },
    {
        "name": "ssl-enum-ciphers",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumera cifras SSL/TLS com notas de A a F e alerta cifras fracas ou obsoletas."
    },
    {
        "name": "ssl-heartbleed",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Verifica suscetibilidade à falha crítica Heartbleed no OpenSSL (CVE-2014-0160)."
    },
    {
        "name": "ssl-known-key",
        "categories": [
            "default",
            "discovery",
            "safe",
            "vuln"
        ],
        "desc": "Checks whether the SSL certificate used by a host has a fingerprint that matches an included database of problematic keys."
    },
    {
        "name": "ssl-poodle",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detecta vulnerabilidade ao ataque POODLE em SSLv3 (CVE-2014-3566)."
    },
    {
        "name": "sslv2-drown",
        "categories": [
            "intrusive",
            "vuln"
        ],
        "desc": "Determines whether the server supports SSLv2, what ciphers it supports and tests for CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 (DROWN)"
    },
    {
        "name": "sslv2",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Determines whether the server supports obsolete and less secure SSLv2, and discovers which ciphers it supports."
    },
    {
        "name": "sstp-discover",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Check if the Secure Socket Tunneling Protocol is supported. This is accomplished by trying to establish the HTTPS layer which is used to carry SSTP tr"
    },
    {
        "name": "stun-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves the external IP address of a NAT:ed host using the STUN protocol."
    },
    {
        "name": "stun-version",
        "categories": [
            "version"
        ],
        "desc": "Sends a binding request to the server and attempts to extract version information from the response, if the server attribute is present."
    },
    {
        "name": "stuxnet-detect",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Detects whether a host is infected with the Stuxnet worm (http://en.wikipedia.org/wiki/Stuxnet)."
    },
    {
        "name": "supermicro-ipmi-conf",
        "categories": [
            "exploit",
            "vuln"
        ],
        "desc": "Attempts to download an unprotected configuration file containing plain-text user credentials in vulnerable Supermicro Onboard IPMI controllers."
    },
    {
        "name": "svn-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against Subversion source code control servers."
    },
    {
        "name": "targets-asn",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Produces a list of IP prefixes for a given routing AS number (ASN)."
    },
    {
        "name": "targets-ipv6-map4to6",
        "categories": [
            "discovery"
        ],
        "desc": "This script runs in the pre-scanning phase to map IPv4 addresses onto IPv6 networks and add them to the scan queue."
    },
    {
        "name": "targets-ipv6-multicast-echo",
        "categories": [
            "broadcast",
            "discovery"
        ],
        "desc": "Sends an ICMPv6 echo request packet to the all-nodes link-local multicast address (<code>ff02::1</code>) to discover responsive hosts on a LAN without"
    },
    {
        "name": "targets-ipv6-multicast-invalid-dst",
        "categories": [
            "broadcast",
            "discovery"
        ],
        "desc": "Sends an ICMPv6 packet with an invalid extension header to the all-nodes link-local multicast address (<code>ff02::1</code>) to discover (some) availa"
    },
    {
        "name": "targets-ipv6-multicast-mld",
        "categories": [
            "broadcast",
            "discovery"
        ],
        "desc": "Attempts to discover available IPv6 hosts on the LAN by sending an MLD (multicast listener discovery) query to the link-local multicast address (ff02:"
    },
    {
        "name": "targets-ipv6-multicast-slaac",
        "categories": [
            "broadcast",
            "discovery"
        ],
        "desc": "Performs IPv6 host discovery by triggering stateless address auto-configuration (SLAAC)."
    },
    {
        "name": "targets-ipv6-wordlist",
        "categories": [
            "discovery"
        ],
        "desc": "Adds IPv6 addresses to the scan queue using a wordlist of hexadecimal \"words\" that form addresses in a given subnet."
    },
    {
        "name": "targets-sniffer",
        "categories": [
            "broadcast",
            "discovery",
            "safe"
        ],
        "desc": "Sniffs the local network for a configurable amount of time (10 seconds by default) and prints discovered addresses. If the <code>newtargets</code> scr"
    },
    {
        "name": "targets-traceroute",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Inserts traceroute hops into the Nmap scanning queue. It only functions if Nmap's <code>--traceroute</code> option is used and the <code>newtargets</c"
    },
    {
        "name": "targets-xml",
        "categories": [
            "safe"
        ],
        "desc": "Loads addresses from an Nmap XML output file for scanning."
    },
    {
        "name": "teamspeak2-version",
        "categories": [
            "version"
        ],
        "desc": "Detects the TeamSpeak 2 voice communication server and attempts to determine version and configuration information."
    },
    {
        "name": "telnet-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute-force password auditing against telnet servers."
    },
    {
        "name": "telnet-encryption",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Determines whether the encryption option is supported on a remote telnet server. Some systems (including FreeBSD and the krb5 telnetd available in man"
    },
    {
        "name": "telnet-ntlm-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "This script enumerates information from remote Microsoft Telnet services with NTLM authentication enabled."
    },
    {
        "name": "tftp-enum",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Enumerates TFTP (trivial file transfer protocol) filenames by testing for a list of common ones."
    },
    {
        "name": "tftp-version",
        "categories": [
            "default",
            "safe",
            "version"
        ],
        "desc": "Obtains information (such as vendor and device type where available) from a TFTP service by requesting a random filename. Software vendor information "
    },
    {
        "name": "tls-alpn",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Enumerates a TLS server's supported application-layer protocols using the ALPN protocol."
    },
    {
        "name": "tls-nextprotoneg",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Enumerates a TLS server's supported protocols by using the next protocol negotiation extension."
    },
    {
        "name": "tls-ticketbleed",
        "categories": [
            "safe",
            "vuln"
        ],
        "desc": "Detects whether a server is vulnerable to the F5 Ticketbleed bug (CVE-2016-9244)."
    },
    {
        "name": "tn3270-screen",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Connects to a tn3270 'server' and returns the screen."
    },
    {
        "name": "tor-consensus-checker",
        "categories": [
            "external",
            "safe"
        ],
        "desc": "Checks if a target is a known Tor node."
    },
    {
        "name": "traceroute-geolocation",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Lists the geographic locations of each hop in a traceroute and optionally saves the results to a KML file, plottable on Google earth and maps."
    },
    {
        "name": "tso-brute",
        "categories": [
            "intrusive"
        ],
        "desc": "TSO account brute forcer."
    },
    {
        "name": "tso-enum",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "TSO User ID enumerator for IBM mainframes (z/OS). The TSO logon panel tells you when a user ID is valid or invalid with the message: <code>IKJ56420I U"
    },
    {
        "name": "ubiquiti-discovery",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Extracts information from Ubiquiti networking devices."
    },
    {
        "name": "unittest",
        "categories": [
            "safe"
        ],
        "desc": "Runs unit tests on all NSE libraries."
    },
    {
        "name": "unusual-port",
        "categories": [
            "safe"
        ],
        "desc": "Compares the detected service on a port against the expected service for that port number (e.g. ssh on 22, http on 80) and reports deviations. The scr"
    },
    {
        "name": "upnp-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Consulta serviços UPnP/SSDP para extrair fabricante, modelo e número de série de Smart TVs/Roteadores."
    },
    {
        "name": "uptime-agent-info",
        "categories": [
            "default",
            "safe"
        ],
        "desc": "Gets system information from an Idera Uptime Infrastructure Monitor agent."
    },
    {
        "name": "url-snarf",
        "categories": [
            "safe"
        ],
        "desc": "Sniffs an interface for HTTP traffic and dumps any URLs, and their originating IP address. Script output differs from other script as URLs are written"
    },
    {
        "name": "ventrilo-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Detects the Ventrilo voice communication server service versions 2.1.2 and above and tries to determine version and configuration information. Some of"
    },
    {
        "name": "versant-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Extracts information, including file paths, version and database names from a Versant object database."
    },
    {
        "name": "vmauthd-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against the VMWare Authentication Daemon (vmware-authd)."
    },
    {
        "name": "vmware-version",
        "categories": [
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Queries VMware server (vCenter, ESX, ESXi) SOAP API to extract the version information."
    },
    {
        "name": "vnc-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against VNC servers."
    },
    {
        "name": "vnc-info",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Obtém informações do protocolo e profundidade de cores do servidor VNC."
    },
    {
        "name": "vnc-title",
        "categories": [
            "discovery",
            "intrusive"
        ],
        "desc": "Extrai o título e resolução da tela compartilhada no servidor VNC."
    },
    {
        "name": "voldemort-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves cluster and store information from the Voldemort distributed key-value store using the Voldemort Native Protocol."
    },
    {
        "name": "vtam-enum",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Many mainframes use VTAM screens to connect to various applications (CICS, IMS, TSO, and many more)."
    },
    {
        "name": "vulners",
        "categories": [
            "external",
            "safe",
            "vuln"
        ],
        "desc": "For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores."
    },
    {
        "name": "vuze-dht-info",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Retrieves some basic information, including protocol version from a Vuze filesharing node."
    },
    {
        "name": "wdb-version",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version",
            "vuln"
        ],
        "desc": "Detects vulnerabilities and gathers information (such as version numbers and hardware support) from VxWorks Wind DeBug agents."
    },
    {
        "name": "weblogic-t3-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Script NSE oficial do Nmap da categoria default."
    },
    {
        "name": "whois-domain",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Attempts to retrieve information about the domain name of the target"
    },
    {
        "name": "whois-ip",
        "categories": [
            "discovery",
            "external",
            "safe"
        ],
        "desc": "Script NSE oficial do Nmap da categoria discovery."
    },
    {
        "name": "wsdd-discover",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Retrieves and displays information from devices supporting the Web Services Dynamic Discovery (WS-Discovery) protocol. It also attempts to locate any "
    },
    {
        "name": "x11-access",
        "categories": [
            "auth",
            "default",
            "safe"
        ],
        "desc": "Checks if you're allowed to connect to the X server."
    },
    {
        "name": "xdmcp-discover",
        "categories": [
            "discovery",
            "safe"
        ],
        "desc": "Requests an XDMCP (X display manager control protocol) session and lists supported authentication and authorization mechanisms."
    },
    {
        "name": "xmlrpc-methods",
        "categories": [
            "default",
            "discovery",
            "safe"
        ],
        "desc": "Performs XMLRPC Introspection via the system.listMethods method."
    },
    {
        "name": "xmpp-brute",
        "categories": [
            "brute",
            "intrusive"
        ],
        "desc": "Performs brute force password auditing against XMPP (Jabber) instant messaging servers."
    },
    {
        "name": "xmpp-info",
        "categories": [
            "default",
            "discovery",
            "safe",
            "version"
        ],
        "desc": "Connects to XMPP server (port 5222) and collects server information such as: supported auth mechanisms, compression methods, whether TLS is supported "
    }
]

def get_all_scripts() -> List[dict]:
    return NSE_SCRIPTS_CATALOG


def get_presets() -> Dict[str, dict]:
    return NSE_PRESETS


def search_scripts(query: str = "", category: str = "") -> List[dict]:
    q = query.strip().lower()
    cat = category.strip().lower()
    results = []
    for s in NSE_SCRIPTS_CATALOG:
        if cat and cat != "todas" and cat not in s["categories"]:
            continue
        if q:
            name_match = q in s["name"].lower()
            cat_match = any(q in c.lower() for c in s["categories"])
            desc_match = q in s["desc"].lower()
            if not (name_match or cat_match or desc_match):
                continue
        results.append(s)
    return results


def parse_nse_script_output(text: str) -> List[dict]:
    """
    Extrai blocos de saída de scripts NSE do texto cru do Nmap.
    Formato típico:
      443/tcp open  https
      | ssl-enum-ciphers:
      |   TLSv1.2:
      |_    Least strength: A
    Ou:
      Host script results:
      | smb2-security-mode:
      |_  Message signing enabled
    """
    results = []
    current_port = None
    current_script = None
    current_output = []

    lines = text.splitlines()
    for line in lines:
        port_match = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$", line)
        if port_match:
            if current_script:
                results.append(_create_script_result(current_script, current_port, current_output))
                current_script = None
                current_output = []
            current_port = f"{port_match.group(1)}/{port_match.group(2)}"
            continue

        if line.strip().startswith("Host script results:"):
            if current_script:
                results.append(_create_script_result(current_script, current_port, current_output))
                current_script = None
                current_output = []
            current_port = "Host"
            continue

        if line.startswith("| ") or line.startswith("|_") or line.startswith("|"):
            raw_content = line[2:] if line.startswith("| ") or line.startswith("|_") else line[1:]
            header_match = re.match(r"^([a-zA-Z0-9_\-\.]+):\s*(.*)$", raw_content)
            # Detect new script start if not indented
            if header_match and not raw_content.startswith("  "):
                if current_script:
                    results.append(_create_script_result(current_script, current_port, current_output))
                current_script = header_match.group(1).strip()
                first_val = header_match.group(2).strip()
                current_output = [first_val] if first_val else []
            else:
                if current_script:
                    current_output.append(raw_content)
        else:
            if current_script and not line.strip().startswith("|"):
                results.append(_create_script_result(current_script, current_port, current_output))
                current_script = None
                current_output = []

    if current_script:
        results.append(_create_script_result(current_script, current_port, current_output))

    return results


def _create_script_result(name: str, port: Optional[str], output_lines: List[str]) -> dict:
    body = "\n".join(output_lines).strip()
    lower = body.lower()
    
    # Avaliação automática de severidade do achado
    is_vuln = any(kw in lower for kw in ["vulnerable", "state: vulnerable", "cve-", "exploit", "critical", "high severity"])
    is_warn = any(kw in lower for kw in ["warning", "insecure", "weak", "grade: c", "grade: d", "grade: f", "deprecated"])
    
    if is_vuln:
        status = "VULN"
        status_label = "🚨 VULNERÁVEL"
        color = "#ef4444"
    elif is_warn:
        status = "WARN"
        status_label = "⚠️ ALERTA"
        color = "#f59e0b"
    else:
        status = "INFO"
        status_label = "ℹ️ INFORMAÇÃO"
        color = "#38bdf8"
        
    # Extração de CVEs caso existam no output
    cves = sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", body, re.IGNORECASE))))

    return {
        "name": name,
        "port": port or "Host",
        "output": body,
        "status": status,
        "status_label": status_label,
        "color": color,
        "cves": cves,
    }
