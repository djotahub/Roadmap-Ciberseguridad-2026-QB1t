# 🛡️Roadmap Ciberseguridad 2026 byQB1t
Guía paso a paso para aprender ciberseguridad en 2026. Compilado exhaustivo de recursos 100% gratuitos: Fundamentos de sistemas, redes, metodología Red Team (Ataque) y Blue Team (SOC/Defensa). De 0 a Junior.

_Este repositorio es una ruta de aprendizaje técnica, extensiva y gratuita para dominar la ciberseguridad desde los cimientos hasta el nivel Junior._

## 📌 Tabla de Contenidos
1. [Fase 1: Fundamentos  (Sistemas y Redes)]
2. [Fase 2: Blue Team (DFIR, SOC y Caza de Amenazas)]
3. [Fase 3: Red Team (Auditoría de Infraestructura y Web)]
5. [Biblioteca de Enlaces y Recursos Gratuitos]

## 📊 Resumen del Camino


| Nivel         | Objetivo                                           | Tiempo Estimado |
| :------------ | :------------------------------------------------- | :-------------- |
| **Cimientos** | Dominio de la Terminal, Protocolos y Scripting     | 3-4 meses       |
| **Ataque**    | Explotación de vulnerabilidades y Active Directory | 4-6 meses       |
| **Defensa**   | Análisis Forense, Logs y Respuesta a Incidentes    | 4-6 meses       |
# 🧱 Fase 1: Fundamentos Técnicos

Nadie puede hackear lo que no entiende cómo funciona. En esta etapa el objetivo es entender el sistema operativo y las comunicaciones.

## 1. Linux para Ciberseguridad
No se trata de usar Ubuntu, se trata de entender el sistema:
* **Estructura del Sistema:** Entender `/etc`, `/bin`, `/proc`, y `/var`.
* **Permisos Críticos:** Explicación técnica de SUID, GUID y Sticky Bit (Vectores comunes de escalada).
* **Gestión de Procesos:** Uso de `ps`, `top`, `kill` y cómo leer señales del sistema.
* **Recurso:** [HTB Academy - Linux Fundamentals](https://academy.hackthebox.com/module/details/18)

## 2. Redes (Networking)
El 90% de los problemas en seguridad son problemas de redes mal entendidas.
* **Modelo OSI vs TCP/IP:** No solo los nombres, sino qué pasa en cada capa.

* **Protocolos Críticos:**
    * **ARP:** Cómo funciona la resolución de MACs y por qué es vulnerable (ARP Spoofing).
    * **DNS:** Tipos de registros (A, MX, TXT) y transferencias de zona.
    * **TCP/UDP:** Handshake de 3 vías, flags (SYN, ACK, FIN, RST).
* **Recurso:** [Cisco Skills For All: Networking Basics](https://skillsforall.com/course/networking-basics)

## 3. Windows Internals
Entender por qué Windows es el objetivo principal en empresas.
* **LSASS y SAM:** Dónde se guardan las credenciales y cómo se protegen.
* **Active Directory Conceptos:** ¿Qué es un Dominio, un DC y un Bosque?
* **Recurso:** [Microsoft Learn: Windows Internals](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)


# 🔵 Fase  2: Blue Team (Defensa, SOC y Respuesta)

Aquí aprendés a detectar y frenar ataques en tiempo real.

## 1. Operaciones de SOC (Seguridad Operativa)
Un analista SOC monitorea alertas y decide si son ataques reales o falsos positivos.
* **Teoría:** [Cisco: Junior Cybersecurity Analyst](https://skillsforall.com/learning-path/cybersecurity-analyst) (Path completo).
* **Análisis de Logs:** Identificación de eventos críticos en Windows (Event IDs) y Linux (Syslog).

## 2. Threat Hunting y Detección
No esperar a que salte la alarma, sino buscar al atacante que ya está adentro.
* **Framework MITRE ATT&CK:** Entender las tácticas y técnicas de los grupos de hackers.
* **Reglas de Detección:** Cómo se escriben reglas (Sigma/YARA) para detectar comportamientos raros.

## 3. Network Forensics (Defensa de Red)
Análisis de paquetes para identificar infecciones.

* **Teoría:** [Unit 42 Wireshark Tutorials](https://unit42.paloaltonetworks.com/tag/wireshark-tutorial/) - Material de Palo Alto Networks.
* **Práctica:** [CyberDefenders](https://cyberdefenders.org/) (Labs gratuitos de Blue Team).

## 4. Análisis de Phishing
El vector de entrada #1. 
* **Headers:** Analizar de dónde viene realmente un mail (SPF, DKIM).
* **Adjuntos:** Cómo analizar un PDF o un Office malicioso de forma segura.
* **Recurso:** [Blue Team Labs Online (BTLO)](https://blueteamlabs.online/) - Investigaciones gratuitas.

## 5. Análisis Forense de Memoria (RAM)
Cuando un atacante usa malware que no toca el disco (fileless), la RAM es la única evidencia.
* **Volatility 3:** Instalación y uso de plugins básicos (`windows.pslist`, `windows.malfind`).
* **Concepto:** Diferencia entre un proceso legítimo y uno inyectado.
* **Laboratorio:** [MemLabs](https://github.com/stuxnet999/MemLabs)


## 6. Network Forensics
* **Wireshark Avanzado:** Uso de filtros de visualización para encontrar C2 (Command & Control).
* **PCAP Analysis:** Identificación de exfiltración de datos vía DNS o ICMP.
* **Recurso:** [CyberDefenders BlueTeam CTF](https://cyberdefenders.org/)


# 🔴 FASE 2: RED TEAM (Seguridad Ofensiva)

Esta fase se centra en la metodología de ataque. No es tirar comandos, es seguir un proceso lógico para comprometer un sistema.

## 📍 1. Reconocimiento (Recon)

El éxito de un ataque depende de cuánta información tenés del objetivo. Se divide en Pasivo (sin tocar al objetivo) y Activo.

- **DNS & Subdominios:** Identificar toda la superficie expuesta.
    
    - **Estudiar:** Registros A, MX, TXT, CNAME y Transferencias de Zona (AXFR).
    
    - **Recurso:** [Hacking DNS - HackTricks](https://www.google.com/search?q=https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)
        
- **OSINT Técnico:** Fugas de información en sitios públicos.
    
    - **Estudiar:** Google Dorks, Shodan y fugas en GitHub.
        
    - **Recurso:** [Cisco Ethical Hacker: Reconnaissance](https://www.google.com/search?q=https://skillsforall.com/course/ethical-hacker) (Módulo 2).
        

## 🕵️ 2. Análisis de Vulnerabilidades y Modelado de Amenazas

Antes de atacar, hay que entender qué servicios hay y qué tan "rotos" están.

- **Escaneo de Servicios:** No es solo ver puertos, es identificar versiones y configuraciones.
    
    - **Estudiar:** Nmap avanzado (Scripts NSE, escaneo SYN vs TCP).
        
    - **Recurso:** [Nmap Network Scanning - Documentación Oficial](https://nmap.org/book/man.html)
        
- **Modelado de Amenazas:** Identificar los vectores de entrada más probables.
    
    - **Estudiar:** Framework STRIDE (qué puede fallar en el diseño).
        
    - **Recurso:** [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
        

## 🚀 3. Explotación (Exploitation)

Entrar al sistema aprovechando el fallo encontrado.

- **Explotación Web (OWASP Top 10):**
    
    - **SQL Injection:** Romper la lógica de la base de datos para sacar datos.
    
    - **XSS (Cross-Site Scripting):** Ejecutar código en el navegador de la víctima.
    
    -  **Control de Acceso (Broken Access Control):** * **IDOR:** Manipular IDs para ver datos de otros.
    -
    - **Privilege Escalation:** Pasar de usuario "viewer" a "admin" modificando la lógica de la sesión.
        
- **Vulnerabilidades de Lado del Servidor:**
    
    - **SSRF (Server-Side Request Forgery):** Obligar al servidor a atacar su propia red interna o consultar metadatos de la nube (AWS/Azure/GCP).
        
    - **Insecure Deserialization:** Ejecución de código mediante el abuso de cómo el servidor lee objetos.
        
    - **Path Traversal & LFI/RFI:** Lectura de archivos críticos del sistema operativo (`/etc/shadow`, `C:\Windows\win.ini`).
        
- **Vulnerabilidades de Inyección:** * No solo SQL, sino inyección de plantillas (**SSTI**) e inyecciones de comandos de sistema.


    - **Recurso (Obligatorio):** [PortSwigger Academy: All Labs](https://portswigger.net/web-security/all-labs) (Empezar por nivel Apprentice).


- **Explotación de Red:** Abuso de servicios mal configurados (SMB, SSH, FTP).
    
    - **Recurso:** [Exploit Database](https://www.exploit-db.com/) (Entender cómo leer y modificar un exploit).
        

## 👑 4. Post-Explotación y Escalada de Privilegios

Una vez adentro, sos un usuario sin poder. Tenés que ser Administrador (Root/System).

- **Escalada en Linux:** Abuso de binarios con permisos SUID, tareas cron mal configuradas o Kernel exploits.
    
    - **Recurso:** [Checklist Linux Privilege Escalation](https://www.google.com/search?q=https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
        
- **Escalada en Windows:** Servicios con permisos débiles, Token Manipulation o abusos de privilegios (SeImpersonate).
    
    - **Recurso:** [Checklist Windows Privilege Escalation](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/ntlm/privilege-escalation)
        

## 🏢 5. Active Directory (Hacking Corporativo)

El objetivo final en una empresa real.

- **Ataques de Identidad:** Kerberoasting, AS-REP Roasting y Pass-the-Hash.
    
- **Movimiento Lateral:** Saltar de una PC a otra hasta llegar al Domain Controller.
    
- **Recurso:** [HackTricks Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
    

---

### 📚 Bibliografía y Fuentes de Estudio

Para que el trainee no se pierda, estos son los links de referencia de toda la fase:

1. **Path Ofensivo Cisco:** [Ethical Hacker Path](https://www.google.com/search?q=https://skillsforall.com/course/ethical-hacker) (Teoría base).
    
2. **Web Hacking:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-labs) (Práctica real).
    
3. **Enciclopedia Técnica:** [HackTricks](https://book.hacktricks.xyz/) (Consultar cada vez que encuentres un servicio nuevo).
    
4. **Active Directory:** [The Doger's AD Lab](https://www.google.com/search?q=https://github.com/the-doger/Active-Directory-Lab) (Para entender la arquitectura de un lab de AD).


# 🔗 Biblioteca de Recursos Gratuitos

### 🛠️ Plataformas de Práctica (Labs)
* [DockerLabs](https://github.com/DockerLabs-ES/DockerLabs) - Máquinas locales gratuitas (Español).
* [TryHackMe](https://tryhackme.com/) - Salas gratuitas de fundamentos.
* [PortSwigger Academy](https://portswigger.net/web-security/all-labs) - La biblia del hacking web.
* [CyberDefenders](https://cyberdefenders.org/) - Práctica real de Blue Team.

### 📜 Certificaciones Gratuitas (Para el CV)
* [ISC2 Certified in Cybersecurity (CC)](https://www.isc2.org/Certifications/CC) - Registro gratis.
* [Cisco Python Essentials](https://skillsforall.com/course/python-essentials-1) - Certificado de finalización.
*  [Cisco: Ethical Hacker](https://skillsforall.com/course/ethical-hacker) - Fundamentos de seguridad ofensiva.
* [Cisco: Junior Cybersecurity Analyst](https://skillsforall.com/learning-path/cybersecurity-analyst) - El path inicial para  perfiles SOC.
* [ISC2: Certified in Cybersecurity (CC)](https://www.isc2.org/Certifications/CC) - Estándar de la industria.


### 📚 Biblias Técnicas
* [HackTricks](https://book.hacktricks.xyz/) - Referencia número 1 para Pentesting.
* [GTFOBins](https://gtfobins.github.io/) - Para escalada de privilegios en Linux.
* [LOLBAS](https://lolbas-project.github.io/) - Para escalada de privilegios en Windows.
