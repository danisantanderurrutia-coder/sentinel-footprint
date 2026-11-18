# 🛡️ Sentinel & Footprint

> **DevSecOps Web Security Auditor & Digital Footprint / Privacy Cleaner**  
> *Una plataforma modular diseñada para la auditoría de seguridad en desarrollo de software, DevSecOps y la desinfección práctica de la huella digital personal.*

---

## 📑 Tabla de Contenidos

- [Arquitectura del Proyecto](#arquitectura-del-proyecto)
- [Estructura de Directorios](#estructura-de-directorios)
- [Instalación y Configuración](#instalación-y-configuración)
- [Módulo 1: Web & App Security Auditor](#módulo-1-web--app-security-auditor)
  - [Auditoría Web y Cabeceras HTTP](#1-auditoría-web-y-transporte-seguro)
  - [Escaneo Estático de Secretos y Fugas](#2-detección-de-secretos-y-fugas-locales)
  - [Auditoría de Dependencias y CVEs (SCA)](#3-análisis-de-dependencias-sca)
  - [Generación de Informes (Markdown, HTML, JSON)](#4-motor-de-reportes)
- [Módulo 2: Digital Footprint & Privacy Cleaner](#módulo-2-digital-footprint--privacy-cleaner)
  - [Verificación de Brechas con k-Anonymity (HIBP)](#1-verificación-de-brechas-hibp-con-k-anonymity)
  - [Auditoría y Purga de Metadatos (EXIF / PDF)](#2-análisis-y-limpieza-de-metadatos)
  - [Generador Legal de Solicitudes RGPD (Derecho al Olvido)](#3-generador-de-solicitudes-rgpd--derecho-al-olvido)
  - [Checklist Interactivo de Desinfección](#4-tracker-de-cuentas-y-desinfección)
  - [Guías de Revocación OAuth y Sesiones](#5-guías-de-revocación-oauth-y-sesiones)
- [Enfoque Pedagógico: Base de Conocimiento](#enfoque-pedagógico-base-de-conocimiento)
- [Ejecución de Pruebas](#ejecución-de-pruebas)
- [Licencia](#licencia)

---

## 🏛️ Arquitectura del Proyecto

El proyecto está diseñado bajo principios de **Clean Architecture** y modularidad estricta con **Python 3.9+**, tipado robusto con **Pydantic V2** y una interfaz de consola enriquecida mediante **Typer** y **Rich**:

```text
                               ┌────────────────────────────────┐
                               │       Interfaz CLI Unificada   │
                               │         (sentinel / Typer)     │
                               └───────────────┬────────────────┘
                                               │
                         ┌─────────────────────┴─────────────────────┐
                         ▼                                           ▼
          ┌─────────────────────────────┐             ┌─────────────────────────────┐
          │  MÓDULO 1: Security Auditor │             │ MÓDULO 2: Footprint Cleaner │
          ├─────────────────────────────┤             ├─────────────────────────────┤
          │ • Headers & SSL/TLS Audit   │             │ • HIBP (k-Anonymity API)    │
          │ • OWASP Active Probes       │             │ • EXIF / PDF Metadata Scrub │
          │ • Local Secret Scanner      │             │ • GDPR Art. 17 Generator    │
          │ • SCA Dependency Audit      │             │ • Account Deletion Tracker  │
          │ • GDPR Compliance Checks    │             │ • OAuth Revocation Guides   │
          └─────────────────────────────┘             └─────────────────────────────┘
                         │                                           │
                         └─────────────────────┬─────────────────────┘
                                               ▼
                               ┌────────────────────────────────┐
                               │   Reporter & Knowledge Base    │
                               │  Terminal | Markdown | HTML    │
                               └────────────────────────────────┘
```

---

## 📂 Estructura de Directorios

```text
Seguridad/
├── pyproject.toml              # Definición del paquete y configuración de build
├── requirements.txt            # Dependencias del entorno virtual
├── README.md                   # Manual de usuario y referencia de ciberseguridad
├── sentinel/                   # Código fuente principal
│   ├── __init__.py             # Inicialización y supresión de advertencias
│   ├── __main__.py             # Punto de entrada para ejecución 'python -m sentinel'
│   ├── cli.py                  # CLI unificado interactivo (Typer + Rich)
│   ├── core/                   # Núcleo compartido
│   │   ├── config.py           # Configuración global, User-Agent, timeouts
│   │   ├── models.py           # Modelos Pydantic (Finding, Severity, ScanSummary)
│   │   └── reporter.py         # Motor de reportes (Terminal, Markdown, HTML, JSON)
│   └── modules/
│       ├── auditor/            # MÓDULO 1: Web & App Security Auditor
│       │   ├── compliance.py   # Auditoría de avisos de cookies y política de privacidad
│       │   ├── dependencies.py # Análisis de dependencias (SCA) y CVEs
│       │   ├── headers.py      # Inspección profunda de cabeceras de transporte HTTP
│       │   ├── knowledge_base.py # Fichas didácticas pedagógicas (OWASP, NIST, RFCs)
│       │   ├── owasp_checks.py # Escaneo activo de rutas sensibles (.git, .env, backups)
│       │   └── secrets.py      # Escáner estático de secretos y tokens en código
│       └── footprint/          # MÓDULO 2: Digital Footprint & Personal Privacy Cleaner
│           ├── gdpr_engine.py  # Generador de solicitudes Art. 17 RGPD (ES / EN)
│           ├── guides.py       # Guías paso a paso de revocación OAuth (Google, GitHub, Meta)
│           ├── hibp.py         # Verificador de brechas con k-Anonymity (HaveIBeenPwned)
│           ├── metadata.py     # Extractor y purgador de metadatos EXIF y documentos PDF
│           └── tracker.py      # Registro persistente local de cuentas por eliminar
└── tests/                      # Suite de pruebas unitarias automatizadas (pytest)
    ├── test_auditor.py         # Tests de secretos y dependencias
    └── test_footprint.py       # Tests de RGPD, metadatos y tracking
```

---

## 🚀 Instalación y Configuración

### 1. Clonar o acceder al directorio del proyecto:
```bash
cd /Users/danielsantander/Downloads/Seguridad
```

### 2. Crear y activar el entorno virtual:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependencias y paquete en modo editable:
```bash
pip install -e .
```

Una vez instalado, el comando `sentinel` estará disponible directamente en tu terminal.

---

## 🛡️ Módulo 1: Web & App Security Auditor

### 1. Auditoría Web y Transporte Seguro

Audita las cabeceras de respuesta HTTP, protocolos de transporte, cookies de sesión y configuraciones CORS de cualquier sitio o API:

```bash
# Auditoría rápida en terminal
sentinel web https://ejemplo.com

# Auditoría completa con generación de informes en Markdown y HTML interactivo
sentinel web https://ejemplo.com --report-md informe.md --report-html informe.html
```

#### Aspectos evaluados:
* **HSTS (`Strict-Transport-Security`):** Verifica `max-age`, `includeSubDomains` y `preload`.
* **CSP (`Content-Security-Policy`):** Detecta ausencia de política o uso inseguro de `unsafe-inline`.
* **Protección MIME (`X-Content-Type-Options: nosniff`):** Mitiga ataques basados en confusión de tipos.
* **Clickjacking (`X-Frame-Options` / `frame-ancestors`):** Comprueba que la web no pueda ser enmarcada en iframes no autorizados.
* **Control de Referencia (`Referrer-Policy`):** Previene la fuga de parámetros de URL internos.
* **Cookies de Sesión (`Set-Cookie`):** Exige los atributos `HttpOnly`, `Secure` y `SameSite`.
* **Exposición de Banners (`Server`, `X-Powered-By`):** Fugas de versiones de software.
* **Rutas Sensibles Expuestas (OWASP Top 10):** Intento no destructivo de acceso a `/.git/HEAD`, `/.env`, `/backup.sql`, `/.DS_Store`, `/phpinfo.php`, `/swagger-ui.html`.
* **Cumplimiento RGPD/Privacidad:** Detección de política de privacidad y aviso de cookies.

---

### 2. Detección de Secretos y Fugas Locales

Escanea el código fuente de tu repositorio en busca de credenciales, claves de API y certificados privados antes de hacer commit:

```bash
# Escanear el directorio actual
sentinel secrets .

# Escanear una carpeta específica y exportar reporte
sentinel secrets ./src --report-md reporte_secretos.md
```

#### Patrones de credenciales detectados:
* Claves privadas criptográficas (`RSA`, `EC`, `OPENSSH`).
* AWS Access Key IDs y Secret Access Keys.
* Tokens de acceso de GitHub (`ghp_`, `github_pat_`).
* Tokens de Slack y Stripe (`sk_live_`, `rk_live_`).
* Claves de Google Cloud / Firebase API.
* Cadenas de conexión a Bases de Datos con contraseñas incrustadas (`postgres://`, `mongodb+srv://`).
* Asignaciones directas de contraseñas (`password = "..."`).
* Detección de archivos `.env` sin ignorar.

> **Seguridad por diseño:** Los secretos encontrados se enmascaran automáticamente en la salida de terminal y en los reportes (`ghp_1234****5678`) para evitar fugas secundarias durante revisiones de código.

---

### 3. Análisis de Dependencias (SCA)

Verifica si tus dependencias fijadas contienen vulnerabilidades conocidas (CVEs):

```bash
sentinel dependencies ./requirements.txt
```

---

### 4. Motor de Reportes

Sentinel genera informes profesionales listos para compartir o integrar en pipelines de integración continua:
* **Terminal:** Tablas coloreadas y paneles con Markdown interactivo.
* **Markdown (`--report-md`):** Formato ideal para Pull Requests y documentación interna de seguridad.
* **HTML Autónomo (`--report-html`):** Panel web minimalista sin dependencias externas, con badges de severidad y ejemplos comparativos (Antes / Después).
* **JSON (`--report-json`):** Salida estructurada ideal para automatización y DevSecOps.

---

## 🕵️ Módulo 2: Digital Footprint & Privacy Cleaner

### 1. Verificación de Brechas (HIBP con k-Anonymity)

Verifica si una contraseña ha aparecido en filtraciones masivas de datos sin revelar la contraseña ni su hash completo a través de la red:

```bash
# Introducción segura sin eco en consola
sentinel pwned
```

#### Fundamento técnico: Modelo *k-Anonymity*
1. Sentinel calcula el hash criptográfico SHA-1 de la contraseña en local.
2. Extrae únicamente los **primeros 5 caracteres** del hash (ej. `21BD1`).
3. Envía ese prefijo al endpoint de la API de HaveIBeenPwned.
4. El servidor responde con la lista de todos los sufijos que comparten ese prefijo.
5. Sentinel compara el sufijo restante (35 caracteres) **localmente en tu máquina**.
6. **Garantía:** El servidor remoto nunca recibe tu contraseña ni tu hash completo.

---

### 2. Análisis y Limpieza de Metadatos

#### Inspección de metadatos sensibles (EXIF / GPS / PDF):
```bash
sentinel metadata scan foto_viaje.jpg
sentinel metadata scan documento_interno.pdf
```
Detecta coordenadas de geolocalización GPS exactas, fecha y hora de captura, modelo de cámara/smartphone y autor del documento.

#### Purga y saneamiento de metadatos:
```bash
# Crea una copia idéntica sin metadatos
sentinel metadata clean foto_viaje.jpg foto_anonimizada.jpg
sentinel metadata clean documento.pdf documento_limpio.pdf
```

---

### 3. Generador de Solicitudes RGPD / Derecho al Olvido

Genera cartas legales formalmente redactadas para ejercer el **Derecho de Supresión (Art. 17 RGPD)** y solicitar a plataformas, redes sociales o data brokers la eliminación total de tus datos:

```bash
# Asistente interactivo en español
sentinel privacy gdpr-request

# Generación en inglés (para servicios extranjeros) guardando a archivo
sentinel privacy gdpr-request --lang en -o carta_borrado_twitter.txt
```

---

### 4. Tracker de Cuentas y Desinfección

Un gestor local persistente (`privacy_tracker.json`) para realizar seguimiento de todas las cuentas o suscripciones que deseas dar de baja:

```bash
# Añadir cuenta pendiente
sentinel privacy tracker-add "DataBroker XYZ" "miemail@example.com" -n "Solicitud enviada por email"

# Ver checklist interactivo
sentinel privacy tracker-list

# Actualizar estado
sentinel privacy tracker-update "DataBroker XYZ" "Confirmado Borrado"

# Eliminar del tracker
sentinel privacy tracker-remove "DataBroker XYZ"
```

---

### 5. Guías de Revocación OAuth y Sesiones

Manuales paso a paso para revocar aplicaciones de terceros con acceso a tus cuentas principales y auditar dispositivos conectados:

```bash
# Guía para Google
sentinel privacy guides google

# Guía para GitHub
sentinel privacy guides github

# Ver todas las guías disponibles (Apple, Meta, Data Brokers)
sentinel privacy guides
```

---

## 📖 Enfoque Pedagógico: Base de Conocimiento

Cada vulnerabilidad identificada por Sentinel incluye una ficha didáctica explicativa:
1. **Concepto:** Explicación técnica clara y concisa.
2. **Escenario de Ataque Real:** Cómo explotaría un atacante esa deficiencia en un entorno real.
3. **Remediación:** Configuración o código exacto para corregirla.
4. **Comparativa de Código:** Ejemplos `Antes (Vulnerable)` vs. `Después (Protegido)`.
5. **Estándares de Referencia:** Mapeo con OWASP Top 10, CWE, RFCs y guías de W3C/NIST.

---

## 🧪 Ejecución de Pruebas

Para validar el funcionamiento de todos los módulos:

```bash
source .venv/bin/activate
pytest -v
```

Todas las pruebas se ejecutan de manera aislada utilizando fixtures y directorios temporales.

---

## 📜 Licencia

Proyecto bajo licencia MIT. Desarrollado con fines educativos, de auditoría defensiva y protección de la privacidad digital.
