"""
Pedagogical Knowledge Base for Web & App Security Auditor.
Provides educational cards, attack scenarios, before/after code samples, and RFC/OWASP references.
"""
from typing import Dict
from sentinel.core.models import EducationalCard

AUDITOR_KNOWLEDGE_BASE: Dict[str, EducationalCard] = {
    "MISSING_HSTS": EducationalCard(
        title="Falta de HTTP Strict Transport Security (HSTS)",
        concept="HSTS (RFC 6797) es una cabecera que instruye a los navegadores a interactuar con el dominio únicamente a través de HTTPS cifrado, bloqueando cualquier intento de conexión en texto plano.",
        danger_scenario="Un atacante situado en la misma red Wi-Fi o red intermedia ejecuta un ataque SSL Stripping (ej. con sslstrip o arpspoof). Al no existir HSTS, intercepta la primera petición HTTP del usuario antes de que redirija a HTTPS, leyendo credenciales o tokens de sesión en claro.",
        remediation="Configura la cabecera HSTS en tu servidor web (Nginx, Apache, Cloudflare o middleware de la app) con un max-age de al menos un año y soporte para subdominios.",
        code_before="""# Nginx (Inseguro - Sin HSTS)
server {
    listen 443 ssl;
    server_name example.com;
    # No hay directiva add_header Strict-Transport-Security
}""",
        code_after="""# Nginx (Seguro - Con HSTS y subdominios)
server {
    listen 443 ssl http2;
    server_name example.com;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}""",
        references=[
            "OWASP Top 10: A05:2021-Security Misconfiguration",
            "RFC 6797: HTTP Strict Transport Security (HSTS)",
            "Mozilla Observatory: HSTS Guidelines"
        ]
    ),

    "MISSING_CSP": EducationalCard(
        title="Falta de Content Security Policy (CSP)",
        concept="CSP (W3C Content Security Policy) es una capa de defensa en profundidad que restringe de qué fuentes puede el navegador cargar scripts, estilos, imágenes y conexiones WebSocket o AJAX.",
        danger_scenario="Si la aplicación tiene una vulnerabilidad XSS (Cross-Site Scripting), el navegador ejecutará cualquier script inyectado por el atacante. Con CSP estricto, el navegador bloquea la descarga o ejecución del script malicioso foráneo y evita la exfiltración a servidores del atacante.",
        remediation="Implementa una directiva CSP restrictiva que prohíba 'unsafe-inline' y limite los orígenes permitidos.",
        code_before="""# Cabecera inexistente o demasiado permisiva
Content-Security-Policy: *""",
        code_after="""# Cabecera robusta recomendada
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests;""",
        references=[
            "OWASP Top 10: A03:2021-Injection (Cross-Site Scripting)",
            "W3C Content Security Policy Level 3",
            "MDN Web Docs: Content Security Policy"
        ]
    ),

    "MISSING_X_CONTENT_TYPE_OPTIONS": EducationalCard(
        title="Falta de X-Content-Type-Options (MIME Sniffing)",
        concept="Evita que los navegadores intenten adivinar (sniff) el tipo de contenido de una respuesta HTTP en lugar de respetar estrictamente lo declarado en la cabecera Content-Type.",
        danger_scenario="Un usuario malicioso sube un avatar 'avatar.jpg' que contiene código HTML/JavaScript. Si el servidor no envía 'nosniff', algunos navegadores antiguos o permisivos intentan deducir el tipo, ejecutan el archivo como text/html y desencadenan un ataque XSS.",
        remediation="Establece 'X-Content-Type-Options: nosniff' en todas las respuestas HTTP.",
        code_before="""# Respuesta HTTP sin cabecera
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8""",
        code_after="""# Respuesta HTTP protegida
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff""",
        references=[
            "RFC 7231: Hypertext Transfer Protocol (HTTP/1.1)",
            "OWASP Secure Headers Project"
        ]
    ),

    "MISSING_X_FRAME_OPTIONS": EducationalCard(
        title="Falta de Protección contra Clickjacking (X-Frame-Options / CSP frame-ancestors)",
        concept="Evita que la aplicación web sea incrustada dentro de elementos <iframe>, <frame> o <object> en sitios web de terceros.",
        danger_scenario="Ataque Clickjacking: El atacante monta una página web maliciosa con un juego o botón 'Reclamar premio'. Superpone un iframe transparente de tu panel bancario o de configuración de cuenta justo encima. Cuando el usuario hace clic, confirma una transferencia o borra su cuenta sin saberlo.",
        remediation="Envía la cabecera 'X-Frame-Options: DENY' o 'SAMEORIGIN', o utiliza la directiva CSP 'frame-ancestors 'none''.",
        code_before="""# Express.js (Inseguro - Sin protección iframe)
app.use((req, res, next) => next());""",
        code_after="""# Express.js (Seguro con Helmet)
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
// Genera: X-Frame-Options: DENY""",
        references=[
            "OWASP Top 10: A05:2021-Security Misconfiguration",
            "RFC 7034: HTTP Header Field X-Frame-Options"
        ]
    ),

    "MISSING_REFERRER_POLICY": EducationalCard(
        title="Falta de Referrer-Policy",
        concept="Gobierna la cantidad de información enviada en la cabecera 'Referer' cuando los usuarios hacen clic en enlaces que salen de tu sitio web.",
        danger_scenario="Si tus URLs internas contienen identificadores sensibles (ej. /reset-password?token=xyz123 o /user/49102/invoice), al hacer clic en un enlace a un sitio externo, el token se envía en texto plano en la cabecera Referer al servidor de terceros.",
        remediation="Establece 'Referrer-Policy: strict-origin-when-cross-origin' o 'no-referrer'.",
        code_before="""# Comportamiento por defecto en navegadores antiguos:
Referrer-Policy: unsafe-url""",
        code_after="""# Configuración segura:
Referrer-Policy: strict-origin-when-cross-origin""",
        references=[
            "W3C Referrer Policy Specification",
            "OWASP Cheat Sheet: Securing Web Applications"
        ]
    ),

    "CORS_WILDCARD_ORIGIN": EducationalCard(
        title="CORS Mal Configurado (Access-Control-Allow-Origin: *)",
        concept="El mecanismo Cross-Origin Resource Sharing (CORS) define qué dominios externos pueden leer datos de una API a través de peticiones AJAX en el navegador.",
        danger_scenario="Si una API privada o autenticada responde con 'Access-Control-Allow-Origin: *' o refleja dinámicamente el origen con 'Access-Control-Allow-Credentials: true', cualquier web maliciosa que visite la víctima puede hacer llamadas a tu API y exfiltrar datos privados del usuario.",
        remediation="Valida estrictamente los orígenes permitidos en una lista blanca explícita en lugar de aceptar comodines (*).",
        code_before="""# FastAPI / Starlette (Inseguro)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)""",
        code_after="""# FastAPI / Starlette (Seguro)
ALLOWED_ORIGINS = ["https://app.midominio.com", "https://admin.midominio.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)""",
        references=[
            "OWASP Top 10: A05:2021-Security Misconfiguration",
            "PortSwigger Web Security Academy: CORS Vulnerabilities"
        ]
    ),

    "INSECURE_COOKIE": EducationalCard(
        title="Cookies Inseguras (Falta HttpOnly, Secure o SameSite)",
        concept="Los atributos de las cookies determinan su accesibilidad desde JavaScript (HttpOnly), su transmisión únicamente bajo HTTPS (Secure) y su envío en peticiones de origen cruzado (SameSite).",
        danger_scenario="Si una cookie de sesión carece de 'HttpOnly', cualquier script inyectado mediante XSS puede leer `document.cookie` y robar la sesión completa. Si carece de 'SameSite=Lax/Strict', es vulnerable a CSRF (Cross-Site Request Forgery).",
        remediation="Asegura que toda cookie de sesión o sensible configure: HttpOnly; Secure; SameSite=Lax (o Strict).",
        code_before="""# Inseguro (Cookie de sesión por defecto)
Set-Cookie: session_id=abc12345; Path=/""",
        code_after="""# Seguro (Atributos de endurecimiento completos)
Set-Cookie: session_id=abc12345; Path=/; Secure; HttpOnly; SameSite=Lax""",
        references=[
            "OWASP Top 10: A07:2021-Identification and Authentication Failures",
            "RFC 6265bis: Cookies: HTTP State Management Mechanism"
        ]
    ),

    "SERVER_BANNER_DISCLOSURE": EducationalCard(
        title="Exposición de Tecnologías y Versiones de Servidor",
        concept="Cabeceras como 'Server' o 'X-Powered-By' exponen la marca y versión exacta del software backend (ej. Apache/2.4.41, PHP/7.4.3, Express).",
        danger_scenario="Facilita el reconocimiento a atacantes. En lugar de probar ataques genéricos, buscan inmediatamente CVEs específicos de esa versión exacta en bases de datos como NVD o Exploit-DB.",
        remediation="Oculta o anonimiza las cabeceras de identificación de versión en la configuración del servidor.",
        code_before="""# Cabeceras expuestas por defecto:
Server: Apache/2.4.49 (Unix)
X-Powered-By: PHP/7.4.3""",
        code_after="""# Nginx:
server_tokens off;

# Express:
app.disable('x-powered-by');""",
        references=[
            "OWASP Top 10: A05:2021-Security Misconfiguration",
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        ]
    ),

    "EXPOSED_SENSITIVE_FILES": EducationalCard(
        title="Fuga de Archivos Sensibles (.git, .env, backups)",
        concept="Directorios ocultos de control de versiones (.git), archivos de configuración (.env, config.json) o copias de seguridad (.bak, .sql) expuestos directamente vía web.",
        danger_scenario="Un atacante descarga la carpeta `.git/` completa usando herramientas automáticas y reconstruye todo el código fuente del proyecto, encontrando credenciales históricas, contraseñas de base de datos y lógica interna.",
        remediation="Configura el servidor web (Nginx/Apache/Caddy) para denegar el acceso a archivos ocultos (que inicien con un punto) y bloquea explícitamente extensiones sensibles.",
        code_before="""# Directorio raíz servido sin filtros""",
        code_after="""# Nginx: Bloquear archivos ocultos y sensibles
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}

location ~* \\.(env|git|bak|sql|yaml|yml|config)$ {
    deny all;
    return 404;
}""",
        references=[
            "OWASP Top 10: A01:2021-Broken Access Control",
            "CWE-552: Files or Directories Accessible to External Parties"
        ]
    ),

    "HARDCODED_SECRET": EducationalCard(
        title="Secreto o Credencial Hardcodeada en Código Fuente",
        concept="Claves de API, tokens privados, contraseñas de bases de datos o certificados criptográficos incrustados directamente en el código.",
        danger_scenario="Si el código se sube a un repositorio público o privado comprometido, bots de escaneo automatizado extraen las credenciales en cuestión de segundos, comprometiendo infraestructura en la nube (AWS, Azure) o facturación.",
        remediation="Utiliza variables de entorno cargadas en tiempo de ejecución (.env no commiteado) o almacenes seguros de secretos (Vault, AWS Secrets Manager, GCP Secret Manager).",
        code_before="""# Inseguro (Clave en código fuente)
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASS = "SuperSecretPassword123!\"""",
        code_after="""# Seguro (Lectura desde entorno)
import os
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")
DB_PASS = os.environ.get("DB_PASS")

if not AWS_SECRET_KEY or not DB_PASS:
    raise RuntimeError("Credenciales requeridas ausentes en el entorno.")""",
        references=[
            "OWASP Top 10: A07:2021-Identification and Authentication Failures",
            "CWE-798: Use of Hard-coded Credentials"
        ]
    ),

    "VULNERABLE_DEPENDENCY": EducationalCard(
        title="Componente o Dependencia con Vulnerabilidades Conocidas (CVE)",
        concept="Uso de librerías de terceros con fallos de seguridad documentados y divulgados públicamente.",
        danger_scenario="Los atacantes buscan librerías vulnerables populares (ej. Log4j, versiones desactualizadas de Django o Express) y aplican exploits conocidos ya disponibles para ejecutar código remoto o denegación de servicio.",
        remediation="Ejecuta herramientas de Software Composition Analysis (SCA) como `pip-audit`, `npm audit` o `trivy` de manera continua en tu CI/CD y actualiza a versiones parcheadas.",
        code_before="""# requirements.txt (Desactualizado)
requests==2.20.0
urllib3==1.24.1""",
        code_after="""# requirements.txt (Actualizado y fijado con hash)
requests==2.31.0
urllib3==2.1.0""",
        references=[
            "OWASP Top 10: A06:2021-Vulnerable and Outdated Components",
            "NIST National Vulnerability Database (NVD)"
        ]
    ),
    
    "MISSING_PRIVACY_NOTICE": EducationalCard(
        title="Ausencia de Enlace a Política de Privacidad / RGPD",
        concept="Requisito de transparencia legal (Artículos 12, 13 y 14 del RGPD / LOPDGDD) que exige informar a los usuarios sobre quién trata sus datos, con qué finalidad y cómo ejercer sus derechos.",
        danger_scenario="Incumplimiento legal y sanciones por parte de agencias de protección de datos (AEPD, CNIL), además de pérdida de confianza de los usuarios al recolectar datos sin consentimiento explícito.",
        remediation="Incluye un enlace visible en el pie de página hacia una Política de Privacidad clara, un aviso de cookies antes de almacenar cookies no esenciales, y un canal de contacto para derechos ARCO/Supresión.",
        code_before="""<!-- Footer sin avisos de privacidad -->
<footer>© 2026 Mi Empresa</footer>""",
        code_after="""<!-- Footer con transparencia RGPD -->
<footer>
  © 2026 Mi Empresa | 
  <a href="/privacidad">Política de Privacidad</a> | 
  <a href="/cookies">Configuración de Cookies</a> | 
  <a href="mailto:dpo@miempresa.com">Contacto DPO</a>
</footer>""",
        references=[
            "Reglamento General de Protección de Datos (RGPD) - Art. 13",
            "Agencia Española de Protección de Datos (AEPD) Guía de Cookies"
        ]
    )
}
