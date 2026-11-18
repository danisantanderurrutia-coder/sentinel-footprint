"""
Step-by-step Guides for OAuth App Revocation, Active Session Auditing, and Opt-out.
"""
from typing import Dict

OAUTH_GUIDES: Dict[str, str] = {
    "google": """### 🛡️ Guía de Revocación OAuth: Cuenta de Google
1. **Acceso al Panel:** Ingresa a https://myaccount.google.com/permissions
2. **Revisión de Aplicaciones:** Examina las 'Apps de terceros con acceso a la cuenta'.
3. **Identificación de Riesgos:** Busca apps que ya no uses o permisos excesivos (ej. 'Acceso completo a Gmail' o 'Google Drive').
4. **Revocación:** Haz clic en la aplicación y selecciona **'Quitar acceso'** o **'Eliminar conexiones'**.
5. **Auditoría de Sesiones Activas:** Ve a https://myaccount.google.com/device-activity y cierra sesión en dispositivos antiguos o no reconocidos.
""",

    "github": """### 🛡️ Guía de Revocación OAuth: GitHub
1. **Acceso al Panel:** Ve a **Settings** -> **Applications** -> https://github.com/settings/applications
2. **Authorized OAuth Apps:** Pestaña 'Authorized OAuth Apps' para aplicaciones web vinculadas. Haz clic en **Revoke** en las obsoletas.
3. **Personal Access Tokens:** Ve a https://github.com/settings/tokens y revoca tokens clásicos o fine-grained expirados o innecesarios.
4. **SSH & GPG Keys:** Revisa en https://github.com/settings/keys cualquier clave vinculada a portátiles antiguos.
5. **Sesiones Activas:** Revisa https://github.com/settings/sessions y presiona 'See more' para revocar sesiones sospechosas.
""",

    "apple": """### 🛡️ Guía de Revocación: Iniciar Sesión con Apple
1. **En la Web:** Ve a https://appleid.apple.com/account/manage -> Sección **Inicio de sesión y seguridad** -> **Iniciar sesión con Apple**.
2. **En iPhone/iPad:** Ajustes -> [Tu Nombre] -> **Inicio de sesión y seguridad** -> **Iniciar sesión con Apple**.
3. **Acción:** Selecciona la app o servicio y presiona **'Dejar de usar el ID de Apple'**. Si utilizaste 'Ocultar mi correo', la dirección de reenvío dejará de funcionar.
""",

    "meta": """### 🛡️ Guía de Revocación: Meta / Facebook / Instagram
1. **Configuración de Apps en Facebook:** Ve a https://www.facebook.com/settings?tab=applications
2. **Eliminar aplicaciones:** Marca las aplicaciones inactivas y presiona **'Eliminar'**.
3. **Auditoría de Sesiones:** Ve a https://accountscenter.facebook.com/password_and_security y revisa 'Dónde has iniciado sesión'. Cierra todas las sesiones desconocidas.
""",

    "databrokers": """### 🌐 Guía de Opt-Out en Data Brokers y Motores de Búsqueda
Los data brokers recopilan y venden perfiles personales (nombres, direcciones, teléfonos, familiares).
Enlaces directos de exclusión voluntaria (Opt-out):
1. **Herramienta de retirada de datos personales en Google:** https://myactivity.google.com/results-about-you
2. **Eliminación de búsquedas de información personal de Google:** https://support.google.com/websearch/troubleshooter/3111061
3. **Lista Robinson (España - Exclusión de publicidad no deseada):** https://www.listarobinson.es
4. **Opt-Out general de publicidad comportamental:** https://www.youronlinechoices.eu
"""
}


def get_guide(topic: str) -> str:
    """Retrieve guide for specific provider or all."""
    topic_clean = topic.lower().strip()
    if topic_clean in OAUTH_GUIDES:
        return OAUTH_GUIDES[topic_clean]
    
    # Concatenar resumen si no coincide con uno específico
    available = ", ".join(OAUTH_GUIDES.keys())
    return f"Proveedor no encontrado. Proveedores disponibles: **{available}**\n\n" + "\n---\n".join(OAUTH_GUIDES.values())
