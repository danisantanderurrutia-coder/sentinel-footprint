"""
GDPR / RGPD Right to be Forgotten and Data Erasure Request Generator.
Produces legally robust letters for Article 17 (Erasure), Article 15 (Access), and Article 21 (Opt-out/Objection).
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional


def generate_erasure_request_es(
    full_name: str,
    id_number: str,
    email: str,
    service_name: str,
    username_or_account: Optional[str] = None,
    specific_details: Optional[str] = None
) -> str:
    """
    Genera una solicitud formal de ejercicio del Derecho de Supresión (Derecho al Olvido)
    conforme al Artículo 17 del Reglamento (UE) 2016/679 (RGPD) y Ley Orgánica 3/2018 (LOPDGDD).
    """
    now_date = datetime.now().strftime("%d de %B de %Y")
    account_info = f"- Cuenta / Usuario: {username_or_account}\n" if username_or_account else ""
    extra = f"\nDetalles específicos del tratamiento:\n{specific_details}\n" if specific_details else ""

    return f"""ASUNTO: Ejercicio del Derecho de Supresión de Datos Personales (Art. 17 RGPD)

A la atención del Delegado de Protección de Datos (DPO) / Responsable de Seguridad de {service_name}:

Yo, {full_name}, mayor de edad, con documento de identidad / pasaporte Nº {id_number}, y dirección de correo electrónico vinculada: {email},
{account_info}
Por medio de la presente carta, y en virtud de lo dispuesto en el Artículo 17 del Reglamento General de Protección de Datos (Reglamento UE 2016/679) y la Ley Orgánica 3/2018 de Protección de Datos Personales y garantía de los derechos digitales:

SOLICITO:

1. La SUPRESIÓN Y ELIMINACIÓN DEFINITIVA de todos mis datos personales asociados a mi persona, cuenta de usuario, perfil de navegación, direcciones IP y copias de seguridad obrantes en sus ficheros y bases de datos.
2. Que se revoque de forma inmediata cualquier consentimiento previo otorgado para finalidades de marketing, cesión de datos a terceros, elaboración de perfiles o data brokers.
3. Que, de conformidad con el Artículo 17.2 del RGPD, en caso de haber hecho públicos dichos datos o haberlos comunicado a terceros responsables o encargados del tratamiento, les notifique la presente solicitud de supresión de cualquier enlace, copia o réplica de los mismos.
4. Que me sea remitida confirmación por escrito de la efectiva supresión en el plazo preceptivo de UN MES previsto por el Artículo 12.3 del RGPD.{extra}

En caso de no obtener respuesta en el plazo legal establecido, me reservo el derecho de presentar la correspondiente reclamación ante la Agencia Española de Protección de Datos (AEPD) o la autoridad de control de protección de datos competente.

En fecha {now_date}.

Atentamente,

{full_name}
Email de contacto: {email}
"""


def generate_erasure_request_en(
    full_name: str,
    id_number: str,
    email: str,
    service_name: str,
    username_or_account: Optional[str] = None
) -> str:
    """
    Generates a formal GDPR Article 17 Erasure (Right to be Forgotten) request in English.
    """
    now_date = datetime.now().strftime("%B %d, %Y")
    account_info = f"- Associated Username/ID: {username_or_account}\n" if username_or_account else ""

    return f"""SUBJECT: Formal GDPR Article 17 Request for Erasure (Right to be Forgotten)

To the Data Protection Officer / Privacy Team of {service_name}:

I, {full_name}, identification number {id_number}, registered with the email address {email},
{account_info}
hereby exercise my Right to Erasure pursuant to Article 17 of the General Data Protection Regulation (EU Regulation 2016/679).

I formally request:
1. The permanent deletion and erasure of all personal data, activity logs, identifiers, and telemetry relating to me in your systems and backups.
2. The immediate cessation of any data processing, profiling, or sharing with third parties, affiliate networks, or data brokers.
3. In accordance with Article 17(2) GDPR, that you take all reasonable steps to inform any third-party controllers processing this data of my erasure request.
4. Written confirmation of complete erasure within the statutory deadline of one month as stipulated by Article 12(3) GDPR.

Failure to comply with this request within the statutory timeframe may result in a formal complaint lodged with the competent European Data Protection Authority.

Date: {now_date}

Sincerely,

{full_name}
Email: {email}
"""
