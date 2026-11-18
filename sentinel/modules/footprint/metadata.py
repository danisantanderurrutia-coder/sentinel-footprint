"""
Metadata Auditor and Sanitizer for Images (EXIF) and Documents (PDF).
Detects geolocations, device identifiers, authors, and allows scrubbing metadata.
"""
from __future__ import annotations
import os
from typing import Dict, Any, Optional
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from pypdf import PdfReader, PdfWriter


def get_image_exif_metadata(image_path: str) -> Dict[str, Any]:
    """
    Extract readable EXIF metadata from an image, including GPS data and camera hardware.
    """
    metadata: Dict[str, Any] = {}
    try:
        with Image.open(image_path) as img:
            exif_raw = img._getexif()
            if not exif_raw:
                return metadata

            for tag_id, value in exif_raw.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                
                # Tratar GPS por separado
                if tag_name == "GPSInfo":
                    gps_data = {}
                    for gps_tag_id, gps_val in value.items():
                        sub_tag = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                        gps_data[sub_tag] = str(gps_val)
                    metadata["GPSInfo"] = gps_data
                else:
                    # Convertir a cadena legible si son bytes
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore").strip("\x00")
                        except Exception:
                            value = str(value)
                    metadata[tag_name] = str(value)
    except Exception as e:
        metadata["Error"] = f"No se pudo leer EXIF: {e}"

    return metadata


def strip_image_metadata(source_path: str, output_path: str) -> bool:
    """
    Create a clean copy of the image without any EXIF tags, GPS coordinates, or camera data.
    """
    try:
        with Image.open(source_path) as img:
            # Crear nueva imagen con los mismos píxeles pero sin metadatos
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(list(img.getdata()))
            clean_img.save(output_path)
            return True
    except Exception:
        return False


def get_pdf_metadata(pdf_path: str) -> Dict[str, Any]:
    """
    Extract document metadata from a PDF file (Author, Producer, Creator, ModDate).
    """
    metadata: Dict[str, Any] = {}
    try:
        reader = PdfReader(pdf_path)
        doc_info = reader.metadata
        if doc_info:
            for key, val in doc_info.items():
                clean_key = key.lstrip("/").strip()
                metadata[clean_key] = str(val)
        metadata["TotalPages"] = len(reader.pages)
    except Exception as e:
        metadata["Error"] = f"No se pudo leer metadata de PDF: {e}"

    return metadata


def strip_pdf_metadata(source_path: str, output_path: str) -> bool:
    """
    Sanitize and copy PDF content without original metadata.
    """
    try:
        reader = PdfReader(source_path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        # Dejar metadata vacía explícitamente
        writer.add_metadata({})
        with open(output_path, "wb") as f_out:
            writer.write(f_out)
        return True
    except Exception:
        return False
