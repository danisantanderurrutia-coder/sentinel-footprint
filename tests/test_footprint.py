"""
Unit tests for Digital Footprint and Privacy modules.
"""
import os
import tempfile
import hashlib
from PIL import Image
from sentinel.modules.footprint.gdpr_engine import generate_erasure_request_es, generate_erasure_request_en
from sentinel.modules.footprint.tracker import (
    add_account_to_tracker,
    list_tracked_accounts,
    update_account_status,
    remove_tracked_account
)
from sentinel.modules.footprint.metadata import strip_image_metadata, get_image_exif_metadata


def test_gdpr_request_generator_contains_legal_articles():
    letter_es = generate_erasure_request_es(
        full_name="Juan Perez",
        id_number="12345678Z",
        email="juan@example.com",
        service_name="DataBrokerCorp",
        username_or_account="juanperez88"
    )
    assert "Artículo 17 del Reglamento" in letter_es
    assert "Juan Perez" in letter_es
    assert "12345678Z" in letter_es
    assert "DataBrokerCorp" in letter_es
    assert "juan@example.com" in letter_es

    letter_en = generate_erasure_request_en(
        full_name="John Doe",
        id_number="P123456",
        email="john@example.com",
        service_name="GlobalAds"
    )
    assert "Article 17 of the General Data Protection Regulation" in letter_en
    assert "GlobalAds" in letter_en


def test_privacy_tracker_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        tracker_file = os.path.join(tmpdir, "test_tracker.json")
        
        # Add item
        item = add_account_to_tracker("TestPlatform", "user@test.com", "Test Note", file_path=tracker_file)
        assert item.platform_name == "TestPlatform"
        assert item.status == "Pendiente"

        # List items
        items = list_tracked_accounts(file_path=tracker_file)
        assert len(items) == 1
        assert items[0].id == item.id

        # Update item
        updated = update_account_status(item.id, "Confirmado Borrado", file_path=tracker_file)
        assert updated is True
        items_after = list_tracked_accounts(file_path=tracker_file)
        assert items_after[0].status == "Confirmado Borrado"
        assert items_after[0].confirmation_date is not None

        # Remove item
        removed = remove_tracked_account(item.id, file_path=tracker_file)
        assert removed is True
        assert len(list_tracked_accounts(file_path=tracker_file)) == 0


def test_image_metadata_stripping():
    with tempfile.TemporaryDirectory() as tmpdir:
        src_img = os.path.join(tmpdir, "original.jpg")
        clean_img = os.path.join(tmpdir, "sanitized.jpg")

        # Create basic RGB image
        img = Image.new("RGB", (100, 100), color=(73, 109, 137))
        img.save(src_img)

        # Strip metadata
        success = strip_image_metadata(src_img, clean_img)
        assert success is True
        assert os.path.exists(clean_img)

        # Verify no EXIF remains
        meta = get_image_exif_metadata(clean_img)
        assert meta == {}
