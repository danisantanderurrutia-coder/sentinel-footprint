"""
Privacy Account Deletion & Opt-Out Tracker.
Maintains a local persistent log of services, data brokers, and accounts pending or confirmed for deletion.
"""
from __future__ import annotations
import json
import os
import uuid
from datetime import datetime
from typing import List, Optional
from sentinel.core.models import AccountTrackerItem
from sentinel.core.config import settings


def _load_tracker_file(file_path: Optional[str] = None) -> List[AccountTrackerItem]:
    path = file_path or settings.TRACKER_FILE
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [AccountTrackerItem(**item) for item in data]
    except (json.JSONDecodeError, OSError):
        return []


def _save_tracker_file(items: List[AccountTrackerItem], file_path: Optional[str] = None) -> None:
    path = file_path or settings.TRACKER_FILE
    with open(path, "w", encoding="utf-8") as f:
        json.dump([item.model_dump() for item in items], f, indent=2, ensure_ascii=False)


def add_account_to_tracker(
    platform_name: str,
    email_or_username: str,
    notes: str = "",
    file_path: Optional[str] = None
) -> AccountTrackerItem:
    """Add a new account to the privacy deletion checklist."""
    items = _load_tracker_file(file_path)
    new_item = AccountTrackerItem(
        id=str(uuid.uuid4())[:8],
        platform_name=platform_name,
        email_or_username=email_or_username,
        status="Pendiente",
        request_date=datetime.now().strftime("%Y-%m-%d"),
        notes=notes
    )
    items.append(new_item)
    _save_tracker_file(items, file_path)
    return new_item


def list_tracked_accounts(file_path: Optional[str] = None) -> List[AccountTrackerItem]:
    """Retrieve all tracked accounts."""
    return _load_tracker_file(file_path)


def update_account_status(
    account_id: str,
    new_status: str,
    file_path: Optional[str] = None
) -> bool:
    """Update status of a tracked account (e.g. 'Solicitado', 'Confirmado Borrado')."""
    items = _load_tracker_file(file_path)
    for it in items:
        if it.id == account_id or it.platform_name.lower() == account_id.lower():
            it.status = new_status
            if "borrado" in new_status.lower() or "eliminado" in new_status.lower():
                it.confirmation_date = datetime.now().strftime("%Y-%m-%d")
            _save_tracker_file(items, file_path)
            return True
    return False


def remove_tracked_account(account_id: str, file_path: Optional[str] = None) -> bool:
    """Remove an entry from the tracker."""
    items = _load_tracker_file(file_path)
    filtered = [it for it in items if it.id != account_id and it.platform_name.lower() != account_id.lower()]
    if len(filtered) != len(items):
        _save_tracker_file(filtered, file_path)
        return True
    return False
