"""In-memory fakes for the Supabase surface the backend actually uses.

Just enough of table()/select()/insert()/update()/eq()/limit()/execute()
and storage.from_().upload() for the persistence and evidence-storage
services, so no test ever needs real credentials or network access.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

# Shared fake-but-well-formed Supabase user UUID for tests that don't care
# about a specific value, just that one is consistently present.
DEFAULT_TEST_USER_ID = "11111111-1111-1111-1111-111111111111"


class FakeResult:
    def __init__(self, data: Any):
        self.data = data


class FakeTable:
    def __init__(self, store: "FakeSupabaseClient", name: str):
        self._store = store
        self._name = name
        self._pending_insert: Any = None
        self._pending_update: dict[str, Any] | None = None
        self._filters: list[tuple[str, Any]] = []

    def select(self, *_args: Any, **_kwargs: Any) -> "FakeTable":
        return self

    def limit(self, _n: int) -> "FakeTable":
        return self

    def insert(self, row_or_rows: Any) -> "FakeTable":
        self._pending_insert = row_or_rows
        return self

    def update(self, payload: dict[str, Any]) -> "FakeTable":
        self._pending_update = payload
        return self

    def eq(self, column: str, value: Any) -> "FakeTable":
        self._filters.append((column, value))
        return self

    def execute(self) -> FakeResult:
        if self._store.table_error:
            raise RuntimeError("simulated table failure")

        if self._pending_insert is not None:
            rows = (
                self._pending_insert
                if isinstance(self._pending_insert, list)
                else [self._pending_insert]
            )
            inserted = []
            for row in rows:
                stored = dict(row)
                stored.setdefault(
                    "id", f"{self._name}-{len(self._store.tables[self._name]) + 1}"
                )
                self._store.tables[self._name].append(stored)
                inserted.append(stored)
            self._pending_insert = None
            return FakeResult(inserted)

        if self._pending_update is not None:
            if self._store.update_error:
                raise RuntimeError("simulated update failure")
            updated = []
            for row in self._store.tables[self._name]:
                if all(row.get(col) == val for col, val in self._filters):
                    row.update(self._pending_update)
                    updated.append(row)
            self._pending_update = None
            return FakeResult(updated)

        matching = [
            row
            for row in self._store.tables[self._name]
            if all(row.get(col) == val for col, val in self._filters)
        ]
        return FakeResult(matching)


class FakeStorageBucket:
    def __init__(self, store: "FakeSupabaseClient", bucket: str):
        self._store = store
        self._bucket = bucket

    def upload(
        self,
        *,
        path: str,
        file: bytes,
        file_options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._store.missing_bucket:
            # Mirrors the Supabase Storage error text for an absent bucket.
            raise RuntimeError('{"statusCode":"404","error":"Bucket not found"}')
        if self._store.upload_error:
            raise RuntimeError("simulated storage outage")
        self._store.uploads.append(
            {
                "bucket": self._bucket,
                "path": path,
                "file": file,
                "file_options": file_options,
            }
        )
        return {"path": path}


class FakeStorage:
    def __init__(self, store: "FakeSupabaseClient"):
        self._store = store

    def from_(self, bucket: str) -> FakeStorageBucket:
        return FakeStorageBucket(self._store, bucket)


class FakeSupabaseClient:
    """Fake client with switches for the failure modes worth testing."""

    def __init__(
        self,
        *,
        missing_bucket: bool = False,
        upload_error: bool = False,
        update_error: bool = False,
        table_error: bool = False,
    ):
        self.tables: dict[str, list[dict]] = defaultdict(list)
        self.uploads: list[dict[str, Any]] = []
        self.missing_bucket = missing_bucket
        self.upload_error = upload_error
        self.update_error = update_error
        self.table_error = table_error
        self.storage = FakeStorage(self)

    def table(self, name: str) -> FakeTable:
        return FakeTable(self, name)
