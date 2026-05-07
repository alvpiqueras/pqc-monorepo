from sqlalchemy.orm import Session

from API.app.db import models

from typing import cast


class SqliteRegistryRepository:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------
    # ENTRIES
    # ------------------------

    def add_entry(
        self,
        identity,
        public_key,
        metadata_json,
        valid_from,
        valid_until,
        leaf_hash,
        tree_version,
    ):
        entry = models.RegistryEntry(
            identity=identity,
            public_key=public_key,
            metadata_json=metadata_json,
            valid_from=valid_from,
            valid_until=valid_until,
            leaf_hash=leaf_hash,
            tree_version=tree_version,
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def list_entries(self):
        return self.db.query(models.RegistryEntry).filter_by(status="active").all()

    def list_entries_up_to_version(self, tree_version: int):
        """
        Devuelve las entradas activas cuya incorporación al registro
        se produjo hasta la versión indicada inclusive.
        """
        return (
            self.db.query(models.RegistryEntry)
            .filter(
                models.RegistryEntry.status == "active",
                models.RegistryEntry.tree_version <= tree_version,
            )
            .order_by(models.RegistryEntry.id.asc())
            .all()
        )

    def get_entry_by_identity(self, identity):
        return self.db.query(models.RegistryEntry).filter_by(
            identity=identity,
            status="active",
        ).first()

    # ------------------------
    # ROOTS
    # ------------------------

    def save_signed_root(self, tree_version, tree_size, merkle_root, signature, public_key):
        root = models.SignedRoot(
            tree_version=tree_version,
            tree_size=tree_size,
            merkle_root=merkle_root,
            signature=signature,
            public_key=public_key,
        )
        self.db.add(root)
        self.db.commit()
        self.db.refresh(root)
        return root

    def get_latest_root(self):
        return (
            self.db.query(models.SignedRoot)
            .order_by(
                models.SignedRoot.tree_version.desc(),
                models.SignedRoot.id.desc(),
            )
            .first()
        )

    def get_root_by_version(self, tree_version: int):
        """
        Devuelve la raíz firmada asociada a una versión concreta del árbol.
        """
        return (
            self.db.query(models.SignedRoot)
            .filter(models.SignedRoot.tree_version == tree_version)
            .order_by(models.SignedRoot.id.desc())
            .first()
        )

    def list_roots(self):
        """
        Devuelve todas las raíces firmadas almacenadas, ordenadas por versión ascendente.
        """
        return (
            self.db.query(models.SignedRoot)
            .order_by(models.SignedRoot.tree_version.asc(), models.SignedRoot.id.asc())
            .all()
        )

    def get_latest_tree_version(self) -> int:
        latest_root = (
            self.db.query(models.SignedRoot)
            .order_by(
                models.SignedRoot.tree_version.desc(),
                models.SignedRoot.id.desc(),
            )
            .first()
        )

        if latest_root is None:
            return 0

        return cast(int, latest_root.tree_version)