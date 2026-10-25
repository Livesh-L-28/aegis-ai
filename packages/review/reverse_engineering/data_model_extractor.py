"""Data-model and schema reconstruction engine for LogicFalcon."""

import ast
import contextlib
from pathlib import Path

from packages.review.reverse_engineering.models import (
    DataModel,
    DataModelInventory,
    EvidenceProvenance,
    ModelField,
    ModelRelationship,
    RelationshipType,
)


class DataModelExtractor:
    """Extracts Pydantic, SQLAlchemy, and dataclass models with grounded relationships."""

    def __init__(self, repo_root: Path | str) -> None:
        self.repo_root = Path(repo_root).resolve()

    def extract_inventory(self, source_files: list[Path]) -> DataModelInventory:
        """Extracts all models and computes evidence-grounded relationships."""
        models: list[DataModel] = []

        for file_path in source_files:
            rel_path = str(file_path.relative_to(self.repo_root)) if file_path.is_relative_to(self.repo_root) else str(file_path)
            if file_path.suffix.lower() == ".py":
                models.extend(self._extract_python_models(file_path, rel_path))

        # Build relationships between discovered models
        relationships = self._discover_relationships(models)

        return DataModelInventory(
            total_models=len(models),
            models=models,
            relationships=relationships,
        )

    def _extract_python_models(self, file_path: Path, rel_path: str) -> list[DataModel]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=rel_path)
        except (OSError, SyntaxError):
            return []

        models: list[DataModel] = []
        known_model_types: dict[str, str] = {}

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                model = self._inspect_class_for_model(node, rel_path, known_model_types)
                if model:
                    models.append(model)
                    known_model_types[model.name] = model.model_type

        return models

    def _inspect_class_for_model(
        self,
        node: ast.ClassDef,
        rel_path: str,
        known_types: dict[str, str] | None = None,
    ) -> DataModel | None:
        base_names: list[str] = []
        for base_node in node.bases:
            with contextlib.suppress(Exception):
                base_names.append(ast.unparse(base_node))

        known = known_types or {}

        # Identify model type
        model_type: str | None = None
        if any("BaseModel" in b or "BaseSettings" in b for b in base_names):
            model_type = "pydantic"
        elif any(b in ("Base", "declarative_base") or b.endswith(".Base") for b in base_names):
            model_type = "sqlalchemy"
        elif any(getattr(d, "id", "") == "dataclass" for d in node.decorator_list if isinstance(d, ast.Name)):
            model_type = "dataclass"
        elif any("TypedDict" in b for b in base_names):
            model_type = "typeddict"
        else:
            # Check if it inherits from an already known model in this file
            for base_name in base_names:
                clean_b = base_name.split(".")[-1]
                if clean_b in known:
                    model_type = known[clean_b]
                    break

            # Check for SQLAlchemy __tablename__
            if not model_type:
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name) and target.id == "__tablename__":
                                model_type = "sqlalchemy"
                                break

        if not model_type:
            return None

        # Extract fields
        fields: list[ModelField] = []
        for item in node.body:
            # Pydantic / Dataclass field: x: int = 1
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                field_name = item.target.id
                type_str = "Any"
                with contextlib.suppress(Exception):
                    type_str = ast.unparse(item.annotation)

                has_default = item.value is not None
                is_req = not has_default and "Optional" not in type_str and "None" not in type_str
                default_str = None
                if item.value:
                    with contextlib.suppress(Exception):
                        default_str = ast.unparse(item.value)

                fields.append(
                    ModelField(
                        name=field_name,
                        type_annotation=type_str,
                        is_required=is_req,
                        default_value=default_str,
                    )
                )


            # SQLAlchemy Column: id = Column(Integer, primary_key=True)
            elif isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
                field_name = item.targets[0].id
                if isinstance(item.value, ast.Call):
                    call_func = getattr(item.value.func, "id", "") or getattr(item.value.func, "attr", "")
                    if call_func in ("Column", "relationship"):
                        is_pk = False
                        is_fk = False
                        fk_target = None
                        col_type = "Column"

                        for arg in item.value.args:
                            try:
                                arg_str = ast.unparse(arg)
                                if "ForeignKey" in arg_str:
                                    is_fk = True
                                    fk_target = arg_str
                                else:
                                    col_type = arg_str
                            except Exception:
                                pass

                        for kw in item.value.keywords:
                            if kw.arg == "primary_key" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                is_pk = True

                        fields.append(
                            ModelField(
                                name=field_name,
                                type_annotation=col_type,
                                is_required=is_pk,
                                is_primary_key=is_pk,
                                is_foreign_key=is_fk,
                                foreign_key_target=fk_target,
                            )
                        )

        return DataModel(
            name=node.name,
            model_type=model_type,
            file_path=rel_path,
            line_number=node.lineno,
            fields=fields,
            docstring=ast.get_docstring(node),
            base_classes=base_names,
        )

    def _discover_relationships(self, models: list[DataModel]) -> list[ModelRelationship]:
        """Discovers grounded relationships between discovered models."""
        relationships: list[ModelRelationship] = []
        model_names = {m.name for m in models}

        for model in models:
            # 1. Inheritance relationships
            for base in model.base_classes:
                clean_base = base.split(".")[-1]
                if clean_base in model_names and clean_base != model.name:
                    relationships.append(
                        ModelRelationship(
                            source_model=model.name,
                            target_model=clean_base,
                            relationship_type=RelationshipType.INHERITANCE,
                            field_name="inherits",
                            evidence=EvidenceProvenance(
                                file_path=model.file_path,
                                line_number=model.line_number,
                                code_snippet=f"class {model.name}({base}): ...",
                            ),
                        )
                    )

            # 2. Field type references (composition / one_to_many / reference)
            for field in model.fields:
                annot = field.type_annotation
                for target_name in model_names:
                    if target_name == model.name:
                        continue
                    # Check if target_name is present in type annotation
                    if target_name in annot:
                        rel_type = (
                            RelationshipType.ONE_TO_MANY
                            if ("list[" in annot.lower() or "set[" in annot.lower())
                            else RelationshipType.REFERENCE
                        )
                        relationships.append(
                            ModelRelationship(
                                source_model=model.name,
                                target_model=target_name,
                                relationship_type=rel_type,
                                field_name=field.name,
                                evidence=EvidenceProvenance(
                                    file_path=model.file_path,
                                    line_number=model.line_number,
                                    code_snippet=f"{field.name}: {field.type_annotation}",
                                ),
                            )
                        )

        return relationships
