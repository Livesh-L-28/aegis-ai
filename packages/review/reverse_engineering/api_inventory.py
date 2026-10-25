"""Pluggable API and integration discovery engine for LogicFalcon."""

import ast
import contextlib
import re
from pathlib import Path

from packages.review.reverse_engineering.models import (
    APIInventory,
    APIRoute,
    HTTPMethod,
)

HTTP_METHODS: dict[str, HTTPMethod] = {
    "get": HTTPMethod.GET,
    "post": HTTPMethod.POST,
    "put": HTTPMethod.PUT,
    "delete": HTTPMethod.DELETE,
    "patch": HTTPMethod.PATCH,
    "options": HTTPMethod.OPTIONS,
    "head": HTTPMethod.HEAD,
}


class APIInventoryExtractor:
    """Extracts HTTP routes, methods, schemas, and auth requirements."""

    def __init__(self, repo_root: Path | str) -> None:
        self.repo_root = Path(repo_root).resolve()

    def extract_inventory(self, source_files: list[Path]) -> APIInventory:
        """Discovers all API endpoints across Python and JS/TS source files."""
        routes: list[APIRoute] = []
        frameworks: set[str] = set()
        auth_mechanisms: set[str] = set()

        for file_path in source_files:
            rel_path = str(file_path.relative_to(self.repo_root)) if file_path.is_relative_to(self.repo_root) else str(file_path)
            ext = file_path.suffix.lower()

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if ext == ".py":
                py_routes = self._extract_python_routes(content, rel_path)
                for r in py_routes:
                    routes.append(r)
                    frameworks.add(r.framework)
                    for auth in r.auth_requirements:
                        auth_mechanisms.add(auth)

            elif ext in (".js", ".ts", ".jsx", ".tsx"):
                js_routes = self._extract_js_ts_routes(content, rel_path)
                for r in js_routes:
                    routes.append(r)
                    frameworks.add(r.framework)

        return APIInventory(
            total_routes=len(routes),
            routes=sorted(routes, key=lambda r: (r.path, r.method)),
            frameworks_used=sorted(frameworks),
            auth_mechanisms=sorted(auth_mechanisms),
        )

    def _extract_python_routes(self, content: str, rel_path: str) -> list[APIRoute]:
        routes: list[APIRoute] = []
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    route = self._parse_fastapi_or_flask_decorator(dec, node, rel_path)
                    if route:
                        routes.append(route)

        return routes

    def _parse_fastapi_or_flask_decorator(
        self,
        dec: ast.expr,
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_path: str,
    ) -> APIRoute | None:
        if not isinstance(dec, ast.Call):
            return None

        func = dec.func
        # 1. FastAPI / Starlette: @app.get("/path") or @router.post("/path")
        if isinstance(func, ast.Attribute) and func.attr.lower() in HTTP_METHODS:
            method_name = func.attr.lower()
            http_method = HTTP_METHODS[method_name]

            path_val = "/"
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                path_val = dec.args[0].value

            # Check response_model keyword
            resp_schema: str | None = None
            for kw in dec.keywords:
                if kw.arg == "response_model":
                    with contextlib.suppress(Exception):
                        resp_schema = ast.unparse(kw.value)
                    if not resp_schema:
                        resp_schema = getattr(kw.value, "id", None)

            # Check parameters and default values for Depends(...) or Security(...)
            auth_reqs: list[str] = []
            req_schema: str | None = None
            auth_evidence: str | None = None

            for arg in fn_node.args.args:
                if arg.annotation:
                    annot_str = ""
                    with contextlib.suppress(Exception):
                        annot_str = ast.unparse(arg.annotation)
                    if annot_str and not annot_str.startswith(("str", "int", "bool", "float", "dict", "list", "Any", "None")):
                        req_schema = annot_str

            for default in fn_node.args.defaults + [d for d in fn_node.args.kw_defaults if d]:
                if (
                    isinstance(default, ast.Call)
                    and isinstance(default.func, ast.Name)
                    and default.func.id in ("Depends", "Security")
                ):
                    dep_name = default.func.id
                    if default.args:
                        try:
                            dep_target = ast.unparse(default.args[0])
                            dep_name = f"{default.func.id}({dep_target})"
                        except Exception:
                            dep_name = f"{default.func.id}({getattr(default.args[0], 'id', '')})"
                    auth_reqs.append(dep_name)
                    auth_evidence = f"Explicit dependency: {dep_name}"

            # Check other decorators on handler for auth (e.g. @login_required)
            for other_dec in fn_node.decorator_list:
                dec_repr = ""
                with contextlib.suppress(Exception):
                    dec_repr = ast.unparse(other_dec)
                if any(k in dec_repr.lower() for k in ("login_required", "jwt_required", "auth_required", "authenticate")):
                    auth_reqs.append(dec_repr)
                    auth_evidence = f"Auth decorator: @{dec_repr}"

            auth_detected = len(auth_reqs) > 0
            if not auth_detected:
                auth_evidence = "no authentication detected in route declaration (may be secured by gateway or middleware)"

            return APIRoute(
                path=path_val,
                method=http_method,
                handler_name=fn_node.name,
                file_path=rel_path,
                line_number=fn_node.lineno,
                framework="FastAPI",
                docstring=ast.get_docstring(fn_node),
                parameters=[a.arg for a in fn_node.args.args],
                request_schema=req_schema,
                response_schema=resp_schema,
                auth_requirements=auth_reqs,
                is_authenticated=auth_detected,
                auth_detected=auth_detected,
                auth_evidence=auth_evidence,
            )

        # 2. Flask: @app.route("/path", methods=["GET", "POST"])
        elif isinstance(func, ast.Attribute) and func.attr == "route":
            path_val = "/"
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                path_val = dec.args[0].value

            methods = [HTTPMethod.GET]
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = []
                    for el in kw.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            m_lower = el.value.lower()
                            if m_lower in HTTP_METHODS:
                                methods.append(HTTP_METHODS[m_lower])

            flask_auth_reqs: list[str] = []
            flask_auth_evidence: str | None = None
            for other_dec in fn_node.decorator_list:
                dec_repr = ""
                with contextlib.suppress(Exception):
                    dec_repr = ast.unparse(other_dec)
                if any(k in dec_repr.lower() for k in ("login_required", "jwt_required", "auth_required", "roles_accepted")):
                    flask_auth_reqs.append(dec_repr)
                    flask_auth_evidence = f"Auth decorator: @{dec_repr}"

            flask_auth_detected = len(flask_auth_reqs) > 0
            if not flask_auth_detected:
                flask_auth_evidence = "no authentication detected in route declaration (may be secured by gateway or middleware)"

            return APIRoute(
                path=path_val,
                method=methods[0] if methods else HTTPMethod.GET,
                handler_name=fn_node.name,
                file_path=rel_path,
                line_number=fn_node.lineno,
                framework="Flask",
                docstring=ast.get_docstring(fn_node),
                parameters=[a.arg for a in fn_node.args.args],
                auth_requirements=flask_auth_reqs,
                is_authenticated=flask_auth_detected,
                auth_detected=flask_auth_detected,
                auth_evidence=flask_auth_evidence,
            )

        return None

    def _extract_js_ts_routes(self, content: str, rel_path: str) -> list[APIRoute]:
        routes: list[APIRoute] = []
        # Match app.get('/api/users', ...) or router.post('/login', ...)
        route_pattern = re.compile(
            r"(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]([^)]*)",
            re.IGNORECASE,
        )

        for line_no, line in enumerate(content.splitlines(), start=1):
            m = route_pattern.search(line)
            if m:
                m_str = m.group(1).lower()
                path_str = m.group(2)
                rest = m.group(3) or ""
                method = HTTP_METHODS.get(m_str, HTTPMethod.GET)

                auth_reqs: list[str] = []
                auth_evidence: str | None = None
                if any(k in rest.lower() for k in ("auth", "passport", "verifytoken", "jwt", "requireauth")):
                    auth_reqs.append("middleware_auth")
                    auth_evidence = "Express authentication middleware in route signature"

                auth_detected = len(auth_reqs) > 0
                if not auth_detected:
                    auth_evidence = "no authentication detected in route declaration (may be secured by global middleware)"

                routes.append(
                    APIRoute(
                        path=path_str,
                        method=method,
                        handler_name=f"handler_{method.value.lower()}_{path_str.replace('/', '_')}",
                        file_path=rel_path,
                        line_number=line_no,
                        framework="Express",
                        auth_requirements=auth_reqs,
                        is_authenticated=auth_detected,
                        auth_detected=auth_detected,
                        auth_evidence=auth_evidence,
                    )
                )

        return routes
