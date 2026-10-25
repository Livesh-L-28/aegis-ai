"""Focused regression tests for JavaScript and TypeScript dependency graph and cycle analysis."""

from pathlib import Path

from packages.review.analyzer.dependency_graph import DependencyGraph


def test_ts_circular_dependency_detection(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Create cycle between a.ts and b.ts
    file_a = src_dir / "serviceA.ts"
    file_b = src_dir / "serviceB.ts"

    file_a.write_text("import { bFunc } from './serviceB';\nexport function aFunc() {}\n", encoding="utf-8")
    file_b.write_text("import { aFunc } from './serviceA';\nexport function bFunc() {}\n", encoding="utf-8")

    graph = DependencyGraph(repo_root=tmp_path)
    graph.build_graph(files=["src/serviceA.ts", "src/serviceB.ts"])

    cycles = graph.find_cycles()
    assert len(cycles) == 1
    cycle = cycles[0]
    assert cycle.length == 2
    assert "src.serviceA" in cycle.modules
    assert "src.serviceB" in cycle.modules
    assert "serviceA" in cycle.display_path
    assert "serviceB" in cycle.display_path


def test_ts_transitive_cycle_detection(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # 3-node cycle: x -> y -> z -> x
    (src_dir / "x.ts").write_text("import './y';\n", encoding="utf-8")
    (src_dir / "y.ts").write_text("import './z';\n", encoding="utf-8")
    (src_dir / "z.ts").write_text("import './x';\n", encoding="utf-8")

    graph = DependencyGraph(repo_root=tmp_path)
    graph.build_graph(files=["src/x.ts", "src/y.ts", "src/z.ts"])

    cycles = graph.find_cycles()
    assert len(cycles) == 1
    assert cycles[0].length == 3


def test_ts_conservative_resolution_no_false_dependencies(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Imports external packages and unresolvable relative import
    comp = src_dir / "Component.tsx"
    comp.write_text(
        """
import React, { useState } from 'react';
import { debounce } from 'lodash';
import axios from 'axios';
import { missing } from './non_existent_file';

export function Component() { return null; }
""",
        encoding="utf-8",
    )

    graph = DependencyGraph(repo_root=tmp_path)
    graph.build_graph(files=["src/Component.tsx"])

    # No internal modules should be linked because react, lodash, axios, and missing file are external/unresolvable
    assert len(graph.internal_import_graph.get("src.Component", set())) == 0
    assert len(graph.find_cycles()) == 0


def test_ts_index_file_and_extension_resolution(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    components_dir = src_dir / "components"
    components_dir.mkdir(parents=True)

    # index.tsx inside directory
    (components_dir / "index.tsx").write_text("export const Button = () => null;\n", encoding="utf-8")
    # utils.ts without extension in import
    (src_dir / "utils.ts").write_text("export const add = (a: number, b: number) => a + b;\n", encoding="utf-8")

    app = src_dir / "App.tsx"
    app.write_text(
        """
import { Button } from './components';
import { add } from './utils';

export function App() { return null; }
""",
        encoding="utf-8",
    )

    graph = DependencyGraph(repo_root=tmp_path)
    graph.build_graph(files=["src/App.tsx", "src/components/index.tsx", "src/utils.ts"])

    app_targets = graph.internal_import_graph.get("src.App", set())
    assert "src.components" in app_targets or "src.components.index" in app_targets
    assert "src.utils" in app_targets


def test_tsconfig_paths_alias_and_base_url_resolution(tmp_path: Path) -> None:
    """Verifies that tsconfig.json baseUrl and paths aliases are resolved conservatively."""
    import json

    tsconfig = {
        "compilerOptions": {
            "baseUrl": "./src",
            "paths": {
                "@components/*": ["components/*"],
                "@utils/*": ["utils/*"],
                "@/*": ["*"],
            },
        }
    }
    (tmp_path / "tsconfig.json").write_text(json.dumps(tsconfig), encoding="utf-8")

    src = tmp_path / "src"
    comps = src / "components"
    utils = src / "utils"
    views = src / "views"
    comps.mkdir(parents=True)
    utils.mkdir(parents=True)
    views.mkdir(parents=True)

    (comps / "Header.tsx").write_text("export const Header = () => null;\n", encoding="utf-8")
    (utils / "math.ts").write_text("export const sum = (a: number, b: number) => a + b;\n", encoding="utf-8")
    (views / "Home.tsx").write_text(
        """
import { Header } from '@components/Header';
import { sum } from '@utils/math';
import { external } from '@nonexistent/lib';

export function Home() { return null; }
""",
        encoding="utf-8",
    )

    graph = DependencyGraph(repo_root=tmp_path)
    graph.build_graph(
        files=[
            "src/views/Home.tsx",
            "src/components/Header.tsx",
            "src/utils/math.ts",
        ]
    )

    home_deps = graph.internal_import_graph.get("src.views.Home", set())
    assert "src.components.Header" in home_deps
    assert "src.utils.math" in home_deps
    # Nonexistent alias/import must NOT be invented
    assert "src.nonexistent.lib" not in home_deps
    assert "@nonexistent/lib" not in home_deps


def test_tsconfig_ambiguous_alias_precedence(tmp_path: Path) -> None:
    """Most specific path alias prefix must take precedence over broader wildcards."""
    import json

    tsconfig = {
        "compilerOptions": {
            "baseUrl": ".",
            "paths": {
                "@app/core/*": ["packages/core/*"],
                "@app/*": ["packages/general/*"],
            },
        }
    }
    (tmp_path / "tsconfig.json").write_text(json.dumps(tsconfig), encoding="utf-8")

    core_dir = tmp_path / "packages" / "core"
    gen_dir = tmp_path / "packages" / "general"
    core_dir.mkdir(parents=True)
    gen_dir.mkdir(parents=True)

    (core_dir / "engine.ts").write_text("export const engine = 1;\n", encoding="utf-8")
    (gen_dir / "engine.ts").write_text("export const engine = 2;\n", encoding="utf-8")

    entry = tmp_path / "main.ts"
    entry.write_text("import { engine } from '@app/core/engine';\n", encoding="utf-8")

    graph = DependencyGraph(repo_root=tmp_path)
    graph.build_graph(files=["main.ts", "packages/core/engine.ts", "packages/general/engine.ts"])

    main_deps = graph.internal_import_graph.get("main", set())
    # Should resolve to core.engine, not general.engine
    assert "packages.core.engine" in main_deps
    assert "packages.general.engine" not in main_deps


def test_polyglot_cycles_and_multiple_extensions(tmp_path: Path) -> None:
    """Verifies cycle detection in repositories containing both Python and TypeScript cycles."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "__init__.py").write_text("", encoding="utf-8")

    # Python cycle
    (src / "py_a.py").write_text("import src.py_b\nclass PyA: pass\n", encoding="utf-8")
    (src / "py_b.py").write_text("import src.py_a\nclass PyB: pass\n", encoding="utf-8")

    # TypeScript cycle
    (src / "ts_a.ts").write_text("import './ts_b';\nexport const a = 1;\n", encoding="utf-8")
    (src / "ts_b.ts").write_text("import './ts_a';\nexport const b = 2;\n", encoding="utf-8")

    graph = DependencyGraph(repo_root=tmp_path)
    graph.build_graph(files=["src/py_a.py", "src/py_b.py", "src/ts_a.ts", "src/ts_b.ts"])

    cycles = graph.find_cycles()
    # Expect 2 distinct cycles: 1 Python, 1 TypeScript
    assert len(cycles) == 2
    cycle_modules = [set(c.modules) for c in cycles]
    assert {"src.py_a", "src.py_b"} in cycle_modules
    assert {"src.ts_a", "src.ts_b"} in cycle_modules

