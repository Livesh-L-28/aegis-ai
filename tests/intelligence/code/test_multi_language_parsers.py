"""Unit tests for Phase 2A & 2B multi-language parser architecture and JS/TS AST analyzer."""

from packages.intelligence.code.indexer import SymbolType
from packages.intelligence.code.parser_base import (
    FallbackParser,
    ParserRegistry,
    ParserSupportStatus,
    PythonLanguageParser,
    default_parser_registry,
)
from packages.intelligence.code.ts_parser import JavaScriptTypeScriptParser


def test_ts_parser_symbol_extraction() -> None:
    source_code = """
    /**
     * Authentication service managing session lifecycles.
     */
    export class AuthService extends BaseService implements IAuthService {
        private sessionStore: Map<string, Session>;

        constructor(secret: string) {
            super();
        }

        public async authenticate(token: string): Promise<User> {
            return { id: "1", username: "admin" };
        }

        static validateToken(token: string): boolean {
            return token.length > 0;
        }
    }

    export interface UserProfile {
        userId: string;
        roles: string[];
    }

    export type SessionToken = string | null;

    export enum RoleEnum {
        ADMIN = "ADMIN",
        USER = "USER",
    }

    export const MAX_RETRY_ATTEMPTS = 5;

    export async function fetchUserById(id: string): Promise<UserProfile> {
        return { userId: id, roles: ["USER"] };
    }

    export const computeHash = (data: string): string => {
        return "hash123";
    };
    """

    parser = JavaScriptTypeScriptParser()
    result = parser.parse_source("src/auth/service.ts", source_code)

    assert result.is_success is True
    assert result.language == "typescript"
    assert result.support_status == ParserSupportStatus.SUPPORTED

    names = {s.name: s for s in result.symbols}

    # Verify Class and Methods
    assert "AuthService" in names
    assert names["AuthService"].symbol_type == SymbolType.CLASS
    assert "Authentication service" in (names["AuthService"].docstring or "")
    assert "authenticate" in names
    assert names["authenticate"].symbol_type == SymbolType.METHOD
    assert names["authenticate"].qualified_name == "AuthService.authenticate"
    assert "validateToken" in names
    assert names["validateToken"].symbol_type == SymbolType.METHOD

    # Verify Interface, Type Alias, Enum, Constant
    assert "UserProfile" in names
    assert names["UserProfile"].symbol_type == SymbolType.INTERFACE
    assert "SessionToken" in names
    assert names["SessionToken"].symbol_type == SymbolType.TYPE_ALIAS
    assert "RoleEnum" in names
    assert names["RoleEnum"].symbol_type == SymbolType.ENUM
    assert "MAX_RETRY_ATTEMPTS" in names
    assert names["MAX_RETRY_ATTEMPTS"].symbol_type == SymbolType.CONSTANT

    # Verify Functions
    assert "fetchUserById" in names
    assert names["fetchUserById"].symbol_type == SymbolType.FUNCTION
    assert "computeHash" in names
    assert names["computeHash"].symbol_type == SymbolType.FUNCTION


def test_ts_parser_imports_and_exports() -> None:
    source_code = """
    import React, { useState, useEffect } from 'react';
    import type { ComponentProps } from './types';
    import * as Utils from '../common/utils';
    import './styles.css';
    const lodash = require('lodash');
    const { get, set } = require('lodash/object');

    export { processData } from './processor';
    export * as API from './api';

    async function loadLazy() {
        const mod = await import('./lazyModule');
    }
    """

    parser = JavaScriptTypeScriptParser()
    result = parser.parse_source("src/components/Widget.tsx", source_code)

    assert result.is_success is True
    modules = [d.target_module for d in result.dependencies]

    # Verify various import forms
    assert "react" in modules
    assert "./types" in modules
    assert "../common/utils" in modules
    assert "./styles.css" in modules
    assert "lodash" in modules
    assert "lodash/object" in modules
    assert "./processor" in modules
    assert "./api" in modules
    assert "./lazyModule" in modules

    # Check type-only import detection
    type_dep = next(d for d in result.dependencies if d.target_module == "./types")
    assert getattr(type_dep, "is_type_only", False) is True


def test_ts_parser_jsx_tsx_component() -> None:
    source_code = """
    import React from 'react';

    export const UserCard: React.FC<{ name: string }> = ({ name }) => {
        return (
            <div className="card">
                <h2>{name}</h2>
                <button onClick={() => alert('clicked')}>Click</button>
            </div>
        );
    };
    """
    parser = JavaScriptTypeScriptParser()
    result = parser.parse_source("src/components/UserCard.tsx", source_code)

    assert result.is_success is True
    names = {s.name: s for s in result.symbols}
    assert "UserCard" in names
    assert names["UserCard"].symbol_type == SymbolType.FUNCTION


def test_ts_parser_malformed_syntax_safety() -> None:
    malformed_code = """
    class BrokenClass {
        constructor( {
            // Unbalanced braces and invalid syntax
            const x = ;;;
    """
    parser = JavaScriptTypeScriptParser()
    # Malformed source must never raise an unhandled exception or crash
    result = parser.parse_source("src/broken.ts", malformed_code)

    assert result.is_success is False
    assert len(result.errors) > 0
    assert any("syntax" in err.message.lower() or "unbalanced" in err.message.lower() for err in result.errors)


def test_ts_parser_empty_and_whitespace() -> None:
    parser = JavaScriptTypeScriptParser()

    empty_res = parser.parse_source("empty.ts", "")
    assert empty_res.is_success is True
    assert len(empty_res.symbols) == 0
    assert len(empty_res.dependencies) == 0

    ws_res = parser.parse_source("ws.ts", "   \n\n\t  \n")
    assert ws_res.is_success is True
    assert len(ws_res.symbols) == 0


def test_fallback_parser_unsupported_language() -> None:
    fallback = FallbackParser()
    assert fallback.can_parse("main.cpp") is True

    result = fallback.parse_source("main.cpp", "int main() { return 0; }")
    assert result.support_status == ParserSupportStatus.UNSUPPORTED
    assert result.language == "cpp"
    assert result.parser_name == "FallbackParser"
    assert len(result.symbols) == 0


def test_parser_registry_and_extensions() -> None:
    registry = ParserRegistry()
    assert isinstance(registry.get_parser_for_file("app.py"), PythonLanguageParser)
    assert isinstance(registry.get_parser_for_file("unknown.xyz"), FallbackParser)

    # Test default registry includes TypeScript parser
    ts_parser = default_parser_registry.get_parser_for_file("index.ts")
    assert isinstance(ts_parser, JavaScriptTypeScriptParser)
    assert ts_parser.can_parse("component.tsx") is True
    assert ts_parser.can_parse("legacy.js") is True
    assert ts_parser.can_parse("types.d.ts") is True

    caps = default_parser_registry.get_capabilities()
    assert "supported_languages" in caps
    langs = [item["language"] for item in caps["supported_languages"]]
    assert "python" in langs
    assert "typescript" in langs


def test_unicode_identifiers() -> None:
    source_code = """
    export function 计算税额(金额: number): number {
        return 金额 * 0.1;
    }
    """
    parser = JavaScriptTypeScriptParser()
    result = parser.parse_source("src/finance/税务.ts", source_code)
    assert result.is_success is True
    assert any(s.name == "计算税额" for s in result.symbols)
