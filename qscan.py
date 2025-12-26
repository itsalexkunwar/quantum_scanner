import argparse
import ast
import json
import os
from dataclasses import dataclass
from typing import Optional, Iterable


@dataclass(frozen=True)
class Finding:
    file_path: str
    line_number: int
    kind: str
    match: str
    message: str


CRYPTO_IMPORT_PREFIXES = {
    "hashlib",
    "ssl",
    "hmac",
    "secrets",
    "cryptography",
    "Crypto",
    "OpenSSL",
}

CALL_RULES = {
    "hashlib.md5": ("broken_now", "MD5 is broken and should not be used for security purposes."),
    "hashlib.sha1": ("broken_now", "SHA1 is broken and should not be used for security purposes."),
    "ssl.PROTOCOL_TLSv1": ("obsolete_now", "TLS 1.0 is obsolete and should not be used."),
    "ssl.PROTOCOL_TLSv1_1": ("obsolete_now", "TLS 1.1 is obsolete and should not be used."),
}

PREFIX_CALL_RULES = {
    "cryptography.hazmat.primitives.asymmetric.rsa": (
        "quantum_vulnerable",
        "RSA is vulnerable to future quantum attacks. Plan migration to PQC.",
    ),
    "cryptography.hazmat.primitives.asymmetric.ec": (
        "quantum_vulnerable",
        "Elliptic curve crypto is vulnerable to future quantum attacks. Plan migration to PQC.",
    ),
    "Crypto.PublicKey.RSA": (
        "quantum_vulnerable",
        "RSA is vulnerable to future quantum attacks. Plan migration to PQC.",
    ),
}

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    ".idea",
    ".vscode",
}


def should_skip_dir(dir_name: str, excludes: set[str]) -> bool:
    return dir_name in excludes


def iter_python_files(root: str, excludes: set[str]) -> list[str]:
    paths: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d, excludes)]
        for name in filenames:
            if name.endswith(".py"):
                paths.append(os.path.join(dirpath, name))
    return paths


def get_full_attr_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = get_full_attr_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


class PythonCryptoVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[Finding] = []
        self.alias_map: dict[str, str] = {}

    def add(self, line: int, kind: str, match: str, message: str) -> None:
        self.findings.append(
            Finding(
                file_path=self.file_path,
                line_number=line,
                kind=kind,
                match=match,
                message=message,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name.split(".")[0]
            self.alias_map[asname] = name

            top = name.split(".")[0]
            if top in CRYPTO_IMPORT_PREFIXES:
                self.add(
                    node.lineno,
                    "import",
                    name,
                    "Imports cryptography related module.",
                )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        top = module.split(".")[0] if module else ""

        for alias in node.names:
            imported = alias.name
            asname = alias.asname or imported
            full = f"{module}.{imported}" if module else imported
            self.alias_map[asname] = full

            if top in CRYPTO_IMPORT_PREFIXES or imported in CRYPTO_IMPORT_PREFIXES:
                self.add(
                    node.lineno,
                    "import_from",
                    full,
                    "Imports cryptography related symbol.",
                )

    def resolve_name(self, dotted: str) -> str:
        parts = dotted.split(".")
        if not parts:
            return dotted
        head = parts[0]
        if head in self.alias_map:
            expanded = self.alias_map[head]
            rest = parts[1:]
            if rest:
                return expanded + "." + ".".join(rest)
            return expanded
        return dotted

    def visit_Call(self, node: ast.Call) -> None:
        fn = get_full_attr_name(node.func)
        if fn is None:
            self.generic_visit(node)
            return

        resolved = self.resolve_name(fn)

        if resolved in CALL_RULES:
            kind, msg = CALL_RULES[resolved]
            self.add(node.lineno, kind, resolved, msg)

        for prefix, (kind, msg) in PREFIX_CALL_RULES.items():
            if resolved.startswith(prefix):
                self.add(node.lineno, kind, resolved, msg)
                break

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        full = get_full_attr_name(node)
        if full is None:
            self.generic_visit(node)
            return

        resolved = self.resolve_name(full)

        if resolved in CALL_RULES:
            kind, msg = CALL_RULES[resolved]
            self.add(node.lineno, kind, resolved, msg)

        self.generic_visit(node)


def scan_python_file(path: str) -> list[Finding]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            src = f.read()
    except OSError:
        return []

    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError:
        return []

    visitor = PythonCryptoVisitor(path)
    visitor.visit(tree)
    return visitor.findings


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, int, str, str, str], Finding] = {}
    for f in findings:
        key = (f.file_path, f.line_number, f.kind, f.match, f.message)
        unique[key] = f
    return list(unique.values())


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.kind] = counts.get(f.kind, 0) + 1
    return counts

BROKEN_KINDS = {"broken_now", "obsolete_now"}

def has_blocking(findings: Iterable[Finding]) -> int:
    blocking_kinds = {"broken_now", "obsolete_now"}
    for f in findings:
        if f.kind in BROKEN_KINDS:
            return 1
    return 0


def findings_to_json(findings: list[Finding]) -> list[dict]:
    out: list[dict] = []
    for f in findings:
        out.append(
            {
                "file_path": f.file_path,
                "line_number": f.line_number,
                "kind": f.kind,
                "match": f.match,
                "message": f.message,
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(prog="qscan", description="Week 3 Python crypto scanner.")
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output machine readable JSON",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to exclude from scanning. Can be used multiple times.",
    )
    args = parser.parse_args()

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"Path is not a directory: {root}")
        return 2

    excludes = set(DEFAULT_EXCLUDE_DIRS)
    for d in args.exclude_dir:
        if d:
            excludes.add(d)

    files = iter_python_files(root, excludes)
    all_findings: list[Finding] = []
    for p in files:
        all_findings.extend(scan_python_file(p))

    unique_findings = dedupe_findings(all_findings)
    unique_findings.sort(key=lambda x: (x.file_path, x.line_number, x.kind, x.match))

    if args.json_output:
        payload = {
            "root": root,
            "file_count": len(files),
            "finding_count": len(unique_findings),
            "summary": summarize(unique_findings),
            "findings": findings_to_json(unique_findings),
        }
        print(json.dumps(payload, indent=2))
        return 1 if has_blocking(unique_findings) else 0

    if not unique_findings:
        print("No crypto related findings found.")
        return 0

    counts = summarize(unique_findings)
    
    total_from_summary = sum(counts.values())
    if total_from_summary != len(unique_findings):
        print("Internal error: summary does not match findings")
        return 2

    print("Summary")
    for k in sorted(counts.keys()):
        print(f"  {k}: {counts[k]}")
    print()
    print(f"Scanned files: {len(files)}")
    print(f"Findings: {len(unique_findings)}")
    print()

    for f in unique_findings:
        print(f"{f.file_path}:{f.line_number} [{f.kind}] {f.match} -> {f.message}")

    return 1 if has_blocking(unique_findings) else 0

if __name__ == "__main__":
    raise SystemExit(main())
