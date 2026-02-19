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


BROKEN_KINDS = {"broken_now", "obsolete_now"}
OUTPUT_CATEGORY_ORDER = ["broken", "obsolete_tls", "quantum_vulnerable", "import"]

def kind_to_category(kind: str) -> str:
    if kind == "broken_now":
        return "broken"
    if kind == "obsolete_now":
        return "obsolete_tls"
    if kind == "quantum_vulnerable":
        return "quantum_vulnerable"
    if kind in ("import", "import_from"):
        return "import"
    return "import"

def has_blocking(findings: Iterable[Finding]) -> int:
    for f in findings:
        if f.kind in BROKEN_KINDS:
            return 1
    return 0



def build_report(root: str, files: list[str], findings: list[Finding], exit_code: int) -> dict:
    counts_by_category = {k: 0 for k in OUTPUT_CATEGORY_ORDER}
    for f in findings:
        cat = kind_to_category(f.kind)
        if cat in counts_by_category:
            counts_by_category[cat] += 1

    report = {
        "schema_version": "1.0",
        "tool": {
            "name": "qscan",
            "version": "0.0.0",
        },
        "target": {
            "path": root,
        },
        "summary": {
            "counts_by_category": counts_by_category,
            "findings_total": len(findings),
            "exit_code": exit_code,
        },
        "stats": {
            "python_files_scanned": len(files),
        },
        "findings": [
            {
                "file_path": f.file_path,
                "line_number": f.line_number,
                "category": kind_to_category(f.kind),
                "kind": f.kind,
                "match": f.match,
                "message": f.message,
            }
            for f in findings
        ],
    }
    return report


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def render_text(report: dict) -> str:
    lines: list[str] = []
    lines.append("Cryptography Inventory and Quantum Readiness Scanner")
    lines.append(f"Target: {report['target']['path']}")
    lines.append(f"Python files scanned: {report['stats']['python_files_scanned']}")
    lines.append(f"Findings: {report['summary']['findings_total']}")
    lines.append("")
    lines.append("Summary")
    counts = report["summary"]["counts_by_category"]
    lines.append(f"  Broken: {counts['broken']}")
    lines.append(f"  Obsolete TLS: {counts['obsolete_tls']}")
    lines.append(f"  Quantum vulnerable: {counts['quantum_vulnerable']}")
    lines.append(f"  Imports: {counts['import']}")
    lines.append("")
    lines.append(f"Exit code: {report['summary']['exit_code']}")
    lines.append("")

    findings = report["findings"]
    if not findings:
        lines.append("No crypto related findings found.")
        return "\n".join(lines)

    lines.append("Findings")
    lines.append("")

    current_file: Optional[str] = None
    for item in findings:
        fp = item["file_path"]
        if fp != current_file:
            if current_file is not None:
                lines.append("")
            lines.append(fp)
            current_file = fp

        line_no = item["line_number"]
        cat = item["category"]
        match = item["match"]
        msg = item["message"]
        lines.append(f"  L{line_no}  {cat}  {match}  {msg}")

    return "\n".join(lines)


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

    exit_code = 1 if has_blocking(unique_findings) else 0
    
    report = build_report(root, files, unique_findings, exit_code)

    total_from_summary = sum(report["summary"]["counts_by_category"].values())
    if total_from_summary != report["summary"]["findings_total"]:
        print("Internal error: summary does not match findings")
        return 2

    if args.json_output:
        print(render_json(report))
        return exit_code

    print(render_text(report))
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
