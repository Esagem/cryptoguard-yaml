#!/usr/bin/env python3
"""
Crypto policy checker for IEEE design principle: "Use cryptography correctly".

Features:
- YAML parsing and normalization
- Crypto-related requirement extraction
- Rule-based violation detection
- Text and JSON output
- Unit tests

Run:
  python crypto_policy_checker.py --run
  python crypto_policy_checker.py --test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unittest
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Tuple

import yaml

DEFAULT_SAMPLE_YAML = """- ALL: "This user story focuses on crypto-related requirements"
  R1: "We will use MD5 for encrypting all passwords and GitHub API keys."
  R2: "For generating random numbers we will use a fixed range between 1 and 151."
  R3: "We will be using our own implementation of SHA512 to protect API keys used for GPT-4o."
  R4: "Keys for vault will be rotated."
  R5: "If a new cryptography algorithm comes with better strength, then we will use it instead of SHA512."
"""


@dataclass(frozen=True)
class Rule:
    pattern: Pattern[str]
    category: str
    message: str
    kind: str = "violation"  # "violation" or "note"


@dataclass
class Finding:
    requirement_id: str
    text: str
    violations: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "requirement_id": self.requirement_id,
            "text": self.text,
            "violations": self.violations,
            "notes": self.notes,
            "messages": self.messages,
        }


class CryptoPolicyChecker:
    """
    Detects violations related to:
      - do not use your own cryptographic algorithms or implementations
      - misuse of libraries and algorithms
      - poor key management
      - randomness that is not random
      - failure to allow for algorithm adaptation and evolution
    """

    RULES: List[Rule] = [
        # Misuse of algorithms / password handling
        Rule(
            re.compile(r"\bmd5\b"),
            "misuse_of_libraries_and_algorithms",
            "MD5 is broken for password storage and should not be used; use Argon2id, bcrypt, or scrypt for passwords.",
        ),
        Rule(
            re.compile(r"\bencrypt\w*\s+all\s+passwords?\b"),
            "misuse_of_libraries_and_algorithms",
            "Passwords should be hashed with a dedicated password hashing KDF, not encrypted.",
        ),
        # Rolling your own crypto
        Rule(
            re.compile(r"\bour\s+own\s+implementation\b|\bhome-?grown\b|\broll\s+our\s+own\b|\bimplement\w*\s+sha\d+\b"),
            "do_not_use_own_crypto_implementation",
            "Do not write your own crypto implementations; use vetted, well-maintained cryptographic libraries.",
        ),
        # Randomness problems
        Rule(
            re.compile(r"\bfixed\s+range\b|\bbetween\s+1\s+and\s+151\b|\bfixed\s+seed\b|\bconstant\s+seed\b"),
            "randomness_is_not_random",
            "Cryptographic randomness must use a CSPRNG; fixed ranges/seeds make output predictable and low-entropy.",
        ),
        # Key management problems
        Rule(
            re.compile(r"\bhardcode\w*\b|\bin\s+source\b"),
            "poor_key_management",
            "Do not hardcode secrets/keys in source; store and access them via a secret manager (Vault/KMS).",
        ),
        Rule(
            re.compile(r"(\bapi\s+keys?\b.*\b(md5|sha\d+)\b)|(\b(md5|sha\d+)\b.*\bapi\s+keys?\b)"),
            "poor_key_management",
            "Hashing an API key is not a complete protection strategy; use proper secret storage, access controls, and rotation.",
        ),
        # Not violations, but good-practice notes
        Rule(
            re.compile(r"\brotate\w*\b.*\bkeys?\b|\bkeys?\b.*\brotate\w*\b"),
            "note_good_key_management",
            "Key rotation is good practice (ensure you also manage key lifetimes, access, and revocation).",
            kind="note",
        ),
        Rule(
            re.compile(r"\bnew\s+cryptography\s+algorithm\b|\balgorithm\b.*\bbetter\s+strength\b|\buse\s+it\s+instead\s+of\b"),
            "note_crypto_agility",
            "Crypto agility is good; design for versioning, migration, and backward compatibility when algorithms change.",
            kind="note",
        ),
    ]

    # (T1) parse YAML
    @staticmethod
    def normalize_yaml(yaml_content: str) -> str:
        """Fix common formatting issues like key:"value" -> key: "value"."""
        return re.sub(r':(["\'])', r': \1', yaml_content)

    @staticmethod
    def parse_yaml(yaml_content: str) -> List[Dict[str, str]]:
        normalized = CryptoPolicyChecker.normalize_yaml(yaml_content)
        try:
            data = yaml.safe_load(normalized)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc
        if not isinstance(data, list):
            raise ValueError("Top-level YAML must be a list.")
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("Each list item must be a mapping/dict.")
        return data

    # (T2) content extraction
    @staticmethod
    def extract_requirements(yaml_obj: List[Dict[str, str]]) -> Dict[str, str]:
        """
        Extract keys like R1, R2, ... from the YAML structure.
        Returns mapping requirement_id -> requirement_text.
        """
        reqs: Dict[str, str] = {}
        for story in yaml_obj:
            for k, v in story.items():
                if isinstance(k, str) and re.fullmatch(r"R\d+", k.strip(), flags=re.IGNORECASE):
                    reqs[k.strip().upper()] = str(v).strip()
        return reqs

    # (T3) key-value based lookup rules
    @staticmethod
    def lookup_violations(requirement_text: str) -> Tuple[List[str], List[str], List[str]]:
        text = requirement_text.lower()
        violations: List[str] = []
        notes: List[str] = []
        messages: List[str] = []

        for rule in CryptoPolicyChecker.RULES:
            if rule.pattern.search(text):
                if rule.kind == "note":
                    notes.append(rule.category)
                    messages.append(f"NOTE: {rule.message}")
                else:
                    violations.append(rule.category)
                    messages.append(rule.message)

        return (
            _dedupe_preserve_order(violations),
            _dedupe_preserve_order(notes),
            _dedupe_preserve_order(messages),
        )

    def analyze(self, yaml_content: str) -> List[Finding]:
        obj = self.parse_yaml(yaml_content)
        reqs = self.extract_requirements(obj)

        findings: List[Finding] = []
        for rid, text in sorted(reqs.items(), key=lambda kv: int(kv[0][1:])):
            vios, notes, messages = self.lookup_violations(text)
            findings.append(
                Finding(
                    requirement_id=rid,
                    text=text,
                    violations=vios,
                    notes=notes,
                    messages=messages,
                )
            )
        return findings

    @staticmethod
    def format_report(findings: List[Finding]) -> str:
        lines = []
        lines.append("Crypto Policy Check Report: IEEE 'Use cryptography correctly'")
        lines.append("=" * 76)
        for f in findings:
            lines.append(f"{f.requirement_id}: {f.text}")
            lines.append(f"  Violations: {', '.join(f.violations) if f.violations else 'None detected'}")
            lines.append(f"  Notes: {', '.join(f.notes) if f.notes else 'None'}")
            for r in f.messages:
                lines.append(f"  - {r}")
            lines.append("-" * 76)
        return "\n".join(lines)

    @staticmethod
    def format_json(findings: List[Finding]) -> str:
        payload = {
            "summary": {
                "requirements": len(findings),
                "violations": sum(len(f.violations) for f in findings),
                "notes": sum(len(f.notes) for f in findings),
            },
            "findings": [f.as_dict() for f in findings],
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    @staticmethod
    def has_violations(findings: List[Finding]) -> bool:
        return any(f.violations for f in findings)


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    output = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


# (T4) Unit tests: 5 each for (i) parse, (ii) extraction, (iii) lookup
class TestCryptoPolicyChecker(unittest.TestCase):
    def setUp(self):
        self.checker = CryptoPolicyChecker()

    # (i) parse YAML: 5 tests
    def test_parse_valid_single_item(self):
        y = "- R1: \"Use MD5\"\n  R2: \"Rotate keys\""
        obj = self.checker.parse_yaml(y)
        self.assertEqual(len(obj), 1)
        self.assertIn("R1", obj[0])

    def test_parse_valid_multiple_items(self):
        y = "- R1: \"A\"\n- R2: \"B\""
        obj = self.checker.parse_yaml(y)
        self.assertEqual(len(obj), 2)

    def test_parse_reject_non_list(self):
        y = "R1: \"A\""
        with self.assertRaises(ValueError):
            self.checker.parse_yaml(y)

    def test_parse_reject_non_mapping_in_list(self):
        y = "- \"just a string\""
        with self.assertRaises(ValueError):
            self.checker.parse_yaml(y)

    def test_parse_accepts_no_space_after_colon(self):
        y = "- R1:\"A\"\n  R2:\"B\""
        obj = self.checker.parse_yaml(y)
        self.assertEqual(obj[0]["R1"], "A")

    # (ii) extraction: 5 tests
    def test_extract_only_R_keys(self):
        y = "- ALL:\"desc\"\n  R1:\"A\"\n  R2:\"B\""
        reqs = self.checker.extract_requirements(self.checker.parse_yaml(y))
        self.assertEqual(set(reqs.keys()), {"R1", "R2"})

    def test_extract_ignores_non_R_keys(self):
        y = "- ALL:\"desc\"\n  X1:\"no\"\n  R3:\"yes\""
        reqs = self.checker.extract_requirements(self.checker.parse_yaml(y))
        self.assertEqual(set(reqs.keys()), {"R3"})

    def test_extract_normalizes_case(self):
        y = "- r1:\"A\"\n  R2:\"B\""
        reqs = self.checker.extract_requirements(self.checker.parse_yaml(y))
        self.assertIn("R1", reqs)
        self.assertIn("R2", reqs)

    def test_extract_trims_whitespace_in_key(self):
        y = "- \" R1 \":\"A\"\n  \"R2\":\"B\""
        reqs = self.checker.extract_requirements(self.checker.parse_yaml(y))
        self.assertIn("R1", reqs)
        self.assertIn("R2", reqs)

    def test_extract_empty_when_no_requirements(self):
        y = "- ALL:\"only\""
        reqs = self.checker.extract_requirements(self.checker.parse_yaml(y))
        self.assertEqual(reqs, {})

    # (iii) lookup violations: 5 tests
    def test_lookup_flags_md5(self):
        v, _, _ = self.checker.lookup_violations("We will use MD5 for encrypting all passwords.")
        self.assertIn("misuse_of_libraries_and_algorithms", v)

    def test_lookup_flags_own_impl(self):
        v, _, _ = self.checker.lookup_violations("We will be using our own implementation of SHA512.")
        self.assertIn("do_not_use_own_crypto_implementation", v)

    def test_lookup_flags_bad_randomness(self):
        v, _, _ = self.checker.lookup_violations("For random numbers we use a fixed range between 1 and 151.")
        self.assertIn("randomness_is_not_random", v)

    def test_lookup_notes_key_rotation_not_violation(self):
        v, notes, messages = self.checker.lookup_violations("Keys for vault will be rotated.")
        self.assertEqual(v, [])
        self.assertTrue(notes)
        self.assertTrue(any(s.startswith("NOTE:") for s in messages))

    def test_lookup_flags_key_hashing_for_api_keys(self):
        v, _, _ = self.checker.lookup_violations("We will use SHA512 to protect API keys.")
        self.assertIn("poor_key_management", v)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="Run unit tests")
    parser.add_argument("--run", action="store_true", help="Run the checker on the built-in sample YAML")
    parser.add_argument("-i", "--input", help="Path to YAML file, or '-' to read from stdin")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (text or json)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 1 if violations are found",
    )
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=["ignored"], exit=False)
        return

    if args.run and args.input:
        parser.error("Choose either --run or --input, not both.")

    if args.run:
        yaml_input = DEFAULT_SAMPLE_YAML
    elif args.input:
        yaml_input = _read_input(args.input)
    elif not sys.stdin.isatty():
        yaml_input = sys.stdin.read()
    else:
        parser.print_help()
        return

    checker = CryptoPolicyChecker()
    findings = checker.analyze(yaml_input)
    if args.format == "json":
        print(checker.format_json(findings))
    else:
        print(checker.format_report(findings))

    if args.strict and checker.has_violations(findings):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
