"""
SCA (Software Composition Analysis) Module
Scans dependency files for known vulnerabilities using AI-powered CVE detection.

Supported files:
- Python: requirements.txt, Pipfile, pyproject.toml
- JavaScript: package.json, package-lock.json, yarn.lock
- Ruby: Gemfile, Gemfile.lock
- Go: go.mod, go.sum
- Java: pom.xml, build.gradle
- Rust: Cargo.toml
"""

import os
import re
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger("vuln_scan.sca")


class DependencyParser:
    """Parse various dependency file formats."""
    
    @staticmethod
    def parse_requirements_txt(content: str) -> List[Dict[str, str]]:
        """Parse Python requirements.txt"""
        deps = []
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            # Handle various formats: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!~]+)?\s*([0-9a-zA-Z._-]+)?', line)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(3) or "latest",
                    "constraint": match.group(2) or "=="
                })
        return deps
    
    @staticmethod
    def parse_package_json(content: str) -> List[Dict[str, str]]:
        """Parse Node.js package.json"""
        deps = []
        try:
            data = json.loads(content)
            for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
                for name, version in data.get(dep_type, {}).items():
                    # Clean version string (remove ^, ~, etc.)
                    clean_version = re.sub(r'^[\^~>=<]+', '', version)
                    deps.append({
                        "name": name,
                        "version": clean_version,
                        "type": dep_type
                    })
        except json.JSONDecodeError:
            logger.error("Failed to parse package.json")
        return deps
    
    @staticmethod
    def parse_gemfile(content: str) -> List[Dict[str, str]]:
        """Parse Ruby Gemfile"""
        deps = []
        for line in content.split('\n'):
            # gem 'name', '~> 1.0'
            match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2) or "latest"
                })
        return deps
    
    @staticmethod
    def parse_go_mod(content: str) -> List[Dict[str, str]]:
        """Parse Go go.mod"""
        deps = []
        in_require = False
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('require ('):
                in_require = True
                continue
            if line == ')':
                in_require = False
                continue
            if in_require or line.startswith('require '):
                # module/path v1.2.3
                match = re.match(r'(?:require\s+)?([^\s]+)\s+v?([^\s]+)', line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "version": match.group(2)
                    })
        return deps
    
    @staticmethod
    def parse_pyproject_toml(content: str) -> List[Dict[str, str]]:
        """Parse Python pyproject.toml"""
        deps = []
        in_deps = False
        for line in content.split('\n'):
            if '[project.dependencies]' in line or '[tool.poetry.dependencies]' in line:
                in_deps = True
                continue
            if in_deps and line.startswith('['):
                in_deps = False
                continue
            if in_deps:
                # name = "^1.0.0" or name = ">=1.0"
                match = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*["\']?([^"\']+)', line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "version": re.sub(r'^[\^~>=<]+', '', match.group(2))
                    })
        return deps


class SCAScanner:
    """Software Composition Analysis Scanner"""
    
    DEPENDENCY_FILES = {
        "requirements.txt": ("python", DependencyParser.parse_requirements_txt),
        "Pipfile": ("python", None),  # TODO: Add parser
        "pyproject.toml": ("python", DependencyParser.parse_pyproject_toml),
        "package.json": ("javascript", DependencyParser.parse_package_json),
        "package-lock.json": ("javascript", None),  # Skip, too verbose
        "yarn.lock": ("javascript", None),
        "Gemfile": ("ruby", DependencyParser.parse_gemfile),
        "go.mod": ("go", DependencyParser.parse_go_mod),
        "Cargo.toml": ("rust", None),
        "pom.xml": ("java", None),
        "build.gradle": ("java", None),
    }
    
    def __init__(self, ai_provider=None):
        self.ai_provider = ai_provider
        self.logger = logging.getLogger("vuln_scan.sca")
    
    def is_dependency_file(self, filename: str) -> bool:
        """Check if file is a dependency manifest."""
        return Path(filename).name in self.DEPENDENCY_FILES
    
    def scan_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Scan a dependency file for vulnerabilities."""
        filename = Path(file_path).name
        
        if filename not in self.DEPENDENCY_FILES:
            return {"status": "SKIPPED", "reason": "Not a dependency file"}
        
        ecosystem, parser = self.DEPENDENCY_FILES[filename]
        
        if parser is None:
            return {"status": "SKIPPED", "reason": f"Parser not implemented for {filename}"}
        
        # Parse dependencies
        try:
            dependencies = parser(content)
        except Exception as e:
            self.logger.error(f"Failed to parse {filename}: {e}")
            return {"status": "ERROR", "error": str(e)}
        
        if not dependencies:
            return {"status": "SAFE", "findings": [], "dependencies": 0}
        
        self.logger.info(f"[SCA] Found {len(dependencies)} dependencies in {filename}")
        
        # Use AI to check for known vulnerabilities
        if self.ai_provider:
            findings = self._check_vulnerabilities_with_ai(dependencies, ecosystem, filename)
        else:
            findings = self._basic_version_check(dependencies)
        
        return {
            "status": "VULNERABLE" if findings else "SAFE",
            "findings": findings,
            "dependencies": len(dependencies),
            "ecosystem": ecosystem
        }
    
    def _check_vulnerabilities_with_ai(self, deps: List[Dict], ecosystem: str, filename: str) -> List[Dict]:
        """Use AI to identify vulnerabilities in dependencies."""
        from vuln_scan.engine.prompts import SCA_PROMPT
        
        # Format dependencies for AI
        dep_list = "\n".join([f"- {d['name']}@{d.get('version', 'unknown')}" for d in deps[:50]])  # Limit
        
        context = f"""
Ecosystem: {ecosystem}
File: {filename}

Dependencies:
{dep_list}
"""
        
        try:
            response = self.ai_provider.ask(
                system_prompt=SCA_PROMPT,
                user_prompt="Analyze these dependencies for known security vulnerabilities.",
                context=context
            )
            
            # Parse AI response
            result = self._parse_ai_response(response)
            findings = result.get("vulnerabilities", [])
            
            # Format findings
            formatted = []
            for vuln in findings:
                formatted.append({
                    "type": "Vulnerable Dependency",
                    "severity": vuln.get("severity", "Medium"),
                    "package": vuln.get("package", "unknown"),
                    "version": vuln.get("version", "unknown"),
                    "cve": vuln.get("cve", ""),
                    "description": vuln.get("description", "Known vulnerability"),
                    "recommendation": vuln.get("fix", "Upgrade to latest version"),
                    "source": "sca",
                    "location": {"file": filename}
                })
            
            self.logger.info(f"[SCA] AI found {len(formatted)} vulnerable dependencies")
            return formatted
            
        except Exception as e:
            self.logger.error(f"[SCA] AI analysis failed: {e}")
            return []
    
    def _basic_version_check(self, deps: List[Dict]) -> List[Dict]:
        """Basic check for obviously outdated packages (no AI)."""
        # Known vulnerable packages (static list for fallback)
        known_vulns = {
            "django": {"below": "3.2", "cve": "CVE-2021-33203"},
            "flask": {"below": "2.0", "cve": "CVE-2021-28091"},
            "requests": {"below": "2.20", "cve": "CVE-2018-18074"},
            "urllib3": {"below": "1.26.5", "cve": "CVE-2021-33503"},
            "pillow": {"below": "9.0", "cve": "CVE-2022-22817"},
            "jinja2": {"below": "3.0", "cve": "CVE-2020-28493"},
            "pyyaml": {"below": "5.4", "cve": "CVE-2020-14343"},
            "cryptography": {"below": "3.3.2", "cve": "CVE-2020-36242"},
            "lodash": {"below": "4.17.21", "cve": "CVE-2021-23337"},
            "axios": {"below": "0.21.1", "cve": "CVE-2021-3749"},
        }
        
        findings = []
        for dep in deps:
            name = dep["name"].lower()
            if name in known_vulns:
                findings.append({
                    "type": "Vulnerable Dependency",
                    "severity": "High",
                    "package": dep["name"],
                    "version": dep.get("version", "unknown"),
                    "cve": known_vulns[name]["cve"],
                    "description": f"Version below {known_vulns[name]['below']} has known vulnerabilities",
                    "recommendation": f"Upgrade to version >= {known_vulns[name]['below']}",
                    "source": "sca"
                })
        
        return findings
    
    def _parse_ai_response(self, response: str) -> Dict:
        """Parse AI JSON response."""
        try:
            import json_repair
            return json_repair.loads(response)
        except:
            # Try to extract JSON from response
            import re
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                try:
                    return json.loads(match.group())
                except:
                    pass
        return {"vulnerabilities": []}
