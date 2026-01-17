"""
Taint Tracking Module
Tracks data flow from user-controlled sources to dangerous sinks.
"""

import re
import logging
from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass

logger = logging.getLogger("vuln_scan.taint")


@dataclass
class TaintSource:
    """Represents a source of user-controlled input."""
    name: str
    pattern: str
    category: str  # http, cli, file, env, network


@dataclass
class TaintSink:
    """Represents a dangerous function that shouldn't receive tainted data."""
    name: str
    pattern: str
    vulnerability: str
    cwe: str
    severity: str


class TaintTracker:
    """
    Static taint analysis for detecting data flow vulnerabilities.
    Traces user input from sources to dangerous sinks.
    """
    
    # Taint Sources - User controlled input
    SOURCES = [
        # HTTP (Django, Flask, FastAPI)
        TaintSource("request.GET", r"request\.GET\[", "http"),
        TaintSource("request.POST", r"request\.POST\[", "http"),
        TaintSource("request.body", r"request\.body", "http"),
        TaintSource("request.data", r"request\.data", "http"),
        TaintSource("request.args", r"request\.args\[", "http"),
        TaintSource("request.form", r"request\.form\[", "http"),
        TaintSource("request.json", r"request\.json", "http"),
        TaintSource("request.files", r"request\.files\[", "http"),
        TaintSource("request.values", r"request\.values\[", "http"),
        
        # CLI
        TaintSource("sys.argv", r"sys\.argv\[", "cli"),
        TaintSource("input()", r"input\s*\(", "cli"),
        TaintSource("argparse", r"args\.\w+", "cli"),
        
        # File
        TaintSource("open()", r"open\s*\([^,]+\)", "file"),
        TaintSource("file.read()", r"\.read\s*\(\s*\)", "file"),
        TaintSource("json.load()", r"json\.load\s*\(", "file"),
        
        # Environment
        TaintSource("os.environ", r"os\.environ\[", "env"),
        TaintSource("os.getenv", r"os\.getenv\s*\(", "env"),
        
        # Network
        TaintSource("socket.recv", r"\.recv\s*\(", "network"),
        TaintSource("urllib", r"urllib\.\w+\.urlopen", "network"),
    ]
    
    # Taint Sinks - Dangerous functions
    SINKS = [
        # Code Execution
        TaintSink("exec()", r"exec\s*\(", "Remote Code Execution", "CWE-94", "Critical"),
        TaintSink("eval()", r"eval\s*\(", "Remote Code Execution", "CWE-95", "Critical"),
        TaintSink("compile()", r"compile\s*\(", "Code Injection", "CWE-94", "High"),
        TaintSink("__import__()", r"__import__\s*\(", "Code Injection", "CWE-94", "High"),
        
        # Command Injection
        TaintSink("os.system()", r"os\.system\s*\(", "Command Injection", "CWE-78", "Critical"),
        TaintSink("os.popen()", r"os\.popen\s*\(", "Command Injection", "CWE-78", "Critical"),
        TaintSink("subprocess.call()", r"subprocess\.call\s*\(", "Command Injection", "CWE-78", "High"),
        TaintSink("subprocess.run()", r"subprocess\.run\s*\(", "Command Injection", "CWE-78", "High"),
        TaintSink("subprocess.Popen()", r"subprocess\.Popen\s*\(", "Command Injection", "CWE-78", "High"),
        
        # SQL Injection
        TaintSink("cursor.execute()", r"cursor\.execute\s*\(", "SQL Injection", "CWE-89", "Critical"),
        TaintSink("raw SQL", r"\.raw\s*\(|\.extra\s*\(", "SQL Injection", "CWE-89", "High"),
        TaintSink("execute()", r"\.execute\s*\([^)]*%|\.execute\s*\([^)]*\.format", "SQL Injection", "CWE-89", "Critical"),
        
        # File Operations
        TaintSink("open(user_input)", r"open\s*\([^'\"]+\)", "Path Traversal", "CWE-22", "High"),
        TaintSink("shutil.copy()", r"shutil\.copy\s*\(", "Arbitrary File Write", "CWE-73", "High"),
        
        # Deserialization
        TaintSink("pickle.loads()", r"pickle\.loads?\s*\(", "Insecure Deserialization", "CWE-502", "Critical"),
        TaintSink("yaml.load()", r"yaml\.load\s*\([^)]*\)", "Insecure Deserialization", "CWE-502", "High"),
        TaintSink("yaml.unsafe_load()", r"yaml\.unsafe_load\s*\(", "Insecure Deserialization", "CWE-502", "Critical"),
        
        # Template Injection
        TaintSink("render_template_string()", r"render_template_string\s*\(", "Server-Side Template Injection", "CWE-94", "Critical"),
        TaintSink("Jinja2 no escape", r"Environment\s*\([^)]*autoescape\s*=\s*False", "Template Injection", "CWE-79", "High"),
        
        # XSS
        TaintSink("mark_safe()", r"mark_safe\s*\(", "Cross-Site Scripting", "CWE-79", "High"),
        TaintSink("innerHTML", r"\.innerHTML\s*=", "Cross-Site Scripting", "CWE-79", "High"),
        TaintSink("document.write()", r"document\.write\s*\(", "Cross-Site Scripting", "CWE-79", "High"),
    ]
    
    def __init__(self):
        self.logger = logging.getLogger("vuln_scan.taint")
    
    def analyze(self, code: str, filename: str = "") -> List[Dict[str, Any]]:
        """
        Perform static taint analysis on code.
        Returns list of potential taint flow vulnerabilities.
        """
        findings = []
        lines = code.split('\n')
        
        # Find all sources
        sources = self._find_sources(code, lines)
        
        # Find all sinks
        sinks = self._find_sinks(code, lines)
        
        # For each source, check if data flows to any sink
        # This is a simplified analysis - real taint tracking requires AST
        for source in sources:
            for sink in sinks:
                # Check if source and sink are in proximity (same function)
                if abs(source["line"] - sink["line"]) < 50:  # Within 50 lines
                    # Check for potential flow
                    flow = self._check_flow(lines, source, sink)
                    if flow:
                        findings.append({
                            "type": sink["vulnerability"],
                            "severity": sink["severity"],
                            "cwe": sink["cwe"],
                            "description": f"User input from {source['name']} may flow to {sink['name']}",
                            "source": {
                                "function": source["name"],
                                "line": source["line"],
                                "code": source["code"]
                            },
                            "sink": {
                                "function": sink["name"],
                                "line": sink["line"],
                                "code": sink["code"]
                            },
                            "location": {
                                "file": filename,
                                "line": sink["line"]
                            },
                            "recommendation": f"Sanitize input before passing to {sink['name']}",
                            "taint_flow": True
                        })
        
        self.logger.info(f"[TAINT] Found {len(findings)} potential taint flows in {filename}")
        return findings
    
    def _find_sources(self, code: str, lines: List[str]) -> List[Dict]:
        """Find all taint sources in code."""
        sources = []
        for source in self.SOURCES:
            for line_num, line in enumerate(lines, 1):
                if re.search(source.pattern, line):
                    sources.append({
                        "name": source.name,
                        "category": source.category,
                        "line": line_num,
                        "code": line.strip()[:100]
                    })
        return sources
    
    def _find_sinks(self, code: str, lines: List[str]) -> List[Dict]:
        """Find all taint sinks in code."""
        sinks = []
        for sink in self.SINKS:
            for line_num, line in enumerate(lines, 1):
                if re.search(sink.pattern, line):
                    sinks.append({
                        "name": sink.name,
                        "vulnerability": sink.vulnerability,
                        "cwe": sink.cwe,
                        "severity": sink.severity,
                        "line": line_num,
                        "code": line.strip()[:100]
                    })
        return sinks
    
    def _check_flow(self, lines: List[str], source: Dict, sink: Dict) -> bool:
        """
        Check if there's a potential data flow from source to sink.
        This is a heuristic check - real taint tracking requires AST analysis.
        """
        # Simple heuristic: look for variable assignments between source and sink
        start = min(source["line"], sink["line"]) - 1
        end = max(source["line"], sink["line"])
        
        # Extract potential variable from source
        source_line = source["code"]
        
        # Look for assignment patterns
        # Check if the sink line contains any variable that was assigned from source
        # This is very simplified - production would use proper data flow analysis
        
        # For now, return True if they're in same function scope and sink uses dynamic data
        sink_line = sink["code"]
        
        # Check for obvious unsafe patterns in sink
        unsafe_patterns = [
            r'\+\s*["\']',  # String concatenation
            r'\.format\s*\(',  # String formatting
            r'%\s+["\']',  # Old-style formatting
            r'f["\'].*\{',  # f-strings with variables
        ]
        
        for pattern in unsafe_patterns:
            if re.search(pattern, sink_line):
                return True
        
        return False
