
"""
Service for aggregating scan results.
Updates project-level statistics based on file results.
"""
from typing import Dict, Any
from ..web_dashboard.models import ScanProject, ScanFileResult

def update_project_stats(project: ScanProject):
    """
    Recalculate and update stats for a ScanProject based on its file results.
    """
    results = project.file_results.all()
    
    total_files = 0
    total_risk = 0
    critical = 0
    high = 0
    medium = 0
    low = 0
    
    for res in results:
        total_files += 1
        total_risk += res.risk_score
        
        # Parse findings to count severities if not explicitly stored
        # Or rely on severity field if it was set correctly
        if res.severity == 'CRITICAL':
            critical += 1
        elif res.severity == 'HIGH':
            high += 1
        elif res.severity == 'MEDIUM':
            medium += 1
        elif res.severity == 'LOW':
            low += 1
            
    # Update project fields
    project.total_files = total_files
    project.total_risk_score = total_risk
    project.critical_count = critical
    project.high_count = high
    project.medium_count = medium
    project.low_count = low
    
    project.save()

def create_file_result(project: ScanProject, filename: str, result: Dict[str, Any]) -> ScanFileResult:
    """
    Create a ScanFileResult from a raw LLM result dict.
    """
    # Extract data
    findings = result.get('findings', [])
    summary = result.get('summary', {})
    
    # Determine max severity
    severity = 'SAFE'
    if summary.get('critical', 0) > 0:
        severity = 'CRITICAL'
    elif summary.get('high', 0) > 0:
        severity = 'HIGH'
    elif summary.get('medium', 0) > 0:
        severity = 'MEDIUM'
    elif summary.get('low', 0) > 0:
        severity = 'LOW'
        
    file_result = ScanFileResult(
        project=project,
        filename=filename,
        language=result.get('language', 'Unknown'),
        status=result.get('status', 'COMPLETED'),
        severity=severity,
        risk_score=result.get('risk_score', 0)
    )
    file_result.set_findings(findings)
    file_result.save()
    
    return file_result
