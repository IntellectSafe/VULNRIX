
"""
Service for dispatching LLM scan requests.
Handles throttling, error handling, and pipeline coordination.
"""
import time
import logging
from typing import Dict, Any

logger = logging.getLogger("vuln_scan")

class LLMDispatcher:
    """
    Manages LLM scanning for files.
    Enforces throttling to respect rate limits.
    """
    
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.last_call_time = 0
        self.delay = 0.2 # 200ms delay between calls
        
    def scan_file(self, file_path: str, mode: str = "hybrid") -> Dict[str, Any]:
        """
        Scan a single file using the pipeline.
        Enforces sleep between calls.
        """
        # Throttling
        current_time = time.time()
        elapsed = current_time - self.last_call_time
        if elapsed < self.delay:
            sleep_time = self.delay - elapsed
            time.sleep(sleep_time)
            
        try:
            # Check pipeline readiness
            if not self.pipeline:
                return {"status": "ERROR", "error": "Pipeline not initialized"}
                
            # Perform Scan
            result = self.pipeline.scan_file(file_path, mode=mode)
            
            # Update timestamp
            self.last_call_time = time.time()
            return result
            
        except Exception as e:
            logger.error(f"LLM Dispatch Error: {e}")
            return {"status": "ERROR", "error": str(e)}

    def scan_project_files(self, file_paths: list, mode: str = "fast") -> list:
        """
        Generator to scan multiple files sequentially.
        Yields (file_path, result) tuples.
        """
        for file_path in file_paths:
            logger.info(f"Dispatching scan for: {file_path}")
            result = self.scan_file(file_path, mode)
            yield file_path, result
