
import os
import sys
import django
import shutil
import zipfile
import json
import tempfile
from pathlib import Path

# Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'digitalshield.settings')
django.setup()

from django.test import RequestFactory
from django.contrib.auth.models import User
from vuln_scan.web_dashboard.views import start_upload_scan, scan_next_file, project_status
from vuln_scan.web_dashboard.models import ScanProject, ScanFileResult

def create_test_zip():
    print("[*] Creating test zip file...")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    with zipfile.ZipFile(tmp.name, 'w') as zf:
        # Add a safe python file
        zf.writestr('safe_script.py', 'print("Hello World")\n')
        # Add a file with a dummy "secret" to trigger semantic analysis (maybe)
        zf.writestr('vuln_script.py', 'API_KEY = "123456" # TODO: remove hardcoded key\n')
        # Add a nested zip (should be ignored by our filter)
        # zf.writestr('nested.zip', 'PK...') 
    return tmp.name

def run_verification():
    print("=== VULNRIX REFACTOR VERIFICATION ===")
    
    # 1. Setup User
    user, created = User.objects.get_or_create(username='test_verifier')
    if created:
        user.set_password('pass')
        user.save()
    print(f"[+] User: {user.username}")

    # 2. Prepare Upload
    zip_path = create_test_zip()
    print(f"[+] Created zip: {zip_path}")
    
    factory = RequestFactory()
    
    try:
        # 3. Test Upload Endpoint
        print("[*] Testing /scan/upload/ ...")
        with open(zip_path, 'rb') as f:
            request = factory.post('/vuln/scan/upload/', {'file': f})
            request.user = user
            request._messages = [] # Mock messages
            
            response = start_upload_scan(request)
            
            if response.status_code != 200:
                print(f"[-] Upload Failed: {response.content}")
                return
            
            data = json.loads(response.content)
            project_id = data['project_id']
            total_files = data['total_files']
            print(f"[+] Project Created: ID={project_id}, Files={total_files}")
            
            if total_files != 2:
                print(f"[-] Expected 2 files, got {total_files}")
                
    finally:
        os.unlink(zip_path)
        
    # 4. Test Orchestration Loop
    print("[*] Testing Orchestration Loop...")
    
    files_processed = 0
    max_loops = 10
    
    for i in range(max_loops):
        # Call scan_next_file
        request = factory.get(f'/vuln/project/{project_id}/scan-file/')
        request.user = user
        
        response = scan_next_file(request, project_id)
        data = json.loads(response.content)
        
        status = data.get('status')
        print(f"    Loop {i+1}: Status={status}, File={data.get('filename', 'N/A')}")
        
        if status == 'COMPLETED':
            print("[+] Scan Completed!")
            break
        elif status == 'PROCESSED':
            files_processed += 1
        elif status == 'ERROR':
            print(f"[-] Error scanning file: {data.get('error')}")
            
    # 5. Check Project Status
    project = ScanProject.objects.get(id=project_id)
    print(f"[*] Final Project Status: {project.status}")
    print(f"    Risk Score: {project.total_risk_score}")
    print(f"    Files: {project.total_files}")
    
    if project.status == 'COMPLETED':
        print("\nSUCCESS: Verification Passed! 🚀")
    else:
        print("\nFAILURE: Project did not complete.")

if __name__ == "__main__":
    try:
        run_verification()
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
