
import os
import sys
import django
from django.utils import timezone

# Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'digitalshield.settings')
django.setup()

from django.contrib.auth.models import User
from vuln_scan.web_dashboard.models import CodeScanHistory, ScanProject
from vuln_scan.web_dashboard.views import get_scan_history

def run_verification():
    print("=== UNIFIED HISTORY VERIFICATION ===")
    
    # 1. Setup User
    user, _ = User.objects.get_or_create(username='history_tester')
    
    # 2. Clear old data
    CodeScanHistory.objects.filter(user=user).delete()
    ScanProject.objects.filter(user=user).delete()
    
    # 3. Create Dummy Data
    print("[*] Creating dummy data...")
    
    # Single scan (older)
    s1 = CodeScanHistory.objects.create(
        user=user, filename='old_script.py', status='SAFE', created_at=timezone.now() - timezone.timedelta(hours=2)
    )
    s1.created_at = timezone.now() - timezone.timedelta(hours=2) # Force update
    s1.save()
    
    # Project scan (newer)
    p1 = ScanProject.objects.create(
        user=user, name='cool-repo', scan_type='repo', status='COMPLETED', total_risk_score=50,
        created_at=timezone.now() - timezone.timedelta(hours=1)
    )
    p1.created_at = timezone.now() - timezone.timedelta(hours=1)
    p1.save()
    
    # Single scan (newest)
    s2 = CodeScanHistory.objects.create(
        user=user, filename='new_script.js', status='VULNERABLE', created_at=timezone.now()
    )
    
    # 4. Fetch History
    print("[*] Fetching unified history...")
    history = get_scan_history(user, limit=5)
    
    # 5. Verify Sort Order and Content
    if len(history) != 3:
        print(f"[-] Expected 3 items, got {len(history)}")
        return

    print(f"[+] Item 1 (Newest): {history[0]['filename']} ({history[0]['type']})")
    print(f"[+] Item 2 (Middle): {history[1]['filename']} ({history[1]['type']})")
    print(f"[+] Item 3 (Oldest): {history[2]['filename']} ({history[2]['type']})")
    
    if history[0]['filename'] != 'new_script.js': print("[-] Sort Order Error: Item 1")
    if history[1]['filename'] != 'cool-repo': print("[-] Sort Order Error: Item 2")
    if history[2]['filename'] != 'old_script.py': print("[-] Sort Order Error: Item 3")
    
    print("\nSUCCESS: History unification verified! 🚀")

if __name__ == "__main__":
    try:
        run_verification()
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
