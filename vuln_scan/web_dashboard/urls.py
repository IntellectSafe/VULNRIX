"""
Django URLs for vuln_scan web dashboard.
"""

from django.urls import path
from . import views

app_name = "vuln_scan"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("virustotal/", views.virustotal_scan, name="virustotal"),
    path("history/<int:scan_id>/", views.get_scan_result, name="scan_result"),
    
    # Repo Scan Logic
    path("scan/repo/", views.start_repo_scan, name="start_repo_scan"),
    path("project/<int:project_id>/scan-file/", views.scan_next_file, name="scan_next_file"),
    path("project/<int:project_id>/status/", views.project_status, name="project_status"),
    path("project/<int:project_id>/file/<int:file_id>/", views.project_file_details, name="project_file_details"),
]
