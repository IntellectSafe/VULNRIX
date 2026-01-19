"""
URL configuration for GitHub App integration.
"""
from django.urls import path
from . import views

app_name = 'github_app'

urlpatterns = [
    path('webhook/', views.webhook_handler, name='webhook'),
    
    # API for dashboard
    path('api/repos/', views.get_connected_repos, name='get_repos'),
    path('api/scan/', views.trigger_repo_scan, name='scan_repo'),
    path('api/auto-fix/', views.trigger_auto_fix, name='auto_fix'),
]
