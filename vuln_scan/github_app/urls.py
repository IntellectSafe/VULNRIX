"""
URL configuration for GitHub App integration.
"""
from django.urls import path
from . import views

app_name = 'github_app'

urlpatterns = [
    path('webhook/', views.webhook_handler, name='webhook'),
]
