"""
GitHub App services for VULNRIX.
Handles JWT auth, installation tokens, and GitHub API calls.
"""
import os
import time
import jwt
import requests
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class GitHubAppService:
    """Service for interacting with GitHub as a GitHub App."""
    
    def __init__(self):
        self.app_id = os.environ.get('GITHUB_APP_ID')
        self.private_key_path = os.environ.get('GITHUB_PRIVATE_KEY_PATH')
        self.webhook_secret = os.environ.get('GITHUB_WEBHOOK_SECRET')
        self._private_key = None
    
    @property
    def private_key(self):
        """Load private key from file (lazy)."""
        if self._private_key is None:
            if not self.private_key_path:
                raise ValueError("GITHUB_PRIVATE_KEY_PATH not set")
            
            # Try absolute path first, then relative to BASE_DIR
            key_path = Path(self.private_key_path)
            if not key_path.is_absolute():
                from django.conf import settings
                key_path = settings.BASE_DIR / self.private_key_path
            
            if not key_path.exists():
                raise FileNotFoundError(f"Private key not found: {key_path}")
            
            self._private_key = key_path.read_text()
        return self._private_key
    
    def generate_jwt(self) -> str:
        """Generate a JWT for authenticating as the GitHub App."""
        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued 60 seconds ago (clock drift)
            "exp": now + (10 * 60),  # Expires in 10 minutes
            "iss": self.app_id,
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    def get_installation_token(self, installation_id: int) -> str:
        """Get an installation access token for a specific installation."""
        jwt_token = self.generate_jwt()
        
        response = requests.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10
        )
        
        if response.status_code != 201:
            logger.error(f"Failed to get installation token: {response.text}")
            raise Exception(f"Failed to get installation token: {response.status_code}")
        
        return response.json().get("token")
    
    def get_repo_contents(self, installation_id: int, owner: str, repo: str, path: str = "") -> list:
        """Get repository contents (file listing)."""
        token = self.get_installation_token(installation_id)
        
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get repo contents: {response.text}")
            return []
        
        return response.json()
    
    def get_file_content(self, installation_id: int, owner: str, repo: str, path: str) -> str:
        """Get raw file content from a repository."""
        token = self.get_installation_token(installation_id)
        
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.raw",
            },
            timeout=10
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get file content: {response.text}")
            return ""
        
        return response.text
    
    def create_branch(self, installation_id: int, owner: str, repo: str, 
                      branch_name: str, from_sha: str) -> bool:
        """Create a new branch from a commit SHA."""
        token = self.get_installation_token(installation_id)
        
        response = requests.post(
            f"https://api.github.com/repos/{owner}/{repo}/git/refs",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={
                "ref": f"refs/heads/{branch_name}",
                "sha": from_sha,
            },
            timeout=10
        )
        
        if response.status_code not in [200, 201]:
            logger.error(f"Failed to create branch: {response.text}")
            return False
        
        return True
    
    def update_file(self, installation_id: int, owner: str, repo: str,
                    path: str, content: str, message: str, branch: str, sha: str) -> bool:
        """Update (or create) a file in the repository."""
        import base64
        token = self.get_installation_token(installation_id)
        
        response = requests.put(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={
                "message": message,
                "content": base64.b64encode(content.encode()).decode(),
                "sha": sha,
                "branch": branch,
            },
            timeout=10
        )
        
        if response.status_code not in [200, 201]:
            logger.error(f"Failed to update file: {response.text}")
            return False
        
        return True
    
    def create_pull_request(self, installation_id: int, owner: str, repo: str,
                            title: str, body: str, head: str, base: str = "main") -> dict:
        """Create a pull request."""
        token = self.get_installation_token(installation_id)
        
        response = requests.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={
                "title": title,
                "body": body,
                "head": head,
                "base": base,
            },
            timeout=10
        )
        
        if response.status_code not in [200, 201]:
            logger.error(f"Failed to create PR: {response.text}")
            return {}
        
        return response.json()


# Singleton instance
github_app = GitHubAppService()
