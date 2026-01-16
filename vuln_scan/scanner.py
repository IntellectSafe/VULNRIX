"""
LLM Providers using only requests - NO SDK REQUIRED
Fixed with auto-model discovery for Gemini

Set your API keys as environment variables:
    GOOGLE_API_KEY                  - for Gemini
    GROQ_KEY                        - for Groq
    GROK_API_KEY                    - for Grok
"""

import os
import requests
import json
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod

class LLMProvider(ABC):
    """Base class for all LLM providers"""
    
    @abstractmethod
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        """Send a prompt and get a response"""
        pass
    
    def _build_prompt(self, system: str, user: str, context: str) -> str:
        """Helper to build full prompt"""
        parts = [system, user]
        if context:
            parts.append(f"\n--- FILE CONTENT ---\n{context}")
        return "\n\n".join(parts)


class GeminiProvider(LLMProvider):
    """Google Gemini API - requests only with auto-model discovery"""
    
    API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    LIST_URL = "https://generativelanguage.googleapis.com/v1beta/models"
    
    # Fallback models if auto-discovery fails
    FALLBACK_MODELS = [
        "gemini-2.5-flash"
    ]
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY required")
        
        # If model specified, use it. Otherwise auto-discover
        if model:
            self.models = [model]
        else:
            self.models = self._discover_models() or self.FALLBACK_MODELS
    
    def _discover_models(self) -> List[str]:
        """Auto-discover available models from Google API"""
        try:
            resp = requests.get(
                f"{self.LIST_URL}?key={self.api_key}",
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                models = []
                
                for m in data.get("models", []):
                    name = m.get("name", "").replace("models/", "")
                    methods = m.get("supportedGenerationMethods", [])
                    
                    # Only use models that support generateContent
                    if "generateContent" in methods:
                        models.append(name)
                
                # Sort by preference (flash first, then pro)
                models.sort(key=lambda x: (
                    0 if "flash" in x else 1,
                    1 if "latest" in x else 0
                ))
                
                return models
            
        except Exception:
            pass
        
        return []
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        # Build the prompt
        full_prompt = self._build_prompt(system_prompt, user_prompt, context)
        
        payload = {
            "contents": [{
                "parts": [{"text": full_prompt}]
            }],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 8192
            }
        }
        
        # Add system instruction if supported
        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": system_prompt}]
            }
        
        # Try each available model
        last_error = None
        for model in self.models:
            url = self.API_URL.format(model=model)
            
            try:
                resp = requests.post(
                    f"{url}?key={self.api_key}",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=120
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        content = candidates[0].get("content", {})
                        parts = content.get("parts", [])
                        if parts:
                            text = parts[0].get("text", "")
                            if text:
                                return text
                
                # Try next model
                last_error = f"{model}: {resp.status_code}"
                
            except requests.exceptions.Timeout:
                last_error = f"{model}: Timeout"
            except Exception as e:
                last_error = f"{model}: {str(e)}"
        
        # All models failed
        return f"Gemini Error: All models failed. Last: {last_error}"


class GroqProvider(LLMProvider):
    """Groq API - requests only"""
    
    API_URL = "https://api.groq.com/openai/v1/chat/completions"
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_KEY")
        if not self.api_key:
            raise ValueError("GROQ_KEY required")
        
        self.model = model or os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        user_content = user_prompt
        if context:
            user_content += f"\n\n--- FILE CONTENT ---\n{context}"
        
        messages.append({"role": "user", "content": user_content})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 4096
        }
        
        try:
            resp = requests.post(
                self.API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "No response")
            
            return f"Unexpected response: {json.dumps(data)[:500]}"
            
        except requests.exceptions.HTTPError as e:
            return f"API Error {resp.status_code}: {resp.text[:500]}"
        except Exception as e:
            return f"Error: {str(e)}"


class GrokProvider(LLMProvider):
    """Grok API - requests only"""
    
    API_URL = "https://api.x.ai/v1/chat/completions"
    
    FALLBACK_MODELS = [
        "grok-4.1-fast"
    ]
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROK_API_KEY")
        if not self.api_key:
            raise ValueError("GROK_API_KEY required")
        
        self.model = model or os.getenv("GROK_MODEL", self.FALLBACK_MODELS[0])
    
    def ask(self, system_prompt: str, user_prompt: str, context: str = "") -> str:
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        content = user_prompt
        if context:
            content += f"\n\n--- FILE CONTENT ---\n{context}"
        
        messages.append({"role": "user", "content": content})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
             "max_tokens": 4096
        }
        
        try:
            resp = requests.post(
                self.API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "No response")
            
            return f"Unexpected response: {json.dumps(data)[:300]}"
            
        except requests.exceptions.HTTPError as e:
            return f"API Error {resp.status_code}: {resp.text[:300]}
        except Exception as e:
            return f"Grok API Error: {str(e)}"

# Provider registry
PROVIDERS = {
    "gemini": GeminiProvider,
    "groq": GroqProvider,
    "grok": GrokProvider

}


def load_provider(name: str, **kwargs) -> LLMProvider:
    """Load a provider by name"""
    name = name.lower()
    if name not in PROVIDERS:
        raise ValueError(f"Unknown provider: {name}. Available: {list(PROVIDERS.keys())}")
    return PROVIDERS[name](**kwargs)


def list_providers() -> list:
    """List available providers"""
    return list(PROVIDERS.keys())
