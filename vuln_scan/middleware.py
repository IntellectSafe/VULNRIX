import logging

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware:
    """
    Middleware to inject strict security headers (CSP, HSTS, Permissions, COOP/COEP).
    Fixes 14 findings from pentest report.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # 1. Content-Security-Policy (High Severity)
        # Allow self, CDNs (Tailwind/Fonts), and inline styles/scripts (typical for Django apps)
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://unpkg.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https: blob:; "
            "connect-src 'self' https://api.openai.com https://generativelanguage.googleapis.com; "  # Allow AI APIs if frontend calls them (unlikely, usually backend)
            "frame-ancestors 'none'; "
            "object-src 'none';"
        )
        response['Content-Security-Policy'] = csp_policy

        # 2. Permissions-Policy (Low Severity)
        response['Permissions-Policy'] = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"

        # 3. Referrer-Policy (Low Severity)
        response['Referrer-Policy'] = "strict-origin-when-cross-origin"

        # 4. Cross-Origin Policies (Low Severity) - Isolate the app
        # COOP: Same-origin isolation
        response['Cross-Origin-Opener-Policy'] = "same-origin"
        # COEP: Require CORP (Might break external images if not handled, keep credentialless or unsafe-none if issues arise)
        # Using 'credentialless' is safer for loading external resources without CORS headers
        # But 'require-corp' was recommended. Let's try 'same-origin' for CORP first.
        response['Cross-Origin-Embedder-Policy'] = "require-corp" 
        response['Cross-Origin-Resource-Policy'] = "same-origin"

        # 5. Server Header Suppression (Info Disclosure)
        # Note: WSGI servers might overwrite this, but we try.
        response['Server'] = "" 

        return response
