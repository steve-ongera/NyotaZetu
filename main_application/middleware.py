"""
Custom middleware for handling session timeout gracefully
Place this in: main_application/middleware.py
"""

from django.shortcuts import redirect
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


class SessionTimeoutMiddleware:
    """
    Middleware to handle session timeout gracefully.
    - Tracks last activity time
    - Redirects to login with message on timeout
    - Preserves the original URL to redirect back after login
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Skip for non-authenticated users and login/logout URLs
        if not request.user.is_authenticated:
            return self.get_response(request)
            
        # Exclude these paths from timeout check
        excluded_paths = [
            settings.LOGIN_URL,
            '/logout/',
            '/static/',
            '/media/',
            '/resend-tfa-code/',
        ]
        
        if any(request.path.startswith(path) for path in excluded_paths):
            return self.get_response(request)
        
        # Check for session timeout
        session_timeout = settings.SESSION_COOKIE_AGE
        last_activity = request.session.get('last_activity')
        
        if last_activity:
            # Convert string timestamp to datetime if needed
            if isinstance(last_activity, str):
                from django.utils.dateparse import parse_datetime
                last_activity = parse_datetime(last_activity)
            
            # Calculate time since last activity
            time_since_activity = timezone.now() - last_activity
            
            # If session has expired
            if time_since_activity.total_seconds() > session_timeout:
                # Store the original URL they were trying to access
                request.session['session_expired'] = True
                request.session['redirect_after_login'] = request.get_full_path()
                
                # Log the timeout
                logger.info(f"Session timeout for user {request.user.username} after {time_since_activity}")
                
                # Clear session but preserve the redirect info
                redirect_url = request.session.get('redirect_after_login')
                expired_flag = request.session.get('session_expired')
                
                request.session.flush()
                
                # Restore redirect info in new session
                request.session['redirect_after_login'] = redirect_url
                request.session['session_expired'] = expired_flag
                
                # Add a friendly message
                messages.warning(
                    request, 
                    'Your session has expired due to inactivity. Please log in again.'
                )
                
                # Redirect to login with next parameter
                login_url = f"{settings.LOGIN_URL}?next={redirect_url}"
                return redirect(login_url)
        
        # Update last activity timestamp
        request.session['last_activity'] = timezone.now().isoformat()
        
        response = self.get_response(request)
        return response


class SessionWarningMiddleware:
    """
    Optional: Adds session expiry information to context for frontend warning
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('last_activity')
            if last_activity:
                if isinstance(last_activity, str):
                    from django.utils.dateparse import parse_datetime
                    last_activity = parse_datetime(last_activity)
                
                session_timeout = settings.SESSION_COOKIE_AGE
                time_remaining = session_timeout - (timezone.now() - last_activity).total_seconds()
                
                # Add to request for template access
                request.session_time_remaining = max(0, int(time_remaining))
        
        response = self.get_response(request)
        return response