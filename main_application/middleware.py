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
    

"""
Security and Audit Middleware for tracking user activities and security threats
Place this file at: your_app/middleware.py
"""
from django.utils import timezone
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from datetime import timedelta
import json
import re
from collections import defaultdict
from .models import *


class SecurityMonitoringMiddleware:
    """
    Middleware to track all requests, detect suspicious activities,
    and log security events in real-time
    """
    
    # Suspicious patterns to detect
    SUSPICIOUS_PATTERNS = [
        r'union.*select',  # SQL Injection
        r'<script.*?>',    # XSS
        r'\.\./\.\.',      # Path Traversal
        r'eval\(',         # Code Injection
        r'base64_decode',  # Obfuscation
        r'system\(',       # Command Injection
        r'exec\(',         # Command Injection
    ]
    
    # Rate limiting thresholds
    MAX_REQUESTS_PER_MINUTE = 60
    MAX_FAILED_LOGINS = 5
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Store request counts per IP (in production, use Redis/Memcached)
        self.request_counts = defaultdict(list)
        self.failed_login_counts = defaultdict(int)
    
    def __call__(self, request):
        # Before request processing
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Track request
        self.track_request(request, ip_address, user_agent)
        
        # Check for suspicious activity
        threat_detected = self.detect_threats(request, ip_address, user_agent)
        
        # Check rate limiting
        if self.check_rate_limit(ip_address):
            from django.http import HttpResponseForbidden
            self.log_security_event(
                request,
                'rate_limit_exceeded',
                f'Rate limit exceeded from {ip_address}',
                'high'
            )
            return HttpResponseForbidden('Rate limit exceeded')
        
        # Process request
        response = self.get_response(request)
        
        # After request processing
        if threat_detected:
            self.log_security_event(
                request,
                'threat_detected',
                f'Suspicious activity detected: {threat_detected}',
                'critical'
            )
        
        return response
    
    def get_client_ip(self, request):
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip
    
    def track_request(self, request, ip_address, user_agent):
        """Track request for analytics"""
        from .models import AuditLog
        
        # Only log certain request types to avoid excessive logging
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            try:
                AuditLog.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    action='view',
                    table_affected='Request',
                    description=f'{request.method} {request.path}',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            except Exception as e:
                # Don't break the request if logging fails
                pass
        
        # Track request timestamp for rate limiting
        now = timezone.now()
        self.request_counts[ip_address].append(now)
        
        # Clean old entries (older than 1 minute)
        self.request_counts[ip_address] = [
            ts for ts in self.request_counts[ip_address]
            if now - ts < timedelta(minutes=1)
        ]
    
    def detect_threats(self, request, ip_address, user_agent):
        """Detect potential security threats"""
        threats = []
        
        # Check request path and query parameters
        full_path = request.get_full_path()
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, full_path, re.IGNORECASE):
                threats.append(f'Suspicious pattern in URL: {pattern}')
        
        # Check POST data
        if request.method == 'POST':
            try:
                body = request.body.decode('utf-8')
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        threats.append(f'Suspicious pattern in POST data: {pattern}')
            except:
                pass
        
        # Check user agent for common attack tools
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit']
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                threats.append(f'Suspicious user agent: {agent}')
        
        # Check for credential stuffing attempts
        if 'login' in request.path.lower() and request.method == 'POST':
            if self.failed_login_counts[ip_address] >= self.MAX_FAILED_LOGINS:
                threats.append('Multiple failed login attempts (credential stuffing)')
        
        return threats if threats else None
    
    def check_rate_limit(self, ip_address):
        """Check if IP has exceeded rate limit"""
        request_count = len(self.request_counts[ip_address])
        return request_count > self.MAX_REQUESTS_PER_MINUTE
    
    def log_security_event(self, request, event_type, description, severity='medium'):
        """Log security events to database"""
        from .models import AuditLog
        
        try:
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='security_event',
                table_affected='Security',
                description=f'[{severity.upper()}] {event_type}: {description}',
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                old_values={'event_type': event_type, 'severity': severity}
            )
        except Exception as e:
            # Log to file or external service if database logging fails
            pass


class URLTrackingMiddleware:
    """
    Middleware to track URL visits for analytics
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Track URL before processing
        if request.user.is_authenticated:
            self.track_url_visit(request)
        
        response = self.get_response(request)
        return response
    
    def track_url_visit(self, request):
        """Track URL visits for authenticated users"""
        from .models import URLVisit
        
        try:
            # Get or create URL visit record
            url_visit, created = URLVisit.objects.get_or_create(
                url_path=request.path,
                defaults={
                    'url_name': request.resolver_match.url_name if request.resolver_match else 'unknown',
                    'view_name': request.resolver_match.view_name if request.resolver_match else 'unknown'
                }
            )
            
            # Increment visit count
            url_visit.visit_count += 1
            url_visit.last_visited = timezone.now()
            url_visit.save()
            
            # Track individual user visit
            UserURLVisit.objects.create(
                user=request.user,
                url_visit=url_visit,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
        except Exception as e:
            # Don't break request if tracking fails
            pass
    
    def get_client_ip(self, request):
        """Extract client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip


# Signal receivers for authentication events
@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log successful login"""
    from .models import LoginAttempt, AuditLog
    
    ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')
    
    LoginAttempt.objects.create(
        username=user.username,
        ip_address=ip_address,
        success=True,
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    AuditLog.objects.create(
        user=user,
        action='login',
        table_affected='User',
        record_id=str(user.id),
        description=f'Successful login from {ip_address}',
        ip_address=ip_address,
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """Log failed login attempt"""
    from .models import LoginAttempt, AuditLog
    
    ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')
    username = credentials.get('username', 'unknown')
    
    LoginAttempt.objects.create(
        username=username,
        ip_address=ip_address,
        success=False,
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    AuditLog.objects.create(
        user=None,
        action='login',
        table_affected='User',
        description=f'Failed login attempt for {username} from {ip_address}',
        ip_address=ip_address,
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Log user logout"""
    from .models import AuditLog
    
    if user:
        ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')
        
        AuditLog.objects.create(
            user=user,
            action='logout',
            table_affected='User',
            record_id=str(user.id),
            description=f'User logged out from {ip_address}',
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )


