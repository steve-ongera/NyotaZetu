"""
Utility functions for security analysis and threat detection
"""
from django.utils import timezone
from django.db.models import Count, Q, Avg
from datetime import timedelta
from collections import defaultdict
import re
from user_agents import parse


class SecurityAnalyzer:
    """
    Advanced security analysis utilities
    """
    
    @staticmethod
    def analyze_user_behavior(user, days=7):
        """
        Analyze user behavior patterns to detect anomalies
        Returns a risk score (0-100)
        """
        from .models import UserURLVisit, LoginAttempt, AuditLog
        
        risk_score = 0
        evidence = []
        
        start_date = timezone.now() - timedelta(days=days)
        
        # 1. Check login patterns
        logins = LoginAttempt.objects.filter(
            username=user.username,
            timestamp__gte=start_date
        )
        
        failed_logins = logins.filter(success=False).count()
        if failed_logins > 5:
            risk_score += 20
            evidence.append(f'{failed_logins} failed login attempts')
        
        # 2. Check multiple IP addresses
        ip_addresses = logins.values('ip_address').distinct().count()
        if ip_addresses > 3:
            risk_score += 15
            evidence.append(f'Access from {ip_addresses} different IP addresses')
        
        # 3. Check unusual access times
        night_access = AuditLog.objects.filter(
            user=user,
            timestamp__gte=start_date,
            timestamp__hour__gte=22
        ).count() + AuditLog.objects.filter(
            user=user,
            timestamp__gte=start_date,
            timestamp__hour__lte=5
        ).count()
        
        if night_access > 10:
            risk_score += 10
            evidence.append(f'{night_access} accesses during unusual hours')
        
        # 4. Check rapid page access
        recent_visits = UserURLVisit.objects.filter(
            user=user,
            visited_at__gte=timezone.now() - timedelta(minutes=5)
        ).count()
        
        if recent_visits > 50:
            risk_score += 25
            evidence.append(f'{recent_visits} page visits in 5 minutes (possible scraping)')
        
        # 5. Check access to sensitive URLs
        sensitive_patterns = ['/admin/', '/api/', '/export/', '/download/']
        sensitive_access = UserURLVisit.objects.filter(
            user=user,
            visited_at__gte=start_date
        )
        
        sensitive_count = 0
        for visit in sensitive_access:
            if any(pattern in visit.url_visit.url_path for pattern in sensitive_patterns):
                sensitive_count += 1
        
        if sensitive_count > 20:
            risk_score += 20
            evidence.append(f'{sensitive_count} accesses to sensitive URLs')
        
        # 6. Check for privilege escalation attempts
        escalation_attempts = AuditLog.objects.filter(
            user=user,
            timestamp__gte=start_date,
            description__icontains='unauthorized'
        ).count()
        
        if escalation_attempts > 0:
            risk_score += 30
            evidence.append(f'{escalation_attempts} unauthorized access attempts')
        
        return {
            'risk_score': min(risk_score, 100),
            'evidence': evidence,
            'confidence': 85.0 if len(evidence) > 2 else 60.0
        }
    
    @staticmethod
    def detect_phishing_indicators(user):
        """
        Detect potential phishing or account compromise indicators
        """
        from .models import UserSession, LoginAttempt
        
        indicators = []
        
        # Check for multiple simultaneous sessions
        active_sessions = UserSession.objects.filter(
            user=user,
            is_active=True
        )
        
        if active_sessions.count() > 2:
            indicators.append({
                'type': 'multiple_devices',
                'severity': 'medium',
                'description': f'{active_sessions.count()} simultaneous active sessions'
            })
        
        # Check for geographically impossible logins
        recent_logins = LoginAttempt.objects.filter(
            username=user.username,
            success=True,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).values_list('ip_address', flat=True)
        
        unique_ips = set(recent_logins)
        if len(unique_ips) > 2:
            indicators.append({
                'type': 'impossible_travel',
                'severity': 'high',
                'description': f'Logins from {len(unique_ips)} different locations in 1 hour'
            })
        
        # Check for sudden change in user agent
        recent_sessions = UserSession.objects.filter(
            user=user,
            login_time__gte=timezone.now() - timedelta(days=1)
        ).values_list('user_agent', flat=True)
        
        unique_agents = set(recent_sessions)
        if len(unique_agents) > 3:
            indicators.append({
                'type': 'device_switching',
                'severity': 'medium',
                'description': f'{len(unique_agents)} different devices in 24 hours'
            })
        
        return indicators
    
    @staticmethod
    def analyze_threat_patterns(days=30):
        """
        Analyze security threat patterns over time
        """
        from .models import SecurityThreat
        
        start_date = timezone.now() - timedelta(days=days)
        
        threats = SecurityThreat.objects.filter(
            detected_at__gte=start_date
        )
        
        # Group by threat type
        threat_distribution = threats.values('threat_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Group by IP address (identify repeat offenders)
        repeat_offenders = threats.values('ip_address').annotate(
            count=Count('id')
        ).filter(count__gte=3).order_by('-count')
        
        # Severity distribution
        severity_distribution = threats.values('severity').annotate(
            count=Count('id')
        )
        
        # Trend analysis (daily counts)
        daily_threats = threats.extra(
            select={'day': 'date(detected_at)'}
        ).values('day').annotate(
            count=Count('id')
        ).order_by('day')
        
        return {
            'total_threats': threats.count(),
            'unresolved': threats.filter(resolved=False).count(),
            'threat_distribution': list(threat_distribution),
            'repeat_offenders': list(repeat_offenders),
            'severity_distribution': list(severity_distribution),
            'daily_trend': list(daily_threats),
        }
    
    @staticmethod
    def parse_user_agent(user_agent_string):
        """
        Parse user agent string to extract device info
        """
        try:
            user_agent = parse(user_agent_string)
            
            return {
                'device_type': 'Mobile' if user_agent.is_mobile else 'Tablet' if user_agent.is_tablet else 'Desktop',
                'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
                'os': f"{user_agent.os.family} {user_agent.os.version_string}",
                'is_bot': user_agent.is_bot,
            }
        except:
            return {
                'device_type': 'Unknown',
                'browser': 'Unknown',
                'os': 'Unknown',
                'is_bot': False,
            }
    
    @staticmethod
    def calculate_session_risk(session):
        """
        Calculate risk score for a user session
        """
        from .models import LoginAttempt, SecurityThreat
        
        risk_score = 0
        
        # Check for recent threats from same IP
        recent_threats = SecurityThreat.objects.filter(
            ip_address=session.ip_address,
            detected_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        if recent_threats > 0:
            risk_score += 30
        
        # Check for failed login attempts
        failed_attempts = LoginAttempt.objects.filter(
            ip_address=session.ip_address,
            success=False,
            timestamp__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        if failed_attempts > 3:
            risk_score += 20
        
        # Check session duration
        session_duration = timezone.now() - session.login_time
        if session_duration > timedelta(hours=8):
            risk_score += 10
        
        # Check for unusual user agent
        device_info = SecurityAnalyzer.parse_user_agent(session.user_agent)
        if device_info['is_bot']:
            risk_score += 40
        
        return min(risk_score, 100)
    
    @staticmethod
    def generate_security_report(days=30):
        """
        Generate comprehensive security report
        """
        from .models import (
            SecurityThreat, SuspiciousActivity, LoginAttempt,
            User, UserSession, AuditLog
        )
        
        start_date = timezone.now() - timedelta(days=days)
        
        report = {
            'period': {
                'start': start_date,
                'end': timezone.now(),
                'days': days,
            },
            'threats': {
                'total': SecurityThreat.objects.filter(detected_at__gte=start_date).count(),
                'critical': SecurityThreat.objects.filter(
                    detected_at__gte=start_date,
                    severity='critical'
                ).count(),
                'resolved': SecurityThreat.objects.filter(
                    detected_at__gte=start_date,
                    resolved=True
                ).count(),
                'unresolved': SecurityThreat.objects.filter(
                    detected_at__gte=start_date,
                    resolved=False
                ).count(),
            },
            'suspicious_activities': {
                'total': SuspiciousActivity.objects.filter(detected_at__gte=start_date).count(),
                'high_risk': SuspiciousActivity.objects.filter(
                    detected_at__gte=start_date,
                    risk_score__gte=70
                ).count(),
                'investigated': SuspiciousActivity.objects.filter(
                    detected_at__gte=start_date,
                    investigated=True
                ).count(),
            },
            'authentication': {
                'successful_logins': LoginAttempt.objects.filter(
                    timestamp__gte=start_date,
                    success=True
                ).count(),
                'failed_attempts': LoginAttempt.objects.filter(
                    timestamp__gte=start_date,
                    success=False
                ).count(),
                'unique_users': LoginAttempt.objects.filter(
                    timestamp__gte=start_date,
                    success=True
                ).values('username').distinct().count(),
            },
            'user_activity': {
                'total_users': User.objects.count(),
                'active_users': User.objects.filter(last_login__gte=start_date).count(),
                'new_users': User.objects.filter(date_joined__gte=start_date).count(),
                'current_sessions': UserSession.objects.filter(is_active=True).count(),
            },
            'audit': {
                'total_actions': AuditLog.objects.filter(timestamp__gte=start_date).count(),
                'security_events': AuditLog.objects.filter(
                    timestamp__gte=start_date,
                    action='security_event'
                ).count(),
            }
        }
        
        # Calculate metrics
        total_logins = report['authentication']['successful_logins'] + report['authentication']['failed_attempts']
        if total_logins > 0:
            report['authentication']['success_rate'] = round(
                (report['authentication']['successful_logins'] / total_logins) * 100, 2
            )
        else:
            report['authentication']['success_rate'] = 100.0
        
        # Threat resolution rate
        total_threats = report['threats']['total']
        if total_threats > 0:
            report['threats']['resolution_rate'] = round(
                (report['threats']['resolved'] / total_threats) * 100, 2
            )
        else:
            report['threats']['resolution_rate'] = 100.0
        
        return report


class ThreatDetector:
    """
    Real-time threat detection utilities
    """
    
    @staticmethod
    def detect_sql_injection(data):
        """Detect SQL injection patterns"""
        sql_patterns = [
            r"union.*select",
            r"insert.*into",
            r"delete.*from",
            r"drop.*table",
            r"update.*set",
            r"'.*or.*'.*=.*'",
            r"exec\s*\(",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, str(data), re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def detect_xss(data):
        """Detect XSS patterns"""
        xss_patterns = [
            r"<script.*?>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe.*?>",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, str(data), re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def detect_path_traversal(data):
        """Detect path traversal attempts"""
        if '../' in str(data) or '..\\' in str(data):
            return True
        return False
    
    @staticmethod
    def detect_command_injection(data):
        """Detect command injection patterns"""
        cmd_patterns = [
            r";\s*(ls|cat|echo|wget|curl)",
            r"\|\s*(ls|cat|echo|wget|curl)",
            r"&&\s*(ls|cat|echo|wget|curl)",
            r"`.*`",
            r"\$\(.*\)",
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, str(data), re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def analyze_request(request):
        """
        Analyze request for all threat types
        """
        threats = []
        
        # Check URL
        full_path = request.get_full_path()
        
        if ThreatDetector.detect_sql_injection(full_path):
            threats.append('sql_injection')
        if ThreatDetector.detect_xss(full_path):
            threats.append('xss')
        if ThreatDetector.detect_path_traversal(full_path):
            threats.append('path_traversal')
        if ThreatDetector.detect_command_injection(full_path):
            threats.append('code_injection')
        
        # Check POST data
        if request.method == 'POST':
            try:
                body = request.body.decode('utf-8')
                
                if ThreatDetector.detect_sql_injection(body):
                    threats.append('sql_injection')
                if ThreatDetector.detect_xss(body):
                    threats.append('xss')
                if ThreatDetector.detect_command_injection(body):
                    threats.append('code_injection')
            except:
                pass
        
        return list(set(threats))  # Remove duplicates