"""
Django management command for automated security analysis
Create this file at: main_application/management/commands/analyze_security.py
Run with: python manage.py analyze_security
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
from main_application.models import (
    User, LoginAttempt, SecurityThreat, SuspiciousActivity,
    UserSession, AuditLog
)
from main_application.utils import SecurityAnalyzer, ThreatDetector


class Command(BaseCommand):
    help = 'Run automated security analysis and generate reports'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to analyze (default: 7)'
        )
        
        parser.add_argument(
            '--check-users',
            action='store_true',
            help='Analyze all users for suspicious behavior'
        )
        
        parser.add_argument(
            '--generate-report',
            action='store_true',
            help='Generate comprehensive security report'
        )
        
        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Clean up old audit logs and resolved threats'
        )
    
    def handle(self, *args, **options):
        days = options['days']
        
        self.stdout.write(self.style.SUCCESS(
            f'\n{"="*60}\n'
            f'Security Analysis Started - {timezone.now()}\n'
            f'{"="*60}\n'
        ))
        
        # 1. Analyze user behavior
        if options['check_users']:
            self.analyze_users(days)
        
        # 2. Generate security report
        if options['generate_report']:
            self.generate_report(days)
        
        # 3. Cleanup old data
        if options['cleanup']:
            self.cleanup_old_data()
        
        # 4. Check for stale sessions
        self.check_stale_sessions()
        
        # 5. Summary statistics
        self.print_summary()
        
        self.stdout.write(self.style.SUCCESS(
            f'\n{"="*60}\n'
            f'Security Analysis Completed - {timezone.now()}\n'
            f'{"="*60}\n'
        ))
    
    def analyze_users(self, days):
        """Analyze all active users for suspicious behavior"""
        self.stdout.write(self.style.WARNING(
            f'\nAnalyzing user behavior (last {days} days)...'
        ))
        
        active_users = User.objects.filter(
            last_login__gte=timezone.now() - timedelta(days=days)
        )
        
        suspicious_count = 0
        
        for user in active_users:
            analysis = SecurityAnalyzer.analyze_user_behavior(user, days)
            
            if analysis['risk_score'] > 50:
                suspicious_count += 1
                
                # Create suspicious activity record
                SuspiciousActivity.objects.create(
                    user=user,
                    activity_type='unusual_access_pattern',
                    description='; '.join(analysis['evidence']),
                    ip_address='0.0.0.0',  # System-generated
                    risk_score=analysis['risk_score'],
                    confidence=analysis['confidence'],
                    evidence=analysis
                )
                
                self.stdout.write(self.style.WARNING(
                    f'  🚨 {user.username}: Risk Score {analysis["risk_score"]}'
                ))
            
            # Check for phishing indicators
            phishing = SecurityAnalyzer.detect_phishing_indicators(user)
            
            if phishing:
                for indicator in phishing:
                    SuspiciousActivity.objects.create(
                        user=user,
                        activity_type='phishing_link_click',
                        description=indicator['description'],
                        ip_address='0.0.0.0',
                        risk_score=80 if indicator['severity'] == 'high' else 60,
                        confidence=75.0,
                        evidence={'indicators': phishing}
                    )
                
                self.stdout.write(self.style.WARNING(
                    f'  🎣 {user.username}: {len(phishing)} phishing indicators'
                ))
        
        self.stdout.write(self.style.SUCCESS(
            f'✓ Analyzed {active_users.count()} users, '
            f'found {suspicious_count} with suspicious behavior'
        ))
    
    def generate_report(self, days):
        """Generate comprehensive security report"""
        self.stdout.write(self.style.WARNING(
            f'\nGenerating security report (last {days} days)...'
        ))
        
        report = SecurityAnalyzer.generate_security_report(days)
        
        # Print report
        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('SECURITY REPORT'))
        self.stdout.write('='*60 + '\n')
        
        # Period
        self.stdout.write(f"Period: {report['period']['start'].date()} to {report['period']['end'].date()}")
        self.stdout.write('')
        
        # Threats
        self.stdout.write(self.style.WARNING('THREATS:'))
        self.stdout.write(f"  Total: {report['threats']['total']}")
        self.stdout.write(f"  Critical: {report['threats']['critical']}")
        self.stdout.write(f"  Resolved: {report['threats']['resolved']}")
        self.stdout.write(f"  Unresolved: {report['threats']['unresolved']}")
        self.stdout.write(f"  Resolution Rate: {report['threats']['resolution_rate']}%")
        self.stdout.write('')
        
        # Suspicious Activities
        self.stdout.write(self.style.WARNING('SUSPICIOUS ACTIVITIES:'))
        self.stdout.write(f"  Total: {report['suspicious_activities']['total']}")
        self.stdout.write(f"  High Risk: {report['suspicious_activities']['high_risk']}")
        self.stdout.write(f"  Investigated: {report['suspicious_activities']['investigated']}")
        self.stdout.write('')
        
        # Authentication
        self.stdout.write(self.style.WARNING('AUTHENTICATION:'))
        self.stdout.write(f"  Successful Logins: {report['authentication']['successful_logins']}")
        self.stdout.write(f"  Failed Attempts: {report['authentication']['failed_attempts']}")
        self.stdout.write(f"  Success Rate: {report['authentication']['success_rate']}%")
        self.stdout.write(f"  Unique Users: {report['authentication']['unique_users']}")
        self.stdout.write('')
        
        # User Activity
        self.stdout.write(self.style.WARNING('USER ACTIVITY:'))
        self.stdout.write(f"  Total Users: {report['user_activity']['total_users']}")
        self.stdout.write(f"  Active Users: {report['user_activity']['active_users']}")
        self.stdout.write(f"  New Users: {report['user_activity']['new_users']}")
        self.stdout.write(f"  Current Sessions: {report['user_activity']['current_sessions']}")
        self.stdout.write('')
        
        # Audit
        self.stdout.write(self.style.WARNING('AUDIT:'))
        self.stdout.write(f"  Total Actions: {report['audit']['total_actions']}")
        self.stdout.write(f"  Security Events: {report['audit']['security_events']}")
        
        self.stdout.write('\n' + '='*60 + '\n')
    
    def cleanup_old_data(self):
        """Clean up old audit logs and resolved threats"""
        self.stdout.write(self.style.WARNING('\nCleaning up old data...'))
        
        # Delete old audit logs (older than 1 year)
        old_date = timezone.now() - timedelta(days=365)
        old_logs = AuditLog.objects.filter(timestamp__lt=old_date)
        log_count = old_logs.count()
        old_logs.delete()
        
        self.stdout.write(self.style.SUCCESS(
            f'✓ Deleted {log_count} old audit logs'
        ))
        
        # Delete resolved threats older than 90 days
        resolved_date = timezone.now() - timedelta(days=90)
        old_threats = SecurityThreat.objects.filter(
            resolved=True,
            resolved_at__lt=resolved_date
        )
        threat_count = old_threats.count()
        old_threats.delete()
        
        self.stdout.write(self.style.SUCCESS(
            f'✓ Deleted {threat_count} old resolved threats'
        ))
        
        # Delete investigated suspicious activities older than 90 days
        old_activities = SuspiciousActivity.objects.filter(
            investigated=True,
            investigated_at__lt=resolved_date
        )
        activity_count = old_activities.count()
        old_activities.delete()
        
        self.stdout.write(self.style.SUCCESS(
            f'✓ Deleted {activity_count} old investigated activities'
        ))
    
    def check_stale_sessions(self):
        """Check for and clean up stale sessions"""
        self.stdout.write(self.style.WARNING('\nChecking for stale sessions...'))
        
        stale_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=timezone.now() - timedelta(minutes=30)
        )
        
        stale_count = stale_sessions.count()
        
        # Mark as inactive
        stale_sessions.update(
            is_active=False,
            logout_time=timezone.now()
        )
        
        self.stdout.write(self.style.SUCCESS(
            f'✓ Marked {stale_count} stale sessions as inactive'
        ))
    
    def print_summary(self):
        """Print summary statistics"""
        self.stdout.write(self.style.WARNING('\nCurrent Status:'))
        
        # Current threats
        unresolved_threats = SecurityThreat.objects.filter(resolved=False).count()
        critical_threats = SecurityThreat.objects.filter(
            resolved=False,
            severity='critical'
        ).count()
        
        self.stdout.write(f"  Unresolved Threats: {unresolved_threats}")
        if critical_threats > 0:
            self.stdout.write(self.style.ERROR(
                f"  ⚠️  Critical Threats: {critical_threats}"
            ))
        
        # Uninvestigated activities
        uninvestigated = SuspiciousActivity.objects.filter(
            investigated=False
        ).count()
        
        self.stdout.write(f"  Uninvestigated Activities: {uninvestigated}")
        
        # Active sessions
        active_sessions = UserSession.objects.filter(is_active=True).count()
        self.stdout.write(f"  Active Sessions: {active_sessions}")
        
        # Today's stats
        today = timezone.now().date()
        today_logins = LoginAttempt.objects.filter(
            timestamp__date=today,
            success=True
        ).count()
        today_failed = LoginAttempt.objects.filter(
            timestamp__date=today,
            success=False
        ).count()
        
        self.stdout.write(f"  Today's Successful Logins: {today_logins}")
        self.stdout.write(f"  Today's Failed Attempts: {today_failed}")