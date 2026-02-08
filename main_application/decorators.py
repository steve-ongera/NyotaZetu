"""
Decorators for role-based access control
"""

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect
from django.contrib import messages

from functools import wraps
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect
from django.contrib import messages


REVIEWER_ROLES = ['reviewer', 'admin', 'county_admin']


def reviewer_required(view_func):
    """
    Allows access to reviewers, admins, and county admins
    """

    def check_user(user):
        return user.is_authenticated and user.user_type in REVIEWER_ROLES

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):

        # Not logged in
        if not request.user.is_authenticated:
            return redirect('login_view')

        # Wrong role
        if request.user.user_type not in REVIEWER_ROLES:
            messages.error(
                request,
                "Access denied. Reviewer, Admin, or County Admin privileges required."
            )
            return redirect('dashboard')

        # Reviewer-specific checks
        if request.user.user_type == 'reviewer':
            if not request.user.assigned_ward:
                messages.error(
                    request,
                    "You are not assigned to any ward. Please contact the administrator."
                )
                return redirect('reviewer_profile')

        # County admin checks (optional but recommended)
        if request.user.user_type == 'county_admin':
            if not request.user.assigned_county:
                messages.error(
                    request,
                    "You are not assigned to any county. Please contact the administrator."
                )
                return redirect('dashboard')

        return view_func(request, *args, **kwargs)

    return wrapper



def admin_required(function):
    """
    Decorator to ensure user is an admin
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login_view')
        
        if request.user.user_type != 'admin':
            messages.error(request, "Access denied. Administrator privileges required.")
            return redirect('dashboard')
        
        return function(request, *args, **kwargs)
    
    return wrapper


def finance_required(function):
    """
    Decorator to ensure user is a finance officer
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login_view')
        
        if request.user.user_type != 'finance':
            messages.error(request, "Access denied. Finance officer privileges required.")
            return redirect('dashboard')
        
        return function(request, *args, **kwargs)
    
    return wrapper


"""
IMPROVED Ward Administrator Decorators
=======================================
These decorators prevent redirect loops by:
1. Using direct template rendering for errors instead of redirects
2. Having a clear redirect hierarchy
3. Avoiding circular redirects
"""

from django.shortcuts import redirect, render
from django.contrib import messages
from functools import wraps


def ward_admin_required(view_func):
    """
    Decorator to ensure user is a ward administrator
    
    IMPORTANT: This decorator INCLUDES authentication check,
    so you don't need @login_required before it.
    
    Usage:
        @ward_admin_required
        def my_view(request):
            # Your code here
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Check 1: Authentication
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            # Store the current path for redirect after login
            request.session['redirect_after_login'] = request.get_full_path()
            return redirect('login_view')
        
        # Check 2: User Type
        if request.user.user_type != 'ward_admin':
            messages.error(request, 'Access Denied: Ward Administrator privileges required.')
            
            # Redirect based on user type to prevent loops
            if request.user.user_type == 'applicant':
                return redirect('student_dashboard')
            elif request.user.user_type == 'admin':
                return redirect('admin_dashboard')
            elif request.user.user_type == 'reviewer':
                return redirect('reviewer_dashboard')
            elif request.user.user_type == 'finance':
                return redirect('finance_dashboard')
            elif request.user.user_type == 'county_admin':
                return redirect('county_admin_dashboard')
            elif request.user.user_type == 'constituency_admin':
                return redirect('constituency_dashboard')
            else:
                # Fallback: logout and redirect to login
                return redirect('logout_view')
        
        # Check 3: Ward Assignment
        if not request.user.assigned_ward:
            messages.error(request, 'You are not assigned to any ward. Please contact the system administrator.')
            
            # Render an error page instead of redirecting to prevent loops
            context = {
                'error_title': 'Ward Assignment Required',
                'error_message': 'Your account is not assigned to any ward. Please contact the system administrator to complete your account setup.',
                'user': request.user,
                'show_logout': True,
            }
            return render(request, 'errors/no_ward_assignment.html', context, status=403)
        
        # All checks passed - execute the view
        return view_func(request, *args, **kwargs)
    
    return wrapper


def ward_admin_or_higher(view_func):
    """
    Decorator to allow ward admin, constituency admin, county admin, admin, or superuser
    
    This is useful for views that should be accessible by ward admins and their supervisors.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Check 1: Authentication
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            request.session['redirect_after_login'] = request.get_full_path()
            return redirect('login_view')
        
        # Check 2: User Type
        allowed_types = ['ward_admin', 'constituency_admin', 'county_admin', 'admin']
        
        if request.user.user_type not in allowed_types and not request.user.is_superuser:
            messages.error(request, 'Access Denied: Insufficient privileges.')
            
            # Redirect based on user type
            if request.user.user_type == 'applicant':
                return redirect('student_dashboard')
            elif request.user.user_type == 'reviewer':
                return redirect('reviewer_dashboard')
            elif request.user.user_type == 'finance':
                return redirect('finance_dashboard')
            else:
                return redirect('logout_view')
        
        # Check 3: Area Assignment (only for ward/constituency/county admins)
        if request.user.user_type == 'ward_admin' and not request.user.assigned_ward:
            context = {
                'error_title': 'Ward Assignment Required',
                'error_message': 'Your account is not assigned to any ward.',
                'user': request.user,
                'show_logout': True,
            }
            return render(request, 'errors/no_assignment.html', context, status=403)
        
        elif request.user.user_type == 'constituency_admin' and not request.user.assigned_constituency:
            context = {
                'error_title': 'Constituency Assignment Required',
                'error_message': 'Your account is not assigned to any constituency.',
                'user': request.user,
                'show_logout': True,
            }
            return render(request, 'errors/no_assignment.html', context, status=403)
        
        elif request.user.user_type == 'county_admin' and not request.user.assigned_county:
            context = {
                'error_title': 'County Assignment Required',
                'error_message': 'Your account is not assigned to any county.',
                'user': request.user,
                'show_logout': True,
            }
            return render(request, 'errors/no_assignment.html', context, status=403)
        
        # All checks passed
        return view_func(request, *args, **kwargs)
    
    return wrapper


# Optional: Decorator that only checks authentication and ward assignment
# without checking user_type (useful for shared views)
def ward_assigned_required(view_func):
    """
    Lighter decorator that only ensures user has a ward assignment.
    Doesn't check user_type - useful for views accessible by multiple roles.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            request.session['redirect_after_login'] = request.get_full_path()
            return redirect('login_view')
        
        if not hasattr(request.user, 'assigned_ward') or not request.user.assigned_ward:
            context = {
                'error_title': 'Ward Assignment Required',
                'error_message': 'This feature requires ward assignment.',
                'user': request.user,
                'show_logout': True,
            }
            return render(request, 'errors/no_assignment.html', context, status=403)
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def constituency_admin_required(function):
    """
    Decorator to ensure user is a constituency administrator
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login_view')
        
        if request.user.user_type != 'constituency_admin':
            messages.error(request, "Access denied. Constituency administrator privileges required.")
            return redirect('dashboard')
        
        if not request.user.assigned_constituency:
            messages.error(request, "You are not assigned to any constituency.")
            return redirect('dashboard')
        
        return function(request, *args, **kwargs)
    
    return wrapper


def county_admin_required(function):
    """
    Decorator to ensure user is a county administrator
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login_view')
        
        if request.user.user_type != 'county_admin':
            messages.error(request, "Access denied. County administrator privileges required.")
            return redirect('dashboard')
        
        if not request.user.assigned_county:
            messages.error(request, "You are not assigned to any county.")
            return redirect('dashboard')
        
        return function(request, *args, **kwargs)
    
    return wrapper