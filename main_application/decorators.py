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
Decorators for Ward Administrator Authorization
================================================
Custom decorators to restrict access to ward administrator views
"""

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps


def ward_admin_required(view_func):
    """
    Decorator to ensure user is a ward administrator
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            return redirect('login_view')
        
        if request.user.user_type != 'ward_admin':
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard')
        
        if not request.user.assigned_ward:
            messages.error(request, 'You are not assigned to any ward. Please contact the system administrator.')
            return redirect('dashboard')
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def ward_admin_or_higher(view_func):
    """
    Decorator to allow ward admin, constituency admin, county admin, or superuser
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            return redirect('login_view')
        
        allowed_types = ['ward_admin', 'constituency_admin', 'county_admin', 'admin']
        
        if request.user.user_type not in allowed_types and not request.user.is_superuser:
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard')
        
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