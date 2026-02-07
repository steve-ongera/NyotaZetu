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
            return redirect('login')

        # Wrong role
        if request.user.user_type not in REVIEWER_ROLES:
            messages.error(
                request,
                "Access denied. Reviewer, Admin, or County Admin privileges required."
            )
            return redirect('home')

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
            return redirect('login')
        
        if request.user.user_type != 'admin':
            messages.error(request, "Access denied. Administrator privileges required.")
            return redirect('home')
        
        return function(request, *args, **kwargs)
    
    return wrapper


def finance_required(function):
    """
    Decorator to ensure user is a finance officer
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if request.user.user_type != 'finance':
            messages.error(request, "Access denied. Finance officer privileges required.")
            return redirect('home')
        
        return function(request, *args, **kwargs)
    
    return wrapper


def ward_admin_required(function):
    """
    Decorator to ensure user is a ward administrator
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if request.user.user_type != 'ward_admin':
            messages.error(request, "Access denied. Ward administrator privileges required.")
            return redirect('home')
        
        if not request.user.assigned_ward:
            messages.error(request, "You are not assigned to any ward.")
            return redirect('home')
        
        return function(request, *args, **kwargs)
    
    return wrapper


def constituency_admin_required(function):
    """
    Decorator to ensure user is a constituency administrator
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if request.user.user_type != 'constituency_admin':
            messages.error(request, "Access denied. Constituency administrator privileges required.")
            return redirect('home')
        
        if not request.user.assigned_constituency:
            messages.error(request, "You are not assigned to any constituency.")
            return redirect('home')
        
        return function(request, *args, **kwargs)
    
    return wrapper


def county_admin_required(function):
    """
    Decorator to ensure user is a county administrator
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if request.user.user_type != 'county_admin':
            messages.error(request, "Access denied. County administrator privileges required.")
            return redirect('home')
        
        if not request.user.assigned_county:
            messages.error(request, "You are not assigned to any county.")
            return redirect('home')
        
        return function(request, *args, **kwargs)
    
    return wrapper