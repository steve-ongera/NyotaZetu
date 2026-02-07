"""
Decorators for role-based access control
"""

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect
from django.contrib import messages


def reviewer_required(function):
    """
    Decorator to ensure user is a reviewer
    """
    def check_reviewer(user):
        return user.is_authenticated and user.user_type == 'reviewer'
    
    actual_decorator = user_passes_test(
        check_reviewer,
        login_url='login',
        redirect_field_name='next'
    )
    
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if request.user.user_type != 'reviewer':
            messages.error(request, "Access denied. Reviewer privileges required.")
            return redirect('home')
        
        if not request.user.assigned_ward:
            messages.error(request, "You are not assigned to any ward. Please contact the administrator.")
            return redirect('reviewer_profile')
        
        return function(request, *args, **kwargs)
    
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