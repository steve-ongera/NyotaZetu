from django import template

register = template.Library()

@register.filter(name='abs')
def absolute(value):
    """
    Returns the absolute value of a number
    Usage: {{ value|abs }}
    """
    try:
        return abs(value)
    except (TypeError, ValueError):
        return value

@register.filter
def filter_by_status(queryset, status):
    return queryset.filter(status=status)

@register.filter
def sub(value, arg):
    try:
        return int(value) - int(arg)
    except (ValueError, TypeError):
        return value
    
@register.filter
def sum_items(items, field):
    return sum(getattr(item, field) for item in items)