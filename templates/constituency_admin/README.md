# Constituency Admin HTML Templates

This directory contains HTML templates for the Constituency Admin views in the NG-CDF Bursary Management System.

## Template Overview

The following templates have been created:

1. **dashboard.html** - Main dashboard showing CDF bursary overview and key metrics
2. **analytics.html** - Advanced analytics and insights for CDF bursary program
3. **applications_list.html** - List all CDF bursary applications with filtering
4. **application_detail.html** - Detailed view of a single CDF application
5. **wards_overview.html** - Overview of all wards in the constituency
6. **ward_detail.html** - Detailed view of ward applications and statistics
7. **disbursements.html** - Manage CDF bursary disbursements
8. **process_disbursement.html** - Process individual disbursement
9. **bulk_cheques.html** - Manage bulk cheques for institutions
10. **create_bulk_cheque.html** - Create bulk cheque for an institution
11. **reports.html** - Generate various reports for CDF bursary
12. **financial_report.html** - Comprehensive financial report
13. **beneficiaries.html** - Manage and track all beneficiaries
14. **beneficiary_profile.html** - Detailed beneficiary profile with history
15. **settings.html** - Constituency-specific settings and information
16. **send_notifications.html** - Send bulk notifications
17. **document_verification.html** - Document verification dashboard
18. **verify_document.html** - Verify or reject a document
19. **performance_metrics.html** - Track constituency performance metrics
20. **institutions.html** - Manage institutions and their beneficiaries
21. **institution_detail.html** - Detailed view of institution beneficiaries
22. **ward_comparison.html** - Compare performance across wards
23. **print_cheque_list.html** - Generate printable cheque collection list
24. **quality_checks.html** - Quality assurance checks for applications

## Features Included in Templates

- **Responsive Design**: Bootstrap 5-based responsive layout
- **Sidebar Navigation**: Consistent navigation across all pages
- **Dashboard Cards**: For displaying statistics and metrics
- **Data Tables**: For listing applications, beneficiaries, etc.
- **Form Elements**: For data entry and processing
- **Status Indicators**: Visual badges for application status
- **Chart.js Integration**: Ready for analytics charts
- **Mobile-Friendly**: Works on all device sizes

## Styling

The templates use a custom color scheme:
- Primary: #1a5f7a (blue-teal)
- Secondary: #2c7873 (teal)
- Accent: #ffc107 (yellow)
- Light Background: #f8f9fa
- Dark Background: #343a40

## Usage

1. Place these templates in your Django templates directory under 'constituency_admin/'
2. Update Django views to use these templates
3. Customize the content with actual Django template tags and context variables
4. Add dynamic functionality as needed

## Placeholder Content

Each template contains placeholder content that should be replaced with:
- Django template tags ({{ variable }})
- Template logic ({% if %}, {% for %})
- Dynamic data from view context
- Form handling with CSRF tokens
- URL reversing ({% url 'view_name' %})

## JavaScript Integration

Templates include:
- Bootstrap 5 JavaScript
- Chart.js for analytics pages
- Custom JavaScript for common functionality
- AJAX-ready structure for dynamic updates

## Notes

- All templates include Font Awesome icons
- Bootstrap 5 is loaded from CDN
- Charts are initialized in analytics-related templates
- The sidebar is responsive and collapses on mobile
- All templates share common CSS for consistency
