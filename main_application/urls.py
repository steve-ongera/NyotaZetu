from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout_view'),
    path('resend-tfa-code/', views.resend_tfa_code, name='resend_tfa_code'),
    
    # Dashboards
    path('dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('reviewer-dashboard/', views.reviewer_dashboard, name='reviewer_dashboard'),
    
    
    # ============= FINANCE DASHBOARD =============
    path('finance/dashboard/', views.finance_dashboard, name='finance_dashboard'),
    
    # ============= ALLOCATIONS =============
    path('finance/allocations/', views.allocation_list, name='finance_allocation_list'),
    path('finance/allocations/pending/', views.pending_disbursement_list, name='finance_pending_disbursement'),
    path('finance/allocations/<int:allocation_id>/process/', views.process_disbursement, name='finance_process_disbursement'),
    path('finance/allocations/bulk-disbursement/', views.bulk_disbursement, name='finance_bulk_disbursement'),
    
    # ============= DISBURSEMENTS =============
    path('finance/disbursements/', views.disbursement_list, name='finance_disbursement_list'),
    
    # ============= BULK CHEQUES =============
    path('finance/bulk-cheques/', views.bulk_cheque_list, name='finance_bulk_cheque_list'),
    path('finance/bulk-cheques/<int:cheque_id>/', views.bulk_cheque_detail, name='finance_bulk_cheque_detail'),
    path('finance/bulk-cheques/<int:cheque_id>/mark-collected/', views.mark_bulk_cheque_collected, name='finance_mark_bulk_cheque_collected'),
    
    # ============= BUDGET MANAGEMENT =============
    path('finance/budget/', views.budget_management, name='finance_budget_management'),
    
    # ============= REPORTS =============
    path('finance/reports/disbursements/', views.disbursement_reports, name='finance_disbursement_reports'),
    path('finance/reports/budget-utilization/', views.budget_utilization_report, name='finance_budget_utilization_report'),
    
    # ============= AJAX & EXPORT =============
    path('finance/allocations/<int:allocation_id>/details/', views.get_allocation_details, name='finance_get_allocation_details'),
    path('finance/disbursements/export-csv/', views.export_disbursements_csv, name='finance_export_disbursements_csv'),
     
    # Applications
    path('applications/', views.application_list, name='application_list'),
    path('applications/create/', views.create_application_view , name='create_application'), #by admin
    path('applications/<int:application_id>/', views.application_detail, name='application_detail'),
    path('applications/<int:application_id>/review/', views.application_review, name='application_review'),
    
    # AJAX endpoints for application creation
    path('ajax/search-student/', views.search_student_ajax, name='search_student_ajax'),
    path('ajax/check-existing-application/', views.check_existing_application_ajax, name='check_existing_application_ajax'),
    path('ajax/search-institution/', views.search_institution_ajax, name='search_institution_ajax'),
    path('ajax/get-locations/', views.get_locations_ajax, name='get_locations_ajax'),
    path('ajax/get-sublocations/', views.get_sublocations_ajax, name='get_sublocations_ajax'),
    path('ajax/get-villages/', views.get_villages_ajax, name='get_villages_ajax'),
    path('ajax/get-bursary-categories/', views.get_bursary_categories_ajax, name='get_bursary_categories_ajax'),
    path('ajax/submit-application/', views.submit_application_ajax, name='submit_application_ajax'),

    # PDF document serving URLs
    path('application/<int:application_id>/document/<int:document_id>/serve/',  views.serve_pdf_document,  name='serve_pdf_document'),
    path('application/<int:application_id>/document/<int:document_id>/viewer/',  views.pdf_viewer, name='pdf_viewer'),
    path('application/<int:application_id>/document/<int:document_id>/proxy/',  views.document_proxy,  name='document_proxy'),
    
    # Applicants
    path('applicants/', views.applicant_list, name='applicant_list'),
    path('applicants/<int:applicant_id>/', views.applicant_detail, name='applicant_detail'),
    path('admin-applicants/<int:applicant_id>/edit/', views.edit_applicant, name='edit_applicant'),
    
    # Security management URLs
    path('admin-applicants/<int:applicant_id>/unlock/', views.unlock_account, name='unlock_account'),
    path('admin-applicants/<int:applicant_id>/lock/', views.lock_account, name='lock_account'),
    path('admin-applicants/<int:applicant_id>/reset-attempts/', views.reset_failed_attempts, name='reset_failed_attempts'),
    path('admin-applicants/<int:applicant_id>/send-password-reset/', views.send_password_reset, name='send_password_reset'),
    path('admin-applicants/<int:applicant_id>/delete/', views.delete_applicant, name='delete_applicant'),
    
    # AJAX endpoints for location data
    path('api/locations/<int:ward_id>/', views.get_locations_by_ward, name='get_locations_by_ward'),
    path('api/sublocations/<int:location_id>/', views.get_sublocations_by_location, name='get_sublocations_by_location'),
    path('api/villages/<int:sublocation_id>/', views.get_villages_by_sublocation, name='get_villages_by_sublocation'),

    # Fiscal Year URLs
    path('admin-fiscal-years/', views.fiscal_year_list, name='fiscal_year_list'),
    path('admin-fiscal-years/create/', views.fiscal_year_create, name='fiscal_year_create'),
    path('admin-fiscal-years/<int:pk>/', views.fiscal_year_detail, name='fiscal_year_detail'),
    path('admin-fiscal-years/<int:pk>/edit/', views.fiscal_year_update, name='fiscal_year_update'),
    path('admin-fiscal-years/<int:pk>/delete/', views.fiscal_year_delete, name='fiscal_year_delete'),
    path('admin-fiscal-years/<int:pk>/analytics/', views.fiscal_year_analytics, name='fiscal_year_analytics'),
    path('admin-fiscal-years/<int:pk>/toggle-active/', views.fiscal_year_toggle_active, name='fiscal_year_toggle_active'),
    
    # Bursary Category URLs
    path('admin-bursary-categories/', views.bursary_category_list, name='bursary_category_list'),
    path('admin-bursary-categories/create/', views.bursary_category_create, name='bursary_category_create'),
    path('admin-bursary-categories/<int:pk>/update/', views.bursary_category_update, name='bursary_category_update'),
    path('admin-bursary-categories/<int:pk>/', views.bursary_category_detail, name='bursary_category_detail'),
   
    path('category/<int:category_id>/applications/', views.BursaryCategoryApplicationsView.as_view(), name='bursary_category_applications'),
    path('category/<int:category_id>/applications/pdf/', views.bursary_category_applications_pdf,  name='bursary_category_applications_pdf'),
    path('category/<int:category_id>/summary/pdf/', views.bursary_category_summary_pdf, name='bursary_category_summary_pdf'),
    
    # Budget & Allocation

    path('allocations/', views.allocation_list, name='allocation_list'),
    path('allocations/<int:allocation_id>/disburse/', views.disbursement_create, name='disbursement_create'),

    # Bulk cheque assignment page
    path('bulk-cheque/assignment/', views.bulk_cheque_assignment, name='bulk_cheque_assignment'),
    path('bulk-cheque/get-students/', views.get_students_by_institution, name='get_students_by_institution'),
    path('bulk-cheque/assign/', views.assign_bulk_cheque, name='assign_bulk_cheque'),
    path('bulk-cheque/send-notifications/', views.send_bulk_notifications, name='send_bulk_notifications'),
    path('bulk-cheque/<int:cheque_id>/details/', views.bulk_cheque_details, name='bulk_cheque_details'),
    path('bulk-cheque/<int:cheque_id>/details/mark-collected/', views.mark_bulk_cheque_collected, name='mark_bulk_cheque_collected'),
    
    # Institutions
    path('institutions/', views.institution_list, name='institution_list'),
    # AJAX endpoints
    path('institutions/create/', views.institution_create, name='institution_create'),
    path('institutions/<int:pk>/detail/', views.institution_detail, name='institution_detail'),
    path('institutions/<int:pk>/update/', views.institution_update, name='institution_update'),
    path('institutions/<int:pk>/delete/', views.institution_delete, name='institution_delete'),
    path('institutions/search/', views.institution_search, name='institution_search'),

    
    # User Management
  
    path('users/', views.UserManagementView.as_view(), name='user_management'),
    path('admin-users/create/', views.user_create_ajax, name='user_create_ajax'),
    path('admin-users/<int:user_id>/', views.user_detail_ajax, name='user_detail_ajax'),
    path('admin-users/<int:user_id>/update/', views.user_update_ajax, name='user_update_ajax'),
    path('users/<int:user_id>/delete/', views.user_delete_ajax, name='user_delete_ajax'),
    path('admin-users/<int:user_id>/reset-password/', views.user_reset_password_ajax, name='user_reset_password_ajax'),
    
    # Settings
    path('settings/', views.system_settings, name='system_settings'),
    path('announcements/', views.announcement_list, name='announcement_list'),
    path('announcements/create/', views.announcement_create, name='announcement_create'),
    path('faq/', views.faq_list, name='faq_list'),
    
    # Reports graphs 
    path('reports/applications/', views.application_reports, name='application_reports'),
    path('reports/financial/', views.financial_reports, name='financial_reports'),
    path('reports/wards/', views.ward_reports, name='ward_reports'),
    path('reports/institutions/', views.institution_reports, name='institution_reports'),
    
    # Audit
    path('audit-logs/', views.audit_log_list, name='audit_log_list'),
    
    # Ward Management
    path('wards/', views.ward_list, name='ward_list'),
    path('wards/<int:ward_id>/locations/', views.location_list, name='location_list'),

    # Students Dashboard
    path('student/dashboard/', views.student_dashboard, name='student_dashboard'),
    
    # Profile Management
    path('student/profile/create/', views.student_profile_create, name='student_profile_create'),
    path('student/profile/view/', views.student_profile_view, name='student_profile_view'),
    path('student/profile/edit/', views.student_profile_create, name='student_profile_edit'),
    
    # Guardian and Sibling Management
    path('student/guardian/add/', views.student_guardian_create, name='guardian_create'),
    path('student/sibling/add/', views.student_sibling_create, name='sibling_create'),
    
    # Application Management
    path('student/applications/', views.student_application_list, name='student_application_list'),
    path('student/application/new/', views.student_application_create, name='student_application_create'),
    path('get-category-max-amount/', views.get_category_max_amount, name='get_category_max_amount'),
    path('student/application/<int:pk>/', views.student_application_detail, name='student_application_detail'),
    path('student/application/<int:pk>/edit/', views.student_application_edit, name='student_application_edit'),
    path('student/application/<int:pk>/documents/', views.student_application_documents, name='student_application_documents'),
    path('student/application/<int:pk>/submit/', views.student_application_submit, name='student_application_submit'),
    path('application/<int:application_id>/document/<int:document_id>/preview/', views.document_preview, name='document_preview'),
    
    # Document Management
    path('student/document/<int:pk>/delete/', views.student_document_delete, name='student_document_delete'),
    
    # Notifications
    path('student/notifications/', views.notifications_list, name='notifications_list'),
    
    # Information Pages
    path('student/faqs/', views.faqs_view, name='faqs_view'),
    path('student/announcements/', views.announcements_view, name='announcements_view'),
    
    # AJAX endpoints
    path('ajax/locations/', views.get_locations, name='get_locations'),
    path('ajax/sublocations/', views.get_sublocations, name='get_sublocations'),
    path('ajax/villages/', views.get_villages, name='get_villages'),
    path('ajax/application-status/<int:pk>/', views.application_status_check, name='application_status_check'),

    # Admin Profile Settings
    path('admin-profile/', views.admin_profile_settings, name='admin_profile_settings'),
    
    # Help & Support
    path('admin-help/', views.admin_help_support, name='admin_help_support'),
    path('admin-faq/<int:faq_id>/toggle/', views.toggle_faq_status, name='toggle_faq_status'),
    
    # Preferences
    path('admin-preferences/', views.admin_preferences, name='admin_preferences'),
    path('admin-settings/<int:setting_id>/delete/', views.delete_system_setting, name='delete_system_setting'),
    
    # Communication
    path('admin-communication/', views.admin_communication, name='admin_communication'),
    path('admin-announcements/<int:announcement_id>/toggle/', views.toggle_announcement_status, name='toggle_announcement_status'),
    
 
    # Main security dashboard
    path('admin-security-audit/', views.admin_security_audit, name='admin_security_audit'),
    
    # API Endpoints for real-time data
    path('api/security-stats/', views.api_security_stats, name='api_security_stats'),
    path('api/user-activity-chart/', views.api_user_activity_chart, name='api_user_activity_chart'),
    path('api/login-attempts-chart/', views.api_login_attempts_chart, name='api_login_attempts_chart'),
    path('api/threat-distribution/', views.api_threat_distribution, name='api_threat_distribution'),
    path('api/top-urls/', views.api_top_urls, name='api_top_urls'),
    path('api/active-sessions/', views.api_active_sessions, name='api_active_sessions'),
    path('api/security-threats/', views.api_security_threats, name='api_security_threats'),
    path('api/suspicious-activities/', views.api_suspicious_activities, name='api_suspicious_activities'),
    path('api/geo-distribution/', views.api_geo_distribution, name='api_geo_distribution'),
    
    # Action endpoints
    path('security/resolve-threat/<int:threat_id>/', views.resolve_threat, name='resolve_threat'),
    path('security/investigate-activity/<int:activity_id>/', views.investigate_activity, name='investigate_activity'),

    path("ai/dashboard/", views.ai_dashboard, name="ai_dashboard"),
    path("ai/generate/", views.generate_analysis, name="generate_analysis"),
    path("ai/report/<int:report_id>/", views.view_report, name="view_report"),
    path("ai/report/<int:report_id>/delete/", views.delete_report, name="delete_report"),

    # (direct endpoints for specific analysis types)
    path("ai/analysis/demand-forecast/", views.generate_demand_forecast, name="demand_forecast"),
    path("ai/analysis/allocation-prediction/", views.generate_allocation_prediction, name="allocation_prediction"),
    path("ai/analysis/budget-analysis/", views.generate_budget_analysis, name="budget_analysis"),
    path("ai/analysis/performance-trend/", views.generate_performance_trend, name="performance_trend"),
    path("ai/analysis/geographic-analysis/", views.generate_geographic_analysis, name="geographic_analysis"),
    path("ai/analysis/institution-analysis/", views.generate_institution_analysis, name="institution_analysis"),

    # Disbursement Round Management URLs
    path('disbursement-rounds/', views.disbursement_round_list, name='disbursement_round_list'),
    path('disbursement-rounds/create/', views.disbursement_round_create, name='disbursement_round_create'),
    path('disbursement-rounds/<int:round_id>/', views.disbursement_round_detail, name='disbursement_round_detail'),
    path('disbursement-rounds/<int:round_id>/edit/', views.disbursement_round_edit, name='disbursement_round_edit'),
    path('disbursement-rounds/<int:round_id>/toggle-status/', views.disbursement_round_toggle_status, name='disbursement_round_toggle_status'),
    path('disbursement-rounds/<int:round_id>/complete/', views.disbursement_round_complete, name='disbursement_round_complete'),
    path('disbursement-rounds/<int:round_id>/delete/', views.disbursement_round_delete, name='disbursement_round_delete'),
    path('disbursement-rounds/<int:round_id>/applications/', views.disbursement_round_applications, name='disbursement_round_applications'),

    path('export/applicants/', views.export_applicants_to_excel, name='export_applicants'),
    path('export/round/<int:round_id>/applications/', 
         views.export_disbursement_round_applications, 
         name='export_round_applications'),
    
    
    path('reports/', views.public_reports_view, name='public_reports'),
    path('beneficiaries/', views.beneficiaries_list_view, name='beneficiaries_list'),
    path('budget/', views.budget_utilization_view, name='budget_utilization'),
    path('testimonials/', views.testimonials_view, name='testimonials'),
    path('reports-annual/', views.annual_reports_view, name='annual_reports'),
    path('reports/quarterly/', views.quarterly_reports_view, name='quarterly_reports'),
    
    path("documentation/", views.documentation_view, name="documentation"),
    path("user-guide/", views.user_guide_view, name="user_guide"),
    path("contact-support/", views.contact_support_view, name="contact_support"),
    path("search/", views.search_help_view, name="search"),
    path("download/<str:guide_type>/", views.download_guide_view, name="download_guide"),
    path("system-status/", views.system_status_view, name="system_status"),
    path('admin-proposals/', views.proposal_management_view, name='proposal_management'),
    
    # ============= CONSTITUENCY URLS =============
    path('admin-geography/constituencies/', views.constituency_management, name='constituency_management'),
    path('admin-geography/constituencies/create/',  views.constituency_create,  name='constituency_create'),
    path('admin-geography/constituencies/<int:constituency_id>/',  views.constituency_detail,  name='constituency_detail'),
    path('admin-geography/constituencies/<int:constituency_id>/update/',  views.constituency_update,  name='constituency_update'),
    path('admin-geography/constituencies/<int:constituency_id>/delete/',  views.constituency_delete,   name='constituency_delete'),
    # ============= WARD URLS =============
    path('admin-geography/wards/',  views.ward_management,   name='ward_management'),
    path('admin-geography/wards/create/',  views.ward_create,  name='ward_create'),
    path('admin-geography/wards/<int:ward_id>/',  views.ward_detail,  name='ward_detail'),
    path('admin-geography/wards/<int:ward_id>/update/', views.ward_update, name='ward_update'),
    path('admin-geography/wards/<int:ward_id>/delete/',  views.ward_delete,  name='ward_delete'),
    path('api/constituencies/by-county/<int:county_id>/', views.get_constituencies_by_county, name='get_constituencies_by_county'),
    path('api/wards/by-constituency/<int:constituency_id>/', views.get_wards_by_constituency, name='get_wards_by_constituency'),
    
    # ============= NOTIFICATION URLS =============
    path('admin-notifications/all/', views.all_notifications, name='all_notifications'),
    path('admin-notifications/<int:notification_id>/mark-read/', views.mark_notification_read, name='mark_notification_read'),
    path('admin-notifications/mark-all-read/', views.mark_all_read, name='mark_all_read'),
    path('admin-notifications/<int:notification_id>/delete/', views.delete_notification, name='delete_notification'),
    
    # ============= BULK SMS URLS =============
    path('admin-notifications/bulk-sms/', views.bulk_sms, name='bulk_sms'),
    path('admin-notifications/send-bulk-sms/', views.send_bulk_sms, name='send_bulk_sms'),
    path('admin-notifications/sms-logs/',  views.sms_logs, name='sms_logs'),
    # ============= BULK EMAIL URLS =============
    path('admin-notifications/bulk-email/',  views.bulk_email, name='bulk_email'),
    path('admin-notifications/send-bulk-email/', views.send_bulk_email, name='send_bulk_email'),  
    path('admin-notifications/email-logs/', views.email_logs, name='email_logs'),
    path('api/notifications/recipient-count/', views.get_recipient_count, name='get_recipient_count'),
    
]