from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.db.models import Sum, Count, Q
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    User, LoginAttempt, AccountLock, TwoFactorCode, SecurityNotification,
    County, Constituency, Ward, Location, SubLocation, Village,
    Institution, FiscalYear, WardAllocation, BursaryCategory, DisbursementRound,
    Applicant, Guardian, SiblingInformation, Application, Document, Review,
    Allocation, BulkCheque, BulkChequeAllocation,
    Notification, SMSLog, EmailLog, AuditLog, SystemSettings,
    FAQ, Announcement, AIAnalysisReport, PredictionModel, DataSnapshot,
    PublicReport, BeneficiaryTestimonial
)


# ============= CUSTOM USER ADMIN =============

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['username', 'email', 'first_name', 'last_name', 'user_type', 'is_active', 'date_joined']
    list_filter = ['user_type', 'is_active', 'is_staff', 'date_joined']
    search_fields = ['username', 'email', 'first_name', 'last_name', 'id_number', 'phone_number']

    # FIX: Convert existing fieldsets to list
    fieldsets = list(BaseUserAdmin.fieldsets) + [
        ('Additional Info', {
            'fields': ('user_type', 'id_number', 'phone_number'),
        }),
    ]

    # FIX: Convert existing add_fieldsets to list
    add_fieldsets = list(BaseUserAdmin.add_fieldsets) + [
        ('Additional Info', {
            'fields': ('user_type', 'id_number', 'phone_number', 'email', 'first_name', 'last_name'),
        }),
    ]



# ============= SECURITY MODELS ADMIN =============

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['username', 'ip_address', 'timestamp', 'success', 'user_agent_short']
    list_filter = ['success', 'timestamp']
    search_fields = ['username', 'ip_address']
    readonly_fields = ['username', 'ip_address', 'timestamp', 'success', 'user_agent']
    date_hierarchy = 'timestamp'
    
    def user_agent_short(self, obj):
        return obj.user_agent[:50] + '...' if obj.user_agent and len(obj.user_agent) > 50 else obj.user_agent
    user_agent_short.short_description = 'User Agent'
    
    def has_add_permission(self, request):
        return False


@admin.register(AccountLock)
class AccountLockAdmin(admin.ModelAdmin):
    list_display = ['user', 'locked_at', 'failed_attempts', 'is_locked', 'unlock_time']
    list_filter = ['is_locked', 'locked_at']
    search_fields = ['user__username', 'user__email', 'last_attempt_ip']
    readonly_fields = ['locked_at', 'failed_attempts']
    actions = ['unlock_accounts']
    
    def unlock_accounts(self, request, queryset):
        updated = queryset.update(is_locked=False)
        self.message_user(request, f'{updated} account(s) unlocked successfully.')
    unlock_accounts.short_description = 'Unlock selected accounts'


@admin.register(TwoFactorCode)
class TwoFactorCodeAdmin(admin.ModelAdmin):
    list_display = ['user', 'code', 'created_at', 'expires_at', 'used', 'is_valid_status']
    list_filter = ['used', 'created_at']
    search_fields = ['user__username', 'code', 'ip_address']
    readonly_fields = ['code', 'created_at', 'expires_at', 'used', 'used_at', 'ip_address', 'session_key']
    
    def is_valid_status(self, obj):
        if obj.is_valid():
            return format_html('<span style="color: green;">✓ Valid</span>')
        return format_html('<span style="color: red;">✗ Invalid/Expired</span>')
    is_valid_status.short_description = 'Status'
    
    def has_add_permission(self, request):
        return False


@admin.register(SecurityNotification)
class SecurityNotificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'notification_type', 'timestamp', 'email_sent', 'ip_address']
    list_filter = ['notification_type', 'email_sent', 'timestamp']
    search_fields = ['user__username', 'message', 'ip_address']
    readonly_fields = ['timestamp', 'email_sent_at']
    date_hierarchy = 'timestamp'


# ============= ADMINISTRATIVE HIERARCHY ADMIN =============

@admin.register(County)
class CountyAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'headquarters', 'governor_name', 'is_active', 'constituency_count']
    list_filter = ['is_active']
    search_fields = ['name', 'code', 'headquarters', 'governor_name']
    readonly_fields = ['created_at', 'constituency_count']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'code', 'headquarters', 'population', 'is_active' , 'system_county')
        }),
        ('County Government', {
            'fields': ('governor_name', 'county_website')
        }),
        ('Treasury Contacts', {
            'fields': ('treasury_email', 'treasury_phone')
        }),
        ('Education Department', {
            'fields': ('education_cec_name', 'education_office_email', 'education_office_phone')
        }),
        ('System Info', {
            'fields': ('created_at', 'constituency_count')
        }),
    )
    
    def constituency_count(self, obj):
        return obj.constituencies.count()
    constituency_count.short_description = 'Constituencies'


class WardInline(admin.TabularInline):
    model = Ward
    extra = 0
    fields = ['name', 'code', 'current_mca', 'mca_phone', 'is_active']


@admin.register(Constituency)
class ConstituencyAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'county', 'current_mp', 'cdf_bursary_allocation', 'is_active', 'ward_count']
    list_filter = ['county', 'is_active']
    search_fields = ['name', 'code', 'current_mp']
    inlines = [WardInline]
    readonly_fields = ['ward_count']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'code', 'county', 'population', 'is_active')
        }),
        ('MP & CDF Office', {
            'fields': ('current_mp', 'mp_party', 'cdf_office_location', 'cdf_office_email', 'cdf_office_phone')
        }),
        ('CDF Allocations', {
            'fields': ('annual_cdf_allocation', 'cdf_bursary_allocation')
        }),
        ('Statistics', {
            'fields': ('ward_count',)
        }),
    )
    
    def ward_count(self, obj):
        return obj.wards.count()
    ward_count.short_description = 'Number of Wards'


@admin.register(Ward)
class WardAdmin(admin.ModelAdmin):
    list_display = ['name', 'constituency', 'county_name', 'current_mca', 'population', 'is_active']
    list_filter = ['constituency__county', 'constituency', 'is_active']
    search_fields = ['name', 'current_mca']
    
    def county_name(self, obj):
        return obj.constituency.county.name
    county_name.short_description = 'County'


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = ['name', 'ward', 'population']
    list_filter = ['ward__constituency__county', 'ward']
    search_fields = ['name']


@admin.register(SubLocation)
class SubLocationAdmin(admin.ModelAdmin):
    list_display = ['name', 'location', 'ward_name']
    list_filter = ['location__ward']
    search_fields = ['name']
    
    def ward_name(self, obj):
        return obj.location.ward.name
    ward_name.short_description = 'Ward'


@admin.register(Village)
class VillageAdmin(admin.ModelAdmin):
    list_display = ['name', 'sublocation', 'village_elder', 'elder_phone']
    list_filter = ['sublocation__location__ward']
    search_fields = ['name', 'village_elder']


# ============= INSTITUTION ADMIN =============

@admin.register(Institution)
class InstitutionAdmin(admin.ModelAdmin):
    list_display = ['name', 'institution_type', 'county', 'principal_name', 'phone_number', 'is_active', 'application_count']
    list_filter = ['institution_type', 'county', 'is_active']
    search_fields = ['name', 'principal_name', 'email']
    readonly_fields = ['application_count']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'institution_type', 'county', 'sub_county', 'is_active')
        }),
        ('Contact Details', {
            'fields': ('postal_address', 'physical_address', 'phone_number', 'email')
        }),
        ('Principal/Head', {
            'fields': ('principal_name', 'principal_phone', 'principal_email')
        }),
        ('Banking Details', {
            'fields': ('bank_name', 'bank_branch', 'account_number', 'account_name')
        }),
        ('Statistics', {
            'fields': ('application_count',)
        }),
    )
    
    def application_count(self, obj):
        count = obj.application_set.count()
        return format_html('<a href="{}?institution__id__exact={}">{}</a>', 
                          reverse('admin:main_application_application_changelist'), obj.id, count)
    application_count.short_description = 'Applications'


# ============= FISCAL YEAR & BUDGET ADMIN =============

class WardAllocationInline(admin.TabularInline):
    model = WardAllocation
    extra = 0
    readonly_fields = ['balance']
    fields = ['ward', 'allocated_amount', 'spent_amount', 'balance', 'beneficiaries_count']


class DisbursementRoundInline(admin.TabularInline):
    model = DisbursementRound
    extra = 0
    fields = ['round_number', 'name', 'application_start_date', 'application_end_date', 'is_open']


@admin.register(FiscalYear)
class FiscalYearAdmin(admin.ModelAdmin):
    list_display = ['name', 'county', 'start_date', 'end_date', 'total_bursary_allocation', 
                   'is_active', 'application_open', 'application_count']
    list_filter = ['county', 'is_active', 'application_open']
    search_fields = ['name']
    inlines = [DisbursementRoundInline, WardAllocationInline]
    readonly_fields = ['created_at', 'application_count', 'total_allocated', 'total_disbursed']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'county', 'start_date', 'end_date', 'number_of_disbursement_rounds')
        }),
        ('Budget Allocations', {
            'fields': ('total_county_budget', 'education_budget', 'total_bursary_allocation')
        }),
        ('National Treasury Transfers', {
            'fields': ('equitable_share', 'conditional_grants')
        }),
        ('Application Settings', {
            'fields': ('is_active', 'application_open', 'application_deadline')
        }),
        ('System Info', {
            'fields': ('created_at', 'created_by', 'application_count', 'total_allocated', 'total_disbursed')
        }),
    )
    
    def application_count(self, obj):
        return obj.application_set.count()
    application_count.short_description = 'Applications'
    
    def total_allocated(self, obj):
        total = obj.application_set.filter(
            allocation__isnull=False
        ).aggregate(Sum('allocation__amount_allocated'))['allocation__amount_allocated__sum'] or 0
        return f'KES {total:,.2f}'
    total_allocated.short_description = 'Total Allocated'
    
    def total_disbursed(self, obj):
        total = obj.application_set.filter(
            allocation__is_disbursed=True
        ).aggregate(Sum('allocation__amount_allocated'))['allocation__amount_allocated__sum'] or 0
        return f'KES {total:,.2f}'
    total_disbursed.short_description = 'Total Disbursed'


@admin.register(WardAllocation)
class WardAllocationAdmin(admin.ModelAdmin):
    list_display = ['ward', 'fiscal_year', 'allocated_amount', 'spent_amount', 'balance_display', 'beneficiaries_count']
    list_filter = ['fiscal_year', 'ward__constituency__county']
    search_fields = ['ward__name']
    readonly_fields = ['balance_display']
    
    def balance_display(self, obj):
        balance = obj.balance()
        color = 'green' if balance > 0 else 'red'
        return format_html('<span style="color: {};">KES {:,.2f}</span>', color, balance)
    balance_display.short_description = 'Balance'


@admin.register(BursaryCategory)
class BursaryCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'category_type', 'fiscal_year', 'allocation_amount', 
                   'max_amount_per_applicant', 'target_beneficiaries', 'is_active']
    list_filter = ['category_type', 'fiscal_year', 'is_active']
    search_fields = ['name']


@admin.register(DisbursementRound)
class DisbursementRoundAdmin(admin.ModelAdmin):
    list_display = ['name', 'fiscal_year', 'round_number', 'application_start_date', 
                   'application_end_date', 'disbursement_date', 'is_open', 'is_completed']
    list_filter = ['fiscal_year', 'is_open', 'is_completed']
    search_fields = ['name']
    date_hierarchy = 'application_start_date'


# ============= APPLICANT ADMIN =============

class GuardianInline(admin.TabularInline):
    model = Guardian
    extra = 1
    fields = ['name', 'relationship', 'phone_number', 'employment_status', 'monthly_income', 'is_primary_contact']


class SiblingInline(admin.TabularInline):
    model = SiblingInformation
    extra = 1
    fields = ['name', 'age', 'education_level', 'is_in_school']


@admin.register(Applicant)
class ApplicantAdmin(admin.ModelAdmin):
    list_display = ['full_name', 'id_number', 'gender', 'ward', 'is_verified', 'application_count', 'created_at']
    list_filter = ['gender', 'is_verified', 'county', 'constituency', 'ward', 'special_needs']
    search_fields = ['user__first_name', 'user__last_name', 'id_number', 'user__email']
    readonly_fields = ['created_at', 'verification_date', 'application_count']
    inlines = [GuardianInline, SiblingInline]
    
    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Personal Information', {
            'fields': ('gender', 'date_of_birth', 'id_number', 'profile_picture')
        }),
        ('Location', {
            'fields': ('county', 'constituency', 'ward', 'location', 'sublocation', 'village')
        }),
        ('Address', {
            'fields': ('physical_address', 'postal_address')
        }),
        ('Special Circumstances', {
            'fields': ('special_needs', 'special_needs_description')
        }),
        ('Verification', {
            'fields': ('is_verified', 'verified_by', 'verification_date')
        }),
        ('System Info', {
            'fields': ('created_at', 'application_count')
        }),
    )
    
    def full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"
    full_name.short_description = 'Name'
    
    def application_count(self, obj):
        count = obj.applications.count()
        return format_html('<a href="{}?applicant__id__exact={}">{}</a>', 
                          reverse('admin:main_application_application_changelist'), obj.id, count)
    application_count.short_description = 'Applications'
    
    actions = ['verify_applicants']
    
    def verify_applicants(self, request, queryset):
        updated = queryset.update(is_verified=True, verified_by=request.user)
        self.message_user(request, f'{updated} applicant(s) verified successfully.')
    verify_applicants.short_description = 'Verify selected applicants'


@admin.register(Guardian)
class GuardianAdmin(admin.ModelAdmin):
    list_display = ['name', 'applicant', 'relationship', 'phone_number', 'employment_status', 'monthly_income', 'is_primary_contact']
    list_filter = ['relationship', 'employment_status', 'is_primary_contact']
    search_fields = ['name', 'phone_number', 'applicant__user__first_name', 'applicant__user__last_name']


@admin.register(SiblingInformation)
class SiblingInformationAdmin(admin.ModelAdmin):
    list_display = ['name', 'applicant', 'age', 'education_level', 'school_name', 'is_in_school']
    list_filter = ['is_in_school']
    search_fields = ['name', 'school_name']


# ============= APPLICATION ADMIN =============

class DocumentInline(admin.TabularInline):
    model = Document
    extra = 0
    readonly_fields = ['uploaded_at', 'is_verified']
    fields = ['document_type', 'file', 'description', 'is_verified', 'uploaded_at']


class ReviewInline(admin.TabularInline):
    model = Review
    extra = 0
    readonly_fields = ['review_date']
    fields = ['reviewer', 'review_level', 'recommendation', 'recommended_amount', 'review_date']


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['application_number', 'applicant_name', 'institution', 'status', 
                   'amount_requested', 'priority_score', 'date_submitted', 'allocation_link']
    list_filter = ['status', 'fiscal_year', 'bursary_category', 'bursary_source', 
                  'is_orphan', 'is_disabled', 'date_submitted']
    search_fields = ['application_number', 'applicant__user__first_name', 
                    'applicant__user__last_name', 'applicant__id_number']
    readonly_fields = ['application_number', 'date_submitted', 'last_updated', 'priority_score']
    inlines = [DocumentInline, ReviewInline]
    date_hierarchy = 'date_submitted'
    
    fieldsets = (
        ('Application Details', {
            'fields': ('application_number', 'applicant', 'fiscal_year', 'disbursement_round', 
                      'bursary_category', 'bursary_source', 'status')
        }),
        ('Institution & Academic Info', {
            'fields': ('institution', 'admission_number', 'year_of_study', 'course_name', 
                      'expected_completion_date', 'previous_academic_year_average')
        }),
        ('Financial Information', {
            'fields': ('total_fees_payable', 'fees_paid', 'fees_balance', 'amount_requested')
        }),
        ('Other Bursaries', {
            'fields': ('other_bursaries', 'other_bursaries_amount', 'other_bursaries_source')
        }),
        ('Family Situation', {
            'fields': ('is_orphan', 'is_total_orphan', 'is_disabled', 'has_chronic_illness', 
                      'chronic_illness_description')
        }),
        ('Household Info', {
            'fields': ('number_of_siblings', 'number_of_siblings_in_school', 'household_monthly_income')
        }),
        ('Previous Allocations', {
            'fields': ('has_received_previous_allocation', 'previous_allocation_year', 
                      'previous_allocation_amount')
        }),
        ('System Info', {
            'fields': ('priority_score', 'date_submitted', 'last_updated')
        }),
    )
    
    def applicant_name(self, obj):
        return obj.applicant.user.get_full_name()
    applicant_name.short_description = 'Applicant'
    
    def allocation_link(self, obj):
        if hasattr(obj, 'allocation'):
            url = reverse('admin:main_application_allocation_change', args=[obj.allocation.id])
            return format_html('<a href="{}">View Allocation</a>', url)
        return '-'
    allocation_link.short_description = 'Allocation'
    
    actions = ['approve_applications', 'reject_applications']
    
    def approve_applications(self, request, queryset):
        updated = queryset.update(status='approved')
        self.message_user(request, f'{updated} application(s) approved.')
    approve_applications.short_description = 'Approve selected applications'
    
    def reject_applications(self, request, queryset):
        updated = queryset.update(status='rejected')
        self.message_user(request, f'{updated} application(s) rejected.')
    reject_applications.short_description = 'Reject selected applications'


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ['document_type', 'application_number', 'applicant_name', 'uploaded_at', 
                   'is_verified', 'verified_by']
    list_filter = ['document_type', 'is_verified', 'uploaded_at']
    search_fields = ['application__application_number', 'description']
    readonly_fields = ['uploaded_at']
    date_hierarchy = 'uploaded_at'
    
    def application_number(self, obj):
        return obj.application.application_number
    application_number.short_description = 'Application'
    
    def applicant_name(self, obj):
        return obj.application.applicant.user.get_full_name()
    applicant_name.short_description = 'Applicant'
    
    actions = ['verify_documents']
    
    def verify_documents(self, request, queryset):
        updated = queryset.update(is_verified=True, verified_by=request.user)
        self.message_user(request, f'{updated} document(s) verified.')
    verify_documents.short_description = 'Verify selected documents'


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ['application_number', 'reviewer', 'review_level', 'recommendation', 
                   'recommended_amount', 'review_date']
    list_filter = ['review_level', 'recommendation', 'review_date']
    search_fields = ['application__application_number', 'comments']
    readonly_fields = ['review_date']
    date_hierarchy = 'review_date'
    
    def application_number(self, obj):
        return obj.application.application_number
    application_number.short_description = 'Application'


# ============= ALLOCATION & DISBURSEMENT ADMIN =============

@admin.register(Allocation)
class AllocationAdmin(admin.ModelAdmin):
    list_display = ['application_number', 'applicant_name', 'amount_allocated', 
                   'allocation_date', 'payment_method', 'is_disbursed', 'is_received_by_institution']
    list_filter = ['payment_method', 'is_disbursed', 'is_received_by_institution', 'allocation_date']
    search_fields = ['application__application_number', 'cheque_number']
    readonly_fields = ['allocation_date']
    date_hierarchy = 'allocation_date'
    
    fieldsets = (
        ('Allocation Details', {
            'fields': ('application', 'amount_allocated', 'allocation_date', 'approved_by')
        }),
        ('Payment Details', {
            'fields': ('payment_method', 'cheque_number')
        }),
        ('Disbursement', {
            'fields': ('is_disbursed', 'disbursement_date', 'disbursed_by')
        }),
        ('Institution Confirmation', {
            'fields': ('is_received_by_institution', 'institution_confirmation_date', 
                      'institution_receipt_number')
        }),
        ('Additional Info', {
            'fields': ('remarks',)
        }),
    )
    
    def application_number(self, obj):
        return obj.application.application_number
    application_number.short_description = 'Application'
    
    def applicant_name(self, obj):
        return obj.application.applicant.user.get_full_name()
    applicant_name.short_description = 'Applicant'
    
    actions = ['mark_as_disbursed']
    
    def mark_as_disbursed(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(is_disbursed=True, disbursement_date=timezone.now().date(), 
                                 disbursed_by=request.user)
        self.message_user(request, f'{updated} allocation(s) marked as disbursed.')
    mark_as_disbursed.short_description = 'Mark as disbursed'


class BulkChequeAllocationInline(admin.TabularInline):
    model = BulkChequeAllocation
    extra = 0
    readonly_fields = ['allocation', 'is_notified']
    fields = ['allocation', 'is_notified', 'notification_sent_date']


@admin.register(BulkCheque)
class BulkChequeAdmin(admin.ModelAdmin):
    list_display = ['cheque_number', 'institution', 'fiscal_year', 'total_amount', 
                   'student_count', 'is_collected', 'created_date']
    list_filter = ['is_collected', 'fiscal_year', 'created_date']
    search_fields = ['cheque_number', 'institution__name', 'cheque_holder_name']
    readonly_fields = ['created_date', 'assigned_date', 'collection_date']
    inlines = [BulkChequeAllocationInline]
    date_hierarchy = 'created_date'
    
    fieldsets = (
        ('Cheque Details', {
            'fields': ('cheque_number', 'institution', 'fiscal_year', 'disbursement_round', 
                      'total_amount', 'student_count')
        }),
        ('Cheque Holder', {
            'fields': ('cheque_holder_name', 'cheque_holder_id', 'cheque_holder_phone', 
                      'cheque_holder_email', 'cheque_holder_position')
        }),
        ('Status & Dates', {
            'fields': ('created_date', 'assigned_date', 'is_collected', 'collection_date', 
                      'collector_id_number')
        }),
        ('System Info', {
            'fields': ('created_by', 'assigned_by', 'notes')
        }),
    )
    
    actions = ['mark_as_collected']
    
    def mark_as_collected(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(is_collected=True, collection_date=timezone.now())
        self.message_user(request, f'{updated} bulk cheque(s) marked as collected.')
    mark_as_collected.short_description = 'Mark as collected'


@admin.register(BulkChequeAllocation)
class BulkChequeAllocationAdmin(admin.ModelAdmin):
    list_display = ['bulk_cheque_number', 'applicant_name', 'amount', 'is_notified']
    list_filter = ['is_notified', 'bulk_cheque__fiscal_year']
    search_fields = ['bulk_cheque__cheque_number', 'allocation__application__applicant__user__first_name']
    
    def bulk_cheque_number(self, obj):
        return obj.bulk_cheque.cheque_number
    bulk_cheque_number.short_description = 'Bulk Cheque'
    
    def applicant_name(self, obj):
        return obj.allocation.application.applicant.user.get_full_name()
    applicant_name.short_description = 'Applicant'
    
    def amount(self, obj):
        return obj.allocation.amount_allocated
    amount.short_description = 'Amount'


# ============= NOTIFICATION ADMIN =============

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['title', 'user', 'notification_type', 'is_read', 'created_at']
    list_filter = ['notification_type', 'is_read', 'created_at']
    search_fields = ['title', 'message', 'user__username']
    readonly_fields = ['created_at', 'read_at']
    date_hierarchy = 'created_at'


@admin.register(SMSLog)
class SMSLogAdmin(admin.ModelAdmin):
    list_display = ['phone_number', 'recipient_name', 'status', 'sent_at', 'cost', 'message_preview']
    list_filter = ['status', 'sent_at']
    search_fields = ['phone_number', 'message', 'recipient__username']
    readonly_fields = ['sent_at', 'delivery_time']
    date_hierarchy = 'sent_at'
    
    def recipient_name(self, obj):
        return obj.recipient.get_full_name() if obj.recipient else '-'
    recipient_name.short_description = 'Recipient'
    
    def message_preview(self, obj):
        return obj.message[:50] + '...' if len(obj.message) > 50 else obj.message
    message_preview.short_description = 'Message'


@admin.register(EmailLog)
class EmailLogAdmin(admin.ModelAdmin):
    list_display = ['email_address', 'recipient_name', 'subject', 'status', 'sent_at', 'has_attachments']
    list_filter = ['status', 'has_attachments', 'sent_at']
    search_fields = ['email_address', 'subject', 'message']
    readonly_fields = ['sent_at', 'delivered_at']
    date_hierarchy = 'sent_at'
    
    def recipient_name(self, obj):
        return obj.recipient.get_full_name() if obj.recipient else '-'
    recipient_name.short_description = 'Recipient'


# ============= AUDIT & SYSTEM ADMIN =============

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'table_affected', 'record_id', 'timestamp', 'ip_address']
    list_filter = ['action', 'table_affected', 'timestamp']
    search_fields = ['user__username', 'description', 'table_affected', 'record_id']
    readonly_fields = ['user', 'action', 'table_affected', 'record_id', 'description', 
                      'ip_address', 'user_agent', 'old_values', 'new_values', 'timestamp']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ['setting_name', 'setting_category', 'setting_value_preview', 'is_active', 'last_updated']
    list_filter = ['setting_category', 'is_active']
    search_fields = ['setting_name', 'description']
    readonly_fields = ['last_updated']
    
    fieldsets = (
        ('Setting Information', {
            'fields': ('setting_name', 'setting_category', 'setting_value', 'description')
        }),
        ('Status', {
            'fields': ('is_active', 'last_updated', 'updated_by')
        }),
    )
    
    def setting_value_preview(self, obj):
        return obj.setting_value[:50] + '...' if len(obj.setting_value) > 50 else obj.setting_value
    setting_value_preview.short_description = 'Value'


# ============= PUBLIC INFORMATION ADMIN =============

@admin.register(FAQ)
class FAQAdmin(admin.ModelAdmin):
    list_display = ['question_preview', 'category', 'is_active', 'order', 'views_count', 'updated_at']
    list_filter = ['category', 'is_active']
    search_fields = ['question', 'answer']
    readonly_fields = ['views_count', 'created_at', 'updated_at']
    list_editable = ['order', 'is_active']
    
    fieldsets = (
        ('FAQ Content', {
            'fields': ('question', 'answer', 'category')
        }),
        ('Display Settings', {
            'fields': ('is_active', 'order')
        }),
        ('Statistics', {
            'fields': ('views_count', 'created_at', 'updated_at')
        }),
    )
    
    def question_preview(self, obj):
        return obj.question[:80] + '...' if len(obj.question) > 80 else obj.question
    question_preview.short_description = 'Question'


@admin.register(Announcement)
class AnnouncementAdmin(admin.ModelAdmin):
    list_display = ['title', 'announcement_type', 'published_date', 'expiry_date', 
                   'is_active', 'is_featured', 'target_audience']
    list_filter = ['announcement_type', 'is_active', 'is_featured', 'target_audience', 'published_date']
    search_fields = ['title', 'content']
    readonly_fields = ['created_at']
    date_hierarchy = 'published_date'
    list_editable = ['is_active', 'is_featured']
    
    fieldsets = (
        ('Announcement Details', {
            'fields': ('title', 'content', 'announcement_type', 'target_audience')
        }),
        ('Publishing', {
            'fields': ('published_date', 'expiry_date', 'is_active', 'is_featured')
        }),
        ('System Info', {
            'fields': ('created_by', 'created_at')
        }),
    )


# ============= AI/ANALYTICS ADMIN =============

@admin.register(AIAnalysisReport)
class AIAnalysisReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'report_type', 'fiscal_year', 'generated_date', 
                   'accuracy_score', 'confidence_level', 'is_archived']
    list_filter = ['report_type', 'fiscal_year', 'is_archived', 'generated_date']
    search_fields = ['title']
    readonly_fields = ['generated_date']
    date_hierarchy = 'generated_date'
    
    fieldsets = (
        ('Report Information', {
            'fields': ('title', 'report_type', 'fiscal_year')
        }),
        ('Analysis Data', {
            'fields': ('analysis_data', 'predictions', 'recommendations')
        }),
        ('Quality Metrics', {
            'fields': ('accuracy_score', 'confidence_level')
        }),
        ('System Info', {
            'fields': ('generated_date', 'generated_by', 'report_file', 'is_archived')
        }),
    )


@admin.register(PredictionModel)
class PredictionModelAdmin(admin.ModelAdmin):
    list_display = ['name', 'model_type', 'version', 'accuracy', 'is_active', 
                   'training_date', 'last_retrained']
    list_filter = ['model_type', 'is_active', 'training_date']
    search_fields = ['name']
    readonly_fields = ['training_date']
    
    fieldsets = (
        ('Model Information', {
            'fields': ('name', 'model_type', 'version', 'is_active')
        }),
        ('Model Data', {
            'fields': ('model_parameters', 'feature_importance')
        }),
        ('Performance Metrics', {
            'fields': ('accuracy', 'precision', 'recall', 'f1_score')
        }),
        ('Training Information', {
            'fields': ('training_data_size', 'training_date', 'last_retrained', 'created_by')
        }),
    )


@admin.register(DataSnapshot)
class DataSnapshotAdmin(admin.ModelAdmin):
    list_display = ['snapshot_date', 'fiscal_year', 'total_applications', 'approved_applications', 
                   'total_allocated_display', 'approval_rate_display']
    list_filter = ['fiscal_year', 'snapshot_date']
    search_fields = ['fiscal_year__name']
    readonly_fields = ['created_at']
    date_hierarchy = 'snapshot_date'
    
    fieldsets = (
        ('Snapshot Information', {
            'fields': ('snapshot_date', 'fiscal_year')
        }),
        ('Application Statistics', {
            'fields': ('total_applications', 'approved_applications', 'rejected_applications', 
                      'pending_applications')
        }),
        ('Financial Data', {
            'fields': ('total_requested', 'total_allocated', 'total_disbursed', 
                      'average_amount_requested', 'average_amount_allocated')
        }),
        ('Distribution Data', {
            'fields': ('gender_distribution', 'ward_distribution', 'constituency_distribution', 
                      'institution_distribution', 'category_distribution')
        }),
        ('Metrics', {
            'fields': ('approval_rate',)
        }),
        ('System Info', {
            'fields': ('created_at',)
        }),
    )
    
    def total_allocated_display(self, obj):
        return f'KES {obj.total_allocated:,.2f}'
    total_allocated_display.short_description = 'Total Allocated'
    
    def approval_rate_display(self, obj):
        return f'{obj.approval_rate}%'
    approval_rate_display.short_description = 'Approval Rate'


# ============= TRANSPARENCY & REPORTING ADMIN =============

@admin.register(PublicReport)
class PublicReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'report_type', 'fiscal_year', 'period_covered', 
                   'is_published', 'download_count', 'published_date']
    list_filter = ['report_type', 'fiscal_year', 'is_published', 'published_date']
    search_fields = ['title', 'summary']
    readonly_fields = ['published_date', 'download_count']
    date_hierarchy = 'published_date'
    list_editable = ['is_published']
    
    fieldsets = (
        ('Report Details', {
            'fields': ('title', 'report_type', 'fiscal_year', 'period_covered', 'summary')
        }),
        ('File', {
            'fields': ('report_file',)
        }),
        ('Publishing', {
            'fields': ('is_published', 'published_by', 'published_date')
        }),
        ('Statistics', {
            'fields': ('download_count',)
        }),
    )


@admin.register(BeneficiaryTestimonial)
class BeneficiaryTestimonialAdmin(admin.ModelAdmin):
    list_display = ['applicant_name', 'allocation_amount', 'submitted_date', 
                   'is_approved', 'is_featured', 'approved_by']
    list_filter = ['is_approved', 'is_featured', 'submitted_date']
    search_fields = ['applicant__user__first_name', 'applicant__user__last_name', 'testimonial_text']
    readonly_fields = ['submitted_date', 'approval_date']
    date_hierarchy = 'submitted_date'
    list_editable = ['is_approved', 'is_featured']
    
    fieldsets = (
        ('Beneficiary Information', {
            'fields': ('applicant', 'allocation')
        }),
        ('Testimonial', {
            'fields': ('testimonial_text', 'photo')
        }),
        ('Approval', {
            'fields': ('is_approved', 'is_featured', 'approved_by', 'approval_date')
        }),
        ('System Info', {
            'fields': ('submitted_date',)
        }),
    )
    
    def applicant_name(self, obj):
        return obj.applicant.user.get_full_name()
    applicant_name.short_description = 'Applicant'
    
    def allocation_amount(self, obj):
        return f'KES {obj.allocation.amount_allocated:,.2f}'
    allocation_amount.short_description = 'Amount'
    
    actions = ['approve_testimonials', 'feature_testimonials']
    
    def approve_testimonials(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(is_approved=True, approved_by=request.user, 
                                 approval_date=timezone.now())
        self.message_user(request, f'{updated} testimonial(s) approved.')
    approve_testimonials.short_description = 'Approve selected testimonials'
    
    def feature_testimonials(self, request, queryset):
        updated = queryset.update(is_featured=True)
        self.message_user(request, f'{updated} testimonial(s) featured.')
    feature_testimonials.short_description = 'Feature selected testimonials'


# ============= ADMIN SITE CUSTOMIZATION =============

# Customize admin site header and title
admin.site.site_header = "Kenya Bursary Management System"
admin.site.site_title = "Bursary Admin Portal"
admin.site.index_title = "Welcome to Bursary Management Dashboard"


# ============= CUSTOM ADMIN ACTIONS =============

def export_as_csv(modeladmin, request, queryset):
    """
    Generic export as CSV action
    """
    import csv
    from django.http import HttpResponse
    
    meta = modeladmin.model._meta
    field_names = [field.name for field in meta.fields]
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename={meta}.csv'
    writer = csv.writer(response)
    
    writer.writerow(field_names)
    for obj in queryset:
        writer.writerow([getattr(obj, field) for field in field_names])
    
    return response

export_as_csv.short_description = "Export Selected as CSV"


# Add export action to relevant admin classes
ApplicationAdmin.actions.append(export_as_csv)
AllocationAdmin.actions.append(export_as_csv)
ApplicantAdmin.actions.append(export_as_csv)