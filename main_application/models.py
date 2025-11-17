from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.utils import timezone
from datetime import timedelta
import uuid
import random
import string

class User(AbstractUser):
    """
    Extended User model for authentication
    """
    USER_TYPES = (
        ('applicant', 'Applicant'),
        ('admin', 'Administrator'),
        ('reviewer', 'Application Reviewer'),
        ('finance', 'Finance Officer'),
        ('county_admin', 'County Administrator'),
        ('constituency_admin', 'Constituency Administrator'),
        ('ward_admin', 'Ward Administrator'),
    )
    
    user_type = models.CharField(max_length=25, choices=USER_TYPES, default='applicant')
    id_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    phone_regex = RegexValidator(
        regex=r'^\+254\d{9}$',
        message="Phone number must be entered in the format: '+254XXXXXXXXX'. Exactly 12 digits including country code."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True)
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.user_type})"


class LoginAttempt(models.Model):
    """
    Track login attempts for security purposes
    """
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    user_agent = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"Login attempt for {self.username} at {self.timestamp}"


class AccountLock(models.Model):
    """
    Track locked accounts
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='account_lock')
    locked_at = models.DateTimeField(auto_now_add=True)
    failed_attempts = models.PositiveIntegerField(default=0)
    last_attempt_ip = models.GenericIPAddressField(null=True, blank=True)
    unlock_time = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=True)
    
    def is_account_locked(self):
        if not self.is_locked:
            return False
        if self.unlock_time and timezone.now() > self.unlock_time:
            self.is_locked = False
            self.save()
            return False
        return True
    
    def __str__(self):
        return f"Account lock for {self.user.username}"


class TwoFactorCode(models.Model):
    """
    Store 2FA verification codes
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tfa_codes')
    code = models.CharField(max_length=7)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    session_key = models.CharField(max_length=40)
    
    def save(self, *args, **kwargs):
        if not self.code:
            digits = ''.join(random.choices(string.digits, k=6))
            self.code = f"{digits[:3]}-{digits[3:]}"
        
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=2)
        
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        return not self.used and not self.is_expired()
    
    def mark_as_used(self):
        self.used = True
        self.used_at = timezone.now()
        self.save()
    
    def time_remaining(self):
        if self.is_expired():
            return 0
        return int((self.expires_at - timezone.now()).total_seconds())
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"2FA Code for {self.user.username} - {self.code}"


class SecurityNotification(models.Model):
    """
    Security-related notifications sent to users
    """
    NOTIFICATION_TYPES = (
        ('failed_login', 'Failed Login Attempt'),
        ('account_locked', 'Account Locked'),
        ('tfa_code', '2FA Code'),
        ('successful_login', 'Successful Login'),
        ('account_unlocked', 'Account Unlocked'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
    email_sent = models.BooleanField(default=False)
    email_sent_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.get_notification_type_display()} for {self.user.username}"


# ============= ADMINISTRATIVE HIERARCHY MODELS =============

class County(models.Model):
    """
    County information - top level administrative unit
    Based on Kenya's 47 counties
    """
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=10, unique=True)  # e.g., "047" for Murang'a
    headquarters = models.CharField(max_length=100, blank=True, null=True)
    population = models.PositiveIntegerField(blank=True, null=True)
    
    # County Government contacts
    governor_name = models.CharField(max_length=200, blank=True, null=True)
    county_website = models.URLField(blank=True, null=True)
    
    # County Treasury contact
    treasury_email = models.EmailField(blank=True, null=True)
    treasury_phone = models.CharField(max_length=20, blank=True, null=True)
    
    # County Education Department contact
    education_cec_name = models.CharField(max_length=200, blank=True, null=True)
    education_office_email = models.EmailField(blank=True, null=True)
    education_office_phone = models.CharField(max_length=20, blank=True, null=True)

    #  identifies which county this system instance belongs to
    system_county = models.CharField(
        max_length=100,
        help_text="County this bursary system instance is configured for.",
        default="Murang'a"  # You can set a default for each county installation
    )
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name_plural = "Counties"
        ordering = ['name']
    
    def __str__(self):
        return self.name


class Constituency(models.Model):
    """
    Parliamentary constituencies within the county
    Each constituency has NG-CDF bursary (separate from county bursary)
    """
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10)
    county = models.ForeignKey(County, on_delete=models.CASCADE, related_name='constituencies')
    
    # MP and CDF office details
    current_mp = models.CharField(max_length=200, blank=True, null=True)
    mp_party = models.CharField(max_length=100, blank=True, null=True)
    cdf_office_location = models.CharField(max_length=200, blank=True, null=True)
    cdf_office_email = models.EmailField(blank=True, null=True)
    cdf_office_phone = models.CharField(max_length=20, blank=True, null=True)
    
    # CDF bursary allocation (35% of NG-CDF funds - separate from county bursary)
    annual_cdf_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=0,
        help_text="Total annual NG-CDF allocation"
    )
    
    cdf_bursary_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=0,
        help_text="NG-CDF bursary allocation (usually 35% of total CDF)"
    )
    
    population = models.PositiveIntegerField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name_plural = "Constituencies"
        unique_together = ['name', 'county']
        ordering = ['county', 'name']
    
    def __str__(self):
        return f"{self.name} Constituency"


class Ward(models.Model):
    """
    Electoral wards within constituencies
    Wards are key distribution units for county bursaries
    """
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10, blank=True, null=True)
    constituency = models.ForeignKey(
        Constituency, 
        on_delete=models.CASCADE, 
        related_name='wards'
    )
    
    # Ward Representative (MCA) details
    current_mca = models.CharField(max_length=200, blank=True, null=True)
    mca_party = models.CharField(max_length=100, blank=True, null=True)
    mca_phone = models.CharField(max_length=20, blank=True, null=True)
    mca_email = models.EmailField(blank=True, null=True)
    
    # Ward office details
    ward_office_location = models.CharField(max_length=200, blank=True, null=True)
    
    population = models.PositiveIntegerField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['name', 'constituency']
        ordering = ['constituency', 'name']
    
    def __str__(self):
        return f"{self.name} Ward"


class Location(models.Model):
    """
    Locations within wards (administrative level)
    """
    name = models.CharField(max_length=100)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE, related_name='locations')
    population = models.PositiveIntegerField(blank=True, null=True)
    
    class Meta:
        unique_together = ['name', 'ward']
        ordering = ['ward', 'name']
    
    def __str__(self):
        return f"{self.name}, {self.ward.name}"


class SubLocation(models.Model):
    """
    Sub-locations within locations
    """
    name = models.CharField(max_length=100)
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name='sublocations')
    
    class Meta:
        unique_together = ['name', 'location']
        ordering = ['location', 'name']
    
    def __str__(self):
        return f"{self.name}, {self.location.name}"


class Village(models.Model):
    """
    Villages within sub-locations (smallest administrative unit)
    """
    name = models.CharField(max_length=100)
    sublocation = models.ForeignKey(SubLocation, on_delete=models.CASCADE, related_name='villages')
    village_elder = models.CharField(max_length=200, blank=True, null=True)
    elder_phone = models.CharField(max_length=20, blank=True, null=True)
    
    class Meta:
        unique_together = ['name', 'sublocation']
        ordering = ['sublocation', 'name']
    
    def __str__(self):
        return f"{self.name}, {self.sublocation.name}"


# ============= INSTITUTION MODELS =============

class Institution(models.Model):
    """
    Educational institutions where applicants study
    """
    INSTITUTION_TYPES = (
        ('highschool', 'High School'),
        ('special_school', 'Special School'),
        ('college', 'College'),
        ('university', 'University'),
        ('technical_institute', 'Technical Institute'),
    )
    
    name = models.CharField(max_length=200)
    institution_type = models.CharField(max_length=20, choices=INSTITUTION_TYPES)
    county = models.ForeignKey(County, on_delete=models.SET_NULL, null=True, related_name='institutions')
    sub_county = models.CharField(max_length=100, blank=True, null=True)
    
    # Contact details
    postal_address = models.CharField(max_length=100, blank=True, null=True)
    physical_address = models.TextField(blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    
    # Principal/Head details
    principal_name = models.CharField(max_length=200, blank=True, null=True)
    principal_phone = models.CharField(max_length=20, blank=True, null=True)
    principal_email = models.EmailField(blank=True, null=True)
    
    # Bank details for cheque deposits
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    bank_branch = models.CharField(max_length=100, blank=True, null=True)
    account_number = models.CharField(max_length=50, blank=True, null=True)
    account_name = models.CharField(max_length=200, blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['institution_type', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_institution_type_display()})"


# ============= FISCAL YEAR & BUDGET MODELS =============

class FiscalYear(models.Model):
    """
    Fiscal/Budget years for bursary allocations
    Kenya's fiscal year runs July 1 - June 30
    """
    name = models.CharField(max_length=20, unique=True)  # e.g., "2024-2025"
    start_date = models.DateField()
    end_date = models.DateField()
    county = models.ForeignKey(County, on_delete=models.CASCADE, related_name='fiscal_years')
    
    # County budget allocations
    total_county_budget = models.DecimalField(
        max_digits=15, 
        decimal_places=2,
        help_text="Total county budget for the year"
    )
    
    education_budget = models.DecimalField(
        max_digits=15, 
        decimal_places=2,
        help_text="Education sector allocation"
    )
    
    total_bursary_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        help_text="Total county bursary allocation for the year"
    )
    
    # National Treasury transfers to county
    equitable_share = models.DecimalField(
        max_digits=15, 
        decimal_places=2,
        default=0,
        help_text="Equitable share from National Treasury"
    )
    
    conditional_grants = models.DecimalField(
        max_digits=15, 
        decimal_places=2,
        default=0,
        help_text="Conditional allocations from National Treasury"
    )
    
    # Disbursement tracking
    number_of_disbursement_rounds = models.PositiveIntegerField(
        default=2,
        help_text="How many times bursaries are disbursed per year (e.g., 2, 4, or 5)"
    )
    
    is_active = models.BooleanField(default=False)
    application_open = models.BooleanField(default=False)
    application_deadline = models.DateField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        ordering = ['-start_date']
    
    def __str__(self):
        return f"{self.name} - {self.county.name}"


class WardAllocation(models.Model):
    """
    Per-ward bursary allocation within a fiscal year
    Counties typically allocate funds per ward for equity
    """
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE, related_name='ward_allocations')
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE, related_name='allocations')
    
    allocated_amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        help_text="Total amount allocated to this ward for the year"
    )
    
    spent_amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        default=0,
        help_text="Amount disbursed so far"
    )
    
    beneficiaries_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        unique_together = ['fiscal_year', 'ward']
        ordering = ['fiscal_year', 'ward']
    
    def balance(self):
        allocated = self.allocated_amount or 0
        spent = self.spent_amount or 0
        return allocated - spent

    
    def __str__(self):
        return f"{self.ward.name} - {self.fiscal_year.name}: KES {self.allocated_amount:,.2f}"


class BursaryCategory(models.Model):
    """
    Categories for bursary allocation with specific budgets
    Categories help organize allocation by education level
    """
    CATEGORY_TYPES = (
        ('highschool', 'High School'),
        ('special_school', 'Special School'),
        ('college', 'College'),
        ('university', 'University'),
        ('technical', 'Technical/Vocational'),
        ('freshers', 'University Freshers'),
        ('merit', 'Merit-Based'),
        ('needy', 'Extremely Needy'),
        ('orphan', 'Orphan/Vulnerable'),
    )
    
    name = models.CharField(max_length=100)
    category_type = models.CharField(max_length=20, choices=CATEGORY_TYPES)
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE, related_name='categories')
    
    allocation_amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        help_text="Budget for this category"
    )
    
    max_amount_per_applicant = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        help_text="Maximum bursary per student in this category"
    )
    
    min_amount_per_applicant = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        default=5000,
        help_text="Minimum bursary per student"
    )
    
    target_beneficiaries = models.PositiveIntegerField(
        blank=True, 
        null=True,
        help_text="Target number of beneficiaries"
    )
    
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name_plural = "Bursary Categories"
        ordering = ['fiscal_year', 'category_type']
    
    def __str__(self):
        return f"{self.name} - {self.fiscal_year.name}"


class DisbursementRound(models.Model):
    """
    Track multiple disbursement rounds within a fiscal year
    Example: Round 1 (Term 1), Round 2 (Term 2), etc.
    """
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE, related_name='disbursement_rounds')
    round_number = models.PositiveIntegerField()  # 1, 2, 3, 4, or 5
    name = models.CharField(max_length=100)  # e.g., "First Tranche 2024", "Term 2 Disbursement"
    
    application_start_date = models.DateField()
    application_end_date = models.DateField()
    review_deadline = models.DateField()
    disbursement_date = models.DateField()
    
    allocated_amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        help_text="Amount allocated for this round"
    )
    
    disbursed_amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        default=0
    )
    
    is_open = models.BooleanField(default=False)
    is_completed = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['fiscal_year', 'round_number']
        ordering = ['fiscal_year', 'round_number']
    
    def __str__(self):
        return f"{self.name} ({self.fiscal_year.name})"


# ============= APPLICANT MODELS =============

class Applicant(models.Model):
    """
    Applicant personal and demographic information
    """
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='applicant_profile')
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    date_of_birth = models.DateField()
    id_number = models.CharField(max_length=20, unique=True)
    
    # Administrative location
    county = models.ForeignKey(County, on_delete=models.SET_NULL, null=True)
    constituency = models.ForeignKey(Constituency, on_delete=models.SET_NULL, null=True)
    ward = models.ForeignKey(Ward, on_delete=models.SET_NULL, null=True, related_name='residents')
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True)
    sublocation = models.ForeignKey(SubLocation, on_delete=models.SET_NULL, null=True)
    village = models.ForeignKey(Village, on_delete=models.SET_NULL, null=True)
    
    physical_address = models.TextField()
    postal_address = models.CharField(max_length=100, blank=True, null=True)
    
    # Special circumstances
    special_needs = models.BooleanField(default=False)
    special_needs_description = models.TextField(blank=True, null=True)
    
    profile_picture = models.ImageField(
        upload_to='profile_pics/', 
        default='profile_pics/default.png', 
        blank=True,
        null=True
    )
    
    # Verification status
    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='verified_applicants'
    )
    verification_date = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['user__last_name', 'user__first_name']
    
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"


class Guardian(models.Model):
    """
    Parent/Guardian information for applicants
    """
    RELATIONSHIP_CHOICES = (
        ('father', 'Father'),
        ('mother', 'Mother'),
        ('guardian', 'Legal Guardian'),
        ('grandfather', 'Grandfather'),
        ('grandmother', 'Grandmother'),
        ('uncle', 'Uncle'),
        ('aunt', 'Aunt'),
        ('sibling', 'Sibling'),
        ('other', 'Other Relative'),
    )
    
    EMPLOYMENT_STATUS = (
        ('employed', 'Formally Employed'),
        ('self_employed', 'Self Employed'),
        ('casual', 'Casual Laborer'),
        ('unemployed', 'Unemployed'),
        ('retired', 'Retired'),
        ('deceased', 'Deceased'),
    )
    
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='guardians')
    name = models.CharField(max_length=200)
    relationship = models.CharField(max_length=20, choices=RELATIONSHIP_CHOICES)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(blank=True, null=True)
    id_number = models.CharField(max_length=20, blank=True, null=True)
    
    # Employment and income
    employment_status = models.CharField(max_length=20, choices=EMPLOYMENT_STATUS)
    occupation = models.CharField(max_length=200, blank=True, null=True)
    employer = models.CharField(max_length=200, blank=True, null=True)
    monthly_income = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    
    is_primary_contact = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['applicant', '-is_primary_contact']
    
    def __str__(self):
        return f"{self.name} ({self.get_relationship_display()} of {self.applicant})"


class SiblingInformation(models.Model):
    """
    Information about siblings of the applicant
    """
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='siblings')
    name = models.CharField(max_length=200)
    age = models.PositiveIntegerField()
    education_level = models.CharField(max_length=100)
    school_name = models.CharField(max_length=200, blank=True, null=True)
    is_in_school = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.name} (Sibling of {self.applicant})"


# ============= APPLICATION MODELS =============

class Application(models.Model):
    """
    Bursary application details
    """
    APPLICATION_STATUS = (
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('under_review', 'Under Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('disbursed', 'Disbursed'),
        ('pending_documents', 'Pending Documents'),
    )
    
    BURSARY_SOURCE = (
        ('county', 'County Bursary'),
        ('cdf', 'NG-CDF Bursary'),
        ('both', 'Both County and CDF'),
    )
    
    application_number = models.CharField(max_length=20, unique=True, editable=False)
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='applications')
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE)
    disbursement_round = models.ForeignKey(
        DisbursementRound, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    bursary_category = models.ForeignKey(BursaryCategory, on_delete=models.CASCADE)
    institution = models.ForeignKey(Institution, on_delete=models.CASCADE)
    
    # Bursary source selection
    bursary_source = models.CharField(
        max_length=10, 
        choices=BURSARY_SOURCE, 
        default='county',
        help_text="Which bursary fund to apply from"
    )
    
    status = models.CharField(max_length=20, choices=APPLICATION_STATUS, default='draft')
    
    # Academic Information
    admission_number = models.CharField(max_length=100)
    year_of_study = models.PositiveIntegerField()
    course_name = models.CharField(max_length=200, blank=True, null=True)
    expected_completion_date = models.DateField()
    
    # Academic performance (for merit consideration)
    previous_academic_year_average = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        blank=True, 
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    
    # Financial Information
    total_fees_payable = models.DecimalField(max_digits=10, decimal_places=2)
    fees_paid = models.DecimalField(max_digits=10, decimal_places=2)
    fees_balance = models.DecimalField(max_digits=10, decimal_places=2)
    amount_requested = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Other bursaries received
    other_bursaries = models.BooleanField(default=False)
    other_bursaries_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    other_bursaries_source = models.CharField(max_length=200, blank=True, null=True)
    
    # Family situation
    is_orphan = models.BooleanField(default=False)
    is_total_orphan = models.BooleanField(default=False)
    is_disabled = models.BooleanField(default=False)
    has_chronic_illness = models.BooleanField(default=False)
    chronic_illness_description = models.TextField(blank=True, null=True)
    
    # Household information
    number_of_siblings = models.PositiveIntegerField(default=0)
    number_of_siblings_in_school = models.PositiveIntegerField(default=0)
    household_monthly_income = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        blank=True, 
        null=True
    )
    
    # Application dates
    date_submitted = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    # Previous allocations
    has_received_previous_allocation = models.BooleanField(default=False)
    previous_allocation_year = models.CharField(max_length=20, blank=True, null=True)
    previous_allocation_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Priority scoring (calculated)
    priority_score = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=0,
        help_text="Calculated priority score for ranking"
    )
    
    def save(self, *args, **kwargs):
        if not self.application_number:
            # Generate unique application number
            year = self.fiscal_year.name.split('-')[0]
            county_code = self.applicant.county.code if self.applicant.county else "XX"
            random_string = uuid.uuid4().hex[:6].upper()
            self.application_number = f"KB-{county_code}-{year}-{random_string}"
        super().save(*args, **kwargs)
    
    class Meta:
        ordering = ['-date_submitted']
    
    def __str__(self):
        return f"{self.application_number} - {self.applicant}"


class Document(models.Model):
    """
    Supporting documents for applications
    """
    DOCUMENT_TYPES = (
        ('id_card', 'National ID Card'),
        ('birth_certificate', 'Birth Certificate'),
        ('admission_letter', 'Admission Letter'),
        ('fee_structure', 'Fee Structure'),
        ('fee_statement', 'Fee Statement / Balance'),
        ('academic_results', 'Academic Results / Transcript'),
        ('parent_id', 'Parent/Guardian ID'),
        ('death_certificate', 'Death Certificate'),
        ('medical_report', 'Medical Report'),
        ('disability_certificate', 'Disability Certificate'),
        ('chiefs_letter', "Chief's Recommendation Letter"),
        ('mca_letter', "MCA Recommendation Letter"),
        ('pastor_letter', 'Religious Leader Letter'),
        ('school_leaving_cert', 'School Leaving Certificate'),
        ('other', 'Other Document'),
    )
    
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=30, choices=DOCUMENT_TYPES)
    file = models.FileField(upload_to='bursary_documents/%Y/%m/')
    description = models.CharField(max_length=200, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='verified_documents'
    )
    
    class Meta:
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"{self.get_document_type_display()} - {self.application.application_number}"


class Review(models.Model):
    """
    Reviews and comments on applications
    Multi-level review process
    """
    REVIEW_LEVEL = (
        ('ward', 'Ward Committee Review'),
        ('constituency', 'Constituency Review'),
        ('county', 'County Review'),
        ('final', 'Final Approval'),
    )
    
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='reviews')
    reviewer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='reviews')
    review_level = models.CharField(max_length=20, choices=REVIEW_LEVEL, default='ward')
    
    comments = models.TextField()
    recommendation = models.CharField(max_length=50, choices=[
        ('approve', 'Approve'),
        ('reject', 'Reject'),
        ('more_info', 'Request More Information'),
        ('forward', 'Forward to Next Level')
    ])
    
    recommended_amount = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    
    # Scoring criteria
    need_score = models.PositiveIntegerField(
        blank=True, 
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(10)]
    )
    merit_score = models.PositiveIntegerField(
        blank=True, 
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(10)]
    )
    vulnerability_score = models.PositiveIntegerField(
        blank=True, 
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(10)]
    )
    
    review_date = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-review_date']
    
    def __str__(self):
        return f"{self.get_review_level_display()} for {self.application.application_number}"


class Allocation(models.Model):
    """
    Approved bursary allocations
    """
    application = models.OneToOneField(Application, on_delete=models.CASCADE, related_name='allocation')
    amount_allocated = models.DecimalField(max_digits=10, decimal_places=2)
    allocation_date = models.DateField(auto_now_add=True)
    approved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='approvals'
    )
    
    # Cheque/Payment details
    cheque_number = models.CharField(max_length=50, blank=True, null=True)
    payment_method = models.CharField(
        max_length=20,
        choices=[
            ('cheque', 'Cheque'),
            ('bank_transfer', 'Bank Transfer'),
            ('mpesa', 'M-Pesa'),
            ('bulk_cheque', 'Bulk Cheque')
        ],
        default='cheque'
    )
    
    # Disbursement tracking
    is_disbursed = models.BooleanField(default=False)
    disbursement_date = models.DateField(blank=True, null=True)
    disbursed_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='disbursements'
    )
    
    # Confirmation from institution
    is_received_by_institution = models.BooleanField(default=False)
    institution_confirmation_date = models.DateField(blank=True, null=True)
    institution_receipt_number = models.CharField(max_length=50, blank=True, null=True)
    
    remarks = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-allocation_date']
    
    def __str__(self):
        return f"Allocation for {self.application.application_number}: KES {self.amount_allocated:,.2f}"


class BulkCheque(models.Model):
    """
    Bulk cheque assignment for multiple students in same institution
    Common practice to reduce processing costs
    """
    cheque_number = models.CharField(max_length=50, unique=True)
    institution = models.ForeignKey(Institution, on_delete=models.CASCADE, related_name='bulk_cheques')
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE)
    disbursement_round = models.ForeignKey(
        DisbursementRound, 
        on_delete=models.SET_NULL, 
        null=True
    )
    
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    student_count = models.PositiveIntegerField()
    
    # Cheque holder/representative details
    cheque_holder_name = models.CharField(max_length=200)
    cheque_holder_id = models.CharField(max_length=20)
    cheque_holder_phone = models.CharField(max_length=20)
    cheque_holder_email = models.EmailField(blank=True, null=True)
    cheque_holder_position = models.CharField(max_length=100)  # e.g., "Principal", "Bursar"
    
    # Status and dates
    created_date = models.DateTimeField(auto_now_add=True)
    assigned_date = models.DateTimeField(blank=True, null=True)
    is_collected = models.BooleanField(default=False)
    collection_date = models.DateTimeField(blank=True, null=True)
    collector_id_number = models.CharField(max_length=20, blank=True, null=True)
    
    created_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='created_bulk_cheques'
    )
    assigned_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='assigned_bulk_cheques'
    )
    
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_date']
    
    def __str__(self):
        return f"Bulk Cheque {self.cheque_number} - {self.institution.name} ({self.student_count} students)"


class BulkChequeAllocation(models.Model):
    """
    Link individual allocations to bulk cheques
    """
    bulk_cheque = models.ForeignKey(BulkCheque, on_delete=models.CASCADE, related_name='allocations')
    allocation = models.OneToOneField(
        Allocation, 
        on_delete=models.CASCADE, 
        related_name='bulk_cheque_allocation'
    )
    is_notified = models.BooleanField(default=False)
    notification_sent_date = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.allocation.application.applicant} in Bulk Cheque {self.bulk_cheque.cheque_number}"


# ============= NOTIFICATION & COMMUNICATION MODELS =============

class Notification(models.Model):
    """
    System notifications for users
    """
    NOTIFICATION_TYPES = (
        ('application_status', 'Application Status'),
        ('document_request', 'Document Request'),
        ('allocation', 'Allocation'),
        ('disbursement', 'Disbursement'),
        ('review_comment', 'Review Comment'),
        ('deadline', 'Deadline Reminder'),
        ('system', 'System Notification'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    related_application = models.ForeignKey(
        Application, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} for {self.user.username}"


class SMSLog(models.Model):
    """
    Log of SMS messages sent to users
    """
    SMS_STATUS = (
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('delivered', 'Delivered'),
        ('failed', 'Failed'),
    )
    
    recipient = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='sms_messages'
    )
    phone_number = models.CharField(max_length=20)
    message = models.TextField()
    related_application = models.ForeignKey(
        Application, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    
    status = models.CharField(max_length=20, choices=SMS_STATUS, default='pending')
    sent_at = models.DateTimeField(auto_now_add=True)
    delivery_status = models.CharField(max_length=20, blank=True, null=True)
    delivery_time = models.DateTimeField(null=True, blank=True)
    
    # SMS gateway response
    gateway_message_id = models.CharField(max_length=100, blank=True, null=True)
    gateway_response = models.TextField(blank=True, null=True)
    
    cost = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    
    class Meta:
        ordering = ['-sent_at']
    
    def __str__(self):
        return f"SMS to {self.phone_number} at {self.sent_at}"


class EmailLog(models.Model):
    """
    Log of emails sent to users
    """
    EMAIL_STATUS = (
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('delivered', 'Delivered'),
        ('bounced', 'Bounced'),
        ('failed', 'Failed'),
    )
    
    recipient = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='emails'
    )
    email_address = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    related_application = models.ForeignKey(
        Application, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    
    status = models.CharField(max_length=20, choices=EMAIL_STATUS, default='pending')
    sent_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    
    # Attachments info
    has_attachments = models.BooleanField(default=False)
    attachment_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        ordering = ['-sent_at']
    
    def __str__(self):
        return f"Email to {self.email_address}: {self.subject}"


# ============= AUDIT & SYSTEM MODELS =============

class AuditLog(models.Model):
    """
    System audit trail for compliance and transparency
    """
    ACTION_TYPES = (
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('view', 'View'),
        ('approve', 'Approve'),
        ('reject', 'Reject'),
        ('disburse', 'Disburse'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('export', 'Export Data'),
        ('print', 'Print Document'),
    )
    
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='audit_logs'
    )
    action = models.CharField(max_length=20, choices=ACTION_TYPES)
    table_affected = models.CharField(max_length=100)
    record_id = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField()
    
    # Technical details
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    
    # Data changes (store as JSON for detailed tracking)
    old_values = models.JSONField(blank=True, null=True)
    new_values = models.JSONField(blank=True, null=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.action} by {self.user} on {self.timestamp}"


class SystemSettings(models.Model):
    """
    Configuration settings for the system
    """
    SETTING_CATEGORIES = (
        ('general', 'General'),
        ('application', 'Application'),
        ('finance', 'Finance'),
        ('notification', 'Notification'),
        ('security', 'Security'),
    )
    
    setting_name = models.CharField(max_length=100, unique=True)
    setting_category = models.CharField(max_length=20, choices=SETTING_CATEGORIES, default='general')
    setting_value = models.TextField()
    description = models.TextField(blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    last_updated = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        ordering = ['setting_category', 'setting_name']
    
    def __str__(self):
        return self.setting_name


# ============= PUBLIC INFORMATION MODELS =============

class FAQ(models.Model):
    """
    Frequently Asked Questions
    """
    FAQ_CATEGORIES = (
        ('general', 'General'),
        ('eligibility', 'Eligibility'),
        ('application', 'Application Process'),
        ('documents', 'Required Documents'),
        ('disbursement', 'Disbursement'),
        ('technical', 'Technical Support'),
    )
    
    question = models.CharField(max_length=500)
    answer = models.TextField()
    category = models.CharField(max_length=20, choices=FAQ_CATEGORIES, default='general')
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0)
    views_count = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['category', 'order', 'question']
        verbose_name = "FAQ"
        verbose_name_plural = "FAQs"
    
    def __str__(self):
        return self.question


class Announcement(models.Model):
    """
    Public announcements for applicants
    """
    ANNOUNCEMENT_TYPES = (
        ('general', 'General'),
        ('deadline', 'Deadline'),
        ('disbursement', 'Disbursement'),
        ('maintenance', 'System Maintenance'),
        ('urgent', 'Urgent'),
    )
    
    title = models.CharField(max_length=200)
    content = models.TextField()
    announcement_type = models.CharField(max_length=20, choices=ANNOUNCEMENT_TYPES, default='general')
    
    published_date = models.DateTimeField()
    expiry_date = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    is_featured = models.BooleanField(default=False)
    
    target_audience = models.CharField(
        max_length=20,
        choices=[
            ('all', 'All Users'),
            ('applicants', 'Applicants Only'),
            ('staff', 'Staff Only')
        ],
        default='all'
    )
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-published_date']
    
    def __str__(self):
        return self.title


# ============= AI/ANALYTICS MODELS =============

class AIAnalysisReport(models.Model):
    """
    Store AI analysis reports and predictions
    """
    REPORT_TYPES = (
        ('allocation_prediction', 'Allocation Prediction'),
        ('demand_forecast', 'Demand Forecast'),
        ('budget_analysis', 'Budget Analysis'),
        ('performance_trend', 'Performance Trend Analysis'),
        ('geographic_analysis', 'Geographic Distribution Analysis'),
        ('institution_analysis', 'Institution-based Analysis'),
        ('equity_analysis', 'Equity & Fairness Analysis'),
    )
    
    report_type = models.CharField(max_length=30, choices=REPORT_TYPES)
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE, related_name='ai_reports')
    title = models.CharField(max_length=200)
    
    # Analysis data stored as JSON
    analysis_data = models.JSONField()
    predictions = models.JSONField(blank=True, null=True)
    recommendations = models.JSONField(blank=True, null=True)
    
    # Metadata
    generated_date = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    accuracy_score = models.DecimalField(
        max_digits=5, 
        decimal_places=4, 
        blank=True, 
        null=True
    )
    confidence_level = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        blank=True, 
        null=True
    )
    
    # Report file if generated as PDF/Excel
    report_file = models.FileField(upload_to='ai_reports/%Y/%m/', blank=True, null=True)
    
    is_archived = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-generated_date']
    
    def __str__(self):
        return f"{self.get_report_type_display()} - {self.fiscal_year.name}"


class PredictionModel(models.Model):
    """
    Store trained ML model parameters and metadata
    """
    MODEL_TYPES = (
        ('demand_forecasting', 'Demand Forecasting'),
        ('allocation_optimization', 'Allocation Optimization'),
        ('success_prediction', 'Academic Success Prediction'),
        ('geographic_clustering', 'Geographic Clustering'),
        ('fraud_detection', 'Fraud Detection'),
    )
    
    name = models.CharField(max_length=100)
    model_type = models.CharField(max_length=30, choices=MODEL_TYPES)
    version = models.CharField(max_length=10, default='1.0')
    
    # Model parameters and weights stored as JSON
    model_parameters = models.JSONField()
    feature_importance = models.JSONField(blank=True, null=True)
    
    # Performance metrics
    accuracy = models.DecimalField(max_digits=5, decimal_places=4, blank=True, null=True)
    precision = models.DecimalField(max_digits=5, decimal_places=4, blank=True, null=True)
    recall = models.DecimalField(max_digits=5, decimal_places=4, blank=True, null=True)
    f1_score = models.DecimalField(max_digits=5, decimal_places=4, blank=True, null=True)
    
    # Training data info
    training_data_size = models.PositiveIntegerField(blank=True, null=True)
    training_date = models.DateTimeField(auto_now_add=True)
    last_retrained = models.DateTimeField(blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        ordering = ['-training_date']
    
    def __str__(self):
        return f"{self.name} v{self.version}"


class DataSnapshot(models.Model):
    """
    Store periodic snapshots of system data for trend analysis
    """
    snapshot_date = models.DateField()
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE)
    
    # Application statistics
    total_applications = models.PositiveIntegerField()
    approved_applications = models.PositiveIntegerField()
    rejected_applications = models.PositiveIntegerField()
    pending_applications = models.PositiveIntegerField()
    
    # Financial data
    total_requested = models.DecimalField(max_digits=12, decimal_places=2)
    total_allocated = models.DecimalField(max_digits=12, decimal_places=2)
    total_disbursed = models.DecimalField(max_digits=12, decimal_places=2)
    
    # Demographic breakdown stored as JSON
    gender_distribution = models.JSONField()
    ward_distribution = models.JSONField()
    constituency_distribution = models.JSONField()
    institution_distribution = models.JSONField()
    category_distribution = models.JSONField()
    
    # Additional metrics
    average_amount_requested = models.DecimalField(max_digits=10, decimal_places=2)
    average_amount_allocated = models.DecimalField(max_digits=10, decimal_places=2)
    approval_rate = models.DecimalField(max_digits=5, decimal_places=2)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['snapshot_date', 'fiscal_year']
        ordering = ['-snapshot_date']
    
    def __str__(self):
        return f"Data Snapshot - {self.snapshot_date} ({self.fiscal_year.name})"


# ============= TRANSPARENCY & REPORTING MODELS =============

class PublicReport(models.Model):
    """
    Public-facing reports for transparency
    """
    REPORT_TYPES = (
        ('annual', 'Annual Report'),
        ('quarterly', 'Quarterly Report'),
        ('beneficiaries', 'Beneficiaries List'),
        ('budget_utilization', 'Budget Utilization'),
        ('ward_distribution', 'Ward Distribution'),
        ('institution_distribution', 'Institution Distribution'),
    )
    
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=30, choices=REPORT_TYPES)
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE)
    period_covered = models.CharField(max_length=100)
    
    summary = models.TextField()
    report_file = models.FileField(upload_to='public_reports/%Y/')
    
    published_date = models.DateTimeField(auto_now_add=True)
    published_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    is_published = models.BooleanField(default=False)
    download_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        ordering = ['-published_date']
    
    def __str__(self):
        return f"{self.title} - {self.fiscal_year.name}"


class BeneficiaryTestimonial(models.Model):
    """
    Success stories and testimonials from beneficiaries
    """
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='testimonials')
    allocation = models.ForeignKey(Allocation, on_delete=models.CASCADE)
    
    testimonial_text = models.TextField()
    photo = models.ImageField(upload_to='testimonials/', blank=True, null=True)
    
    is_approved = models.BooleanField(default=False)
    is_featured = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='approved_testimonials'
    )
    
    submitted_date = models.DateTimeField(auto_now_add=True)
    approval_date = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-submitted_date']
    
    def __str__(self):
        return f"Testimonial from {self.applicant} - {self.submitted_date.date()}"
    
  
# Add these models to your models.py file
# These models are referenced in your views but missing from the current models

from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone


class Testimonial(models.Model):
    """
    Public testimonials from beneficiaries
    This model consolidates testimonial functionality
    """
    RATING_CHOICES = (
        (1, '1 Star'),
        (2, '2 Stars'),
        (3, '3 Stars'),
        (4, '4 Stars'),
        (5, '5 Stars'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='public_testimonials')
    application = models.ForeignKey('Application', on_delete=models.CASCADE, related_name='testimonials')
    
    testimonial_text = models.TextField(help_text="Share your experience with the bursary program")
    rating = models.PositiveIntegerField(
        choices=RATING_CHOICES,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Rate your experience from 1 to 5 stars"
    )
    
    # Optional photo
    photo = models.ImageField(upload_to='testimonials/%Y/%m/', blank=True, null=True)
    
    # Approval workflow
    is_approved = models.BooleanField(default=False)
    is_public = models.BooleanField(default=True, help_text="Display on public page")
    is_featured = models.BooleanField(default=False, help_text="Feature on homepage")
    
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='approved_public_testimonials'
    )
    approval_date = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    views_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Testimonial"
        verbose_name_plural = "Testimonials"
    
    def __str__(self):
        return f"Testimonial by {self.user.get_full_name()} - {self.rating} stars"


class Disbursement(models.Model):
    """
    Individual disbursement records tracking payment to institutions
    """
    DISBURSEMENT_STATUS = (
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('reversed', 'Reversed'),
    )
    
    PAYMENT_METHOD = (
        ('cheque', 'Cheque'),
        ('bank_transfer', 'Bank Transfer'),
        ('mpesa', 'M-Pesa'),
        ('bulk_cheque', 'Bulk Cheque'),
        ('eft', 'Electronic Funds Transfer'),
    )
    
    allocation = models.ForeignKey(
        'Allocation', 
        on_delete=models.CASCADE, 
        related_name='disbursements'
    )
    applicant = models.ForeignKey(
        'Applicant',
        on_delete=models.CASCADE,
        related_name='disbursements'
    )
    fiscal_year = models.ForeignKey(
        'FiscalYear',
        on_delete=models.CASCADE,
        related_name='disbursements'
    )
    
    # Amount details
    amount = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        help_text="Amount disbursed"
    )
    
    # Payment details
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD, default='cheque')
    reference_number = models.CharField(
        max_length=100, 
        unique=True,
        help_text="Payment reference/transaction number"
    )
    cheque_number = models.CharField(max_length=50, blank=True, null=True)
    
    # Status and dates
    status = models.CharField(max_length=20, choices=DISBURSEMENT_STATUS, default='pending')
    disbursement_date = models.DateField(help_text="Date payment was made")
    expected_receipt_date = models.DateField(blank=True, null=True)
    actual_receipt_date = models.DateField(blank=True, null=True)
    
    # Processing details
    processed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='processed_disbursements'
    )
    processed_at = models.DateTimeField(auto_now_add=True)
    
    # Institution confirmation
    is_received_by_institution = models.BooleanField(default=False)
    institution_receipt_number = models.CharField(max_length=100, blank=True, null=True)
    institution_confirmation_date = models.DateField(blank=True, null=True)
    confirmed_by = models.CharField(max_length=200, blank=True, null=True)
    
    # Bank details (if applicable)
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    bank_branch = models.CharField(max_length=100, blank=True, null=True)
    account_number = models.CharField(max_length=50, blank=True, null=True)
    
    # Bulk cheque reference
    bulk_cheque = models.ForeignKey(
        'BulkCheque',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='individual_disbursements'
    )
    
    remarks = models.TextField(blank=True, null=True)
    failure_reason = models.TextField(blank=True, null=True)
    
    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-disbursement_date']
        indexes = [
            models.Index(fields=['fiscal_year', 'status']),
            models.Index(fields=['disbursement_date']),
            models.Index(fields=['reference_number']),
        ]
    
    def __str__(self):
        return f"Disbursement {self.reference_number} - KES {self.amount:,.2f}"
    
    def mark_as_completed(self):
        """Mark disbursement as completed"""
        self.status = 'completed'
        self.save()
    
    def mark_as_failed(self, reason):
        """Mark disbursement as failed with reason"""
        self.status = 'failed'
        self.failure_reason = reason
        self.save()


class URLVisit(models.Model):
    url_path = models.CharField(max_length=500, unique=True)
    url_name = models.CharField(max_length=200, blank=True, null=True)
    view_name = models.CharField(max_length=200, blank=True, null=True)
    visit_count = models.PositiveIntegerField(default=0)
    last_visited = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-visit_count']
    
    def __str__(self):
        return f"{self.url_path} ({self.visit_count} visits)"


class UserURLVisit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='url_visits')
    url_visit = models.ForeignKey(URLVisit, on_delete=models.CASCADE, related_name='user_visits')
    visited_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-visited_at']
    
    def __str__(self):
        return f"{self.user.username} visited {self.url_visit.url_path}"
    
    
class SecurityThreat(models.Model):
    """
    Log detected security threats
    """
    THREAT_TYPES = (
        ('sql_injection', 'SQL Injection'),
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('path_traversal', 'Path Traversal'),
        ('code_injection', 'Code Injection'),
        ('brute_force', 'Brute Force Attack'),
        ('credential_stuffing', 'Credential Stuffing'),
        ('rate_limit', 'Rate Limit Exceeded'),
        ('suspicious_agent', 'Suspicious User Agent'),
        ('phishing', 'Phishing Attempt'),
        ('malware', 'Malware Detection'),
        ('ddos', 'DDoS Attack'),
        ('other', 'Other'),
    )
    
    SEVERITY_LEVELS = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )
    
    threat_type = models.CharField(max_length=30, choices=THREAT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='medium')
    
    ip_address = models.GenericIPAddressField()
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='security_threats'
    )
    
    description = models.TextField()
    request_path = models.CharField(max_length=500)
    request_method = models.CharField(max_length=10)
    user_agent = models.TextField(blank=True, null=True)
    request_data = models.JSONField(blank=True, null=True)
    
    # Response actions
    blocked = models.BooleanField(default=False)
    resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_threats'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True, null=True)
    
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['-detected_at']),
            models.Index(fields=['severity', '-detected_at']),
            models.Index(fields=['ip_address', '-detected_at']),
            models.Index(fields=['resolved', '-detected_at']),
        ]
    
    def __str__(self):
        return f"{self.get_threat_type_display()} - {self.severity} ({self.detected_at})"


class UserSession(models.Model):
    """
    Track active user sessions for real-time monitoring
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    
    # Session details
    login_time = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Device info
    device_type = models.CharField(max_length=50, blank=True, null=True)  # Mobile, Desktop, Tablet
    browser = models.CharField(max_length=100, blank=True, null=True)
    os = models.CharField(max_length=100, blank=True, null=True)
    
    # Location (if available)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['-last_activity']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address} ({self.login_time})"
    
    def is_expired(self):
        """Check if session has been inactive for more than 30 minutes"""
        if not self.is_active:
            return True
        time_diff = timezone.now() - self.last_activity
        return time_diff > timedelta(minutes=30)


class SuspiciousActivity(models.Model):
    """
    Track suspicious user activities that might indicate phishing or compromise
    """
    ACTIVITY_TYPES = (
        ('unusual_access_pattern', 'Unusual Access Pattern'),
        ('rapid_data_access', 'Rapid Data Access'),
        ('failed_authorization', 'Multiple Failed Authorization Attempts'),
        ('data_exfiltration', 'Possible Data Exfiltration'),
        ('privilege_escalation', 'Privilege Escalation Attempt'),
        ('unusual_location', 'Access from Unusual Location'),
        ('unusual_time', 'Access at Unusual Time'),
        ('multiple_devices', 'Multiple Devices Simultaneously'),
        ('phishing_link_click', 'Phishing Link Click'),
        ('account_sharing', 'Possible Account Sharing'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='suspicious_activities')
    activity_type = models.CharField(max_length=30, choices=ACTIVITY_TYPES)
    description = models.TextField()
    
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    
    # Risk scoring
    risk_score = models.PositiveIntegerField(default=0)  # 0-100
    confidence = models.DecimalField(max_digits=5, decimal_places=2, default=0)  # 0-100%
    
    # Evidence
    evidence = models.JSONField(blank=True, null=True)
    
    # Investigation
    investigated = models.BooleanField(default=False)
    investigated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='investigated_activities'
    )
    investigated_at = models.DateTimeField(null=True, blank=True)
    investigation_notes = models.TextField(blank=True, null=True)
    
    is_false_positive = models.BooleanField(default=False)
    action_taken = models.TextField(blank=True, null=True)
    
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-detected_at']
        verbose_name_plural = "Suspicious Activities"
        indexes = [
            models.Index(fields=['-detected_at']),
            models.Index(fields=['user', '-detected_at']),
            models.Index(fields=['investigated', '-detected_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.get_activity_type_display()}"

# UPDATE YOUR EXISTING ALLOCATION MODEL
# Add these fields to your existing Allocation model if they don't exist:

"""
IMPORTANT: Update your existing Allocation model to include these fields:

class Allocation(models.Model):
    # EXISTING FIELDS - Keep these as they are
    application = models.OneToOneField(Application, on_delete=models.CASCADE, related_name='allocation')
    amount_allocated = models.DecimalField(max_digits=10, decimal_places=2)
    allocation_date = models.DateField(auto_now_add=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='approvals'
    )
    cheque_number = models.CharField(max_length=50, blank=True, null=True)
    payment_method = models.CharField(
        max_length=20,
        choices=[
            ('cheque', 'Cheque'),
            ('bank_transfer', 'Bank Transfer'),
            ('mpesa', 'M-Pesa'),
            ('bulk_cheque', 'Bulk Cheque')
        ],
        default='cheque'
    )
    is_disbursed = models.BooleanField(default=False)
    disbursement_date = models.DateField(blank=True, null=True)
    disbursed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='disbursements'
    )
    is_received_by_institution = models.BooleanField(default=False)
    institution_confirmation_date = models.DateField(blank=True, null=True)
    institution_receipt_number = models.CharField(max_length=50, blank=True, null=True)
    remarks = models.TextField(blank=True, null=True)
    
    # ADD THESE NEW FIELDS if they don't exist:
    applicant = models.ForeignKey(
        'Applicant',
        on_delete=models.CASCADE,
        related_name='allocations',
        null=True  # Allow null for existing data
    )
    fiscal_year = models.ForeignKey(
        'FiscalYear',
        on_delete=models.CASCADE,
        related_name='allocations',
        null=True  # Allow null for existing data
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
            ('disbursed', 'Disbursed'),
        ],
        default='approved'  # Set default since old records don't have this
    )
    approved_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Final approved amount (may differ from allocated amount)",
        null=True,  # Allow null for existing data
        blank=True
    )
    date_approved = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-allocation_date']
    
    def __str__(self):
        return f"Allocation for {self.application.application_number}: KES {self.amount_allocated:,.2f}"
    
    def save(self, *args, **kwargs):
        # Auto-populate applicant and fiscal_year from application if not set
        if not self.applicant:
            self.applicant = self.application.applicant
        if not self.fiscal_year:
            self.fiscal_year = self.application.fiscal_year
        # If approved_amount is not set, use amount_allocated
        if not self.approved_amount:
            self.approved_amount = self.amount_allocated
        super().save(*args, **kwargs)
"""


# MIGRATION STEPS:
"""
After updating your Allocation model with the new fields above, run these commands:

1. python manage.py makemigrations
   
   When prompted about default values for existing records, choose option 1 (provide a one-off default)
   and enter:
   - For 'status': 'approved'
   - For 'applicant': None (we'll fix this with a data migration)
   - For 'fiscal_year': None (we'll fix this with a data migration)
   - For 'approved_amount': None (we'll fix this with a data migration)

2. python manage.py migrate

3. Then run this management command or execute in Django shell to populate the new fields:

from main_application.models import Allocation

# Update all existing allocations
for allocation in Allocation.objects.all():
    if not allocation.applicant:
        allocation.applicant = allocation.application.applicant
    if not allocation.fiscal_year:
        allocation.fiscal_year = allocation.application.fiscal_year
    if not allocation.approved_amount:
        allocation.approved_amount = allocation.amount_allocated
    if not allocation.date_approved:
        allocation.date_approved = allocation.allocation_date
    allocation.save()

4. After data is populated, you can make the fields non-nullable if desired by:
   - Removing null=True from the field definitions
   - Running makemigrations and migrate again

OR: You can keep null=True to be safe and just ensure new records always have these values.
"""