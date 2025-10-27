"""
Django management command to seed the database with realistic Kenyan data
Enhanced version with 300 applicants and fiscal years from 2021-2022
Place this file in: main_application/management/commands/seed_data.py
Run with: python manage.py seed_data
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import models
from datetime import datetime, timedelta
from decimal import Decimal
import random

from main_application.models import (
    County, Constituency, Ward, Location, SubLocation, Village,
    Institution, FiscalYear, WardAllocation, BursaryCategory, DisbursementRound,
    Applicant, Guardian, SiblingInformation, Application, Document, Review,
    Allocation, FAQ, Announcement, SystemSettings
)

User = get_user_model()


class Command(BaseCommand):
    help = 'Seeds the database with realistic Kenyan bursary data (300 applicants, fiscal years 2021-2025)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before seeding',
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write(self.style.WARNING('Clearing existing data...'))
            self.clear_data()

        self.stdout.write(self.style.SUCCESS('Starting data seeding...'))
        
        # Seed in order of dependencies
        self.create_users()
        self.create_counties()
        self.create_constituencies()
        self.create_wards()
        self.create_locations()
        self.create_institutions()
        self.create_fiscal_years()
        self.create_ward_allocations()
        self.create_bursary_categories()
        self.create_disbursement_rounds()
        self.create_applicants()
        self.create_guardians()
        self.create_applications()
        self.create_reviews()
        self.create_allocations()
        self.create_faqs()
        self.create_announcements()
        self.create_system_settings()
        
        self.stdout.write(self.style.SUCCESS('✅ Database seeding completed successfully!'))

    def clear_data(self):
        """Clear existing data (except superusers)"""
        models_to_clear = [
            Allocation, Review, Application, Guardian, SiblingInformation, Applicant,
            DisbursementRound, BursaryCategory, WardAllocation, FiscalYear,
            Institution, Village, SubLocation, Location, Ward, Constituency, County,
            FAQ, Announcement, SystemSettings
        ]
        
        for model in models_to_clear:
            count = model.objects.all().delete()[0]
            self.stdout.write(f'  Deleted {count} {model.__name__} records')
        
        # Delete non-superuser users
        User.objects.filter(is_superuser=False).delete()

    def create_users(self):
        """Create system users"""
        self.stdout.write('Creating users...')
        
        # County Admin
        self.county_admin, created = User.objects.get_or_create(
            username='county_admin',
            defaults={
                'email': 'admin@muranga.go.ke',
                'first_name': 'Jane',
                'last_name': 'Wanjiku',
                'user_type': 'county_admin',
                'phone_number': '+254722000001',
                'is_staff': True
            }
        )
        if created:
            self.county_admin.set_password('admin123')
            self.county_admin.save()
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created County Admin: {self.county_admin.username}'))
        
        # Finance Officer
        self.finance_officer, created = User.objects.get_or_create(
            username='finance_officer',
            defaults={
                'email': 'finance@muranga.go.ke',
                'first_name': 'Peter',
                'last_name': 'Kimani',
                'user_type': 'finance',
                'phone_number': '+254722000002',
                'is_staff': True
            }
        )
        if created:
            self.finance_officer.set_password('finance123')
            self.finance_officer.save()
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created Finance Officer: {self.finance_officer.username}'))
        
        # Ward Admin
        self.ward_admin, created = User.objects.get_or_create(
            username='ward_admin',
            defaults={
                'email': 'ward@muranga.go.ke',
                'first_name': 'Mary',
                'last_name': 'Njeri',
                'user_type': 'ward_admin',
                'phone_number': '+254722000003',
                'is_staff': True
            }
        )
        if created:
            self.ward_admin.set_password('ward123')
            self.ward_admin.save()
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created Ward Admin: {self.ward_admin.username}'))
        
        # Reviewer
        self.reviewer, created = User.objects.get_or_create(
            username='reviewer',
            defaults={
                'email': 'reviewer@muranga.go.ke',
                'first_name': 'John',
                'last_name': 'Mwangi',
                'user_type': 'reviewer',
                'phone_number': '+254722000004',
                'is_staff': True
            }
        )
        if created:
            self.reviewer.set_password('reviewer123')
            self.reviewer.save()
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created Reviewer: {self.reviewer.username}'))

    def create_counties(self):
        """Create sample Kenyan counties"""
        self.stdout.write('Creating counties...')
        
        counties_data = [
            {
                'name': "Murang'a",
                'code': '047',
                'headquarters': "Murang'a Town",
                'population': 1056640,
                'governor_name': 'Irungu Kang\'ata',
                'county_website': 'https://muranga.go.ke',
                'treasury_email': 'treasury@muranga.go.ke',
                'treasury_phone': '+254722100100',
                'education_cec_name': 'Dr. Margaret Mwangi',
                'education_office_email': 'education@muranga.go.ke',
                'education_office_phone': '+254722100101'
            },
            {
                'name': 'Nairobi',
                'code': '001',
                'headquarters': 'Nairobi CBD',
                'population': 4397073,
                'governor_name': 'Johnson Sakaja',
                'county_website': 'https://nairobi.go.ke',
                'treasury_email': 'treasury@nairobi.go.ke',
                'treasury_phone': '+254722200200'
            },
            {
                'name': 'Kiambu',
                'code': '022',
                'headquarters': 'Kiambu Town',
                'population': 2417735,
                'governor_name': 'Kimani Wamatangi',
                'treasury_email': 'treasury@kiambu.go.ke',
                'treasury_phone': '+254722300300'
            }
        ]
        
        for county_data in counties_data:
            county, created = County.objects.get_or_create(
                code=county_data['code'],
                defaults=county_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created County: {county.name}'))
        
        self.muranga = County.objects.get(code='047')

    def create_constituencies(self):
        """Create constituencies for Murang'a County"""
        self.stdout.write('Creating constituencies...')
        
        constituencies_data = [
            {
                'name': 'Kangema',
                'code': '047-01',
                'current_mp': 'Hon. Peter Kihungi',
                'mp_party': 'UDA',
                'cdf_office_location': 'Kangema Town',
                'cdf_office_email': 'cdf@kangema.go.ke',
                'cdf_office_phone': '+254722111111',
                'annual_cdf_allocation': Decimal('150000000.00'),
                'cdf_bursary_allocation': Decimal('52500000.00'),
                'population': 180000
            },
            {
                'name': 'Kiharu',
                'code': '047-02',
                'current_mp': 'Hon. Ndindi Nyoro',
                'mp_party': 'UDA',
                'cdf_office_location': 'Baricho',
                'cdf_office_email': 'cdf@kiharu.go.ke',
                'cdf_office_phone': '+254722222222',
                'annual_cdf_allocation': Decimal('145000000.00'),
                'cdf_bursary_allocation': Decimal('50750000.00'),
                'population': 175000
            },
            {
                'name': 'Mathioya',
                'code': '047-03',
                'current_mp': 'Hon. Edwin Mugo',
                'mp_party': 'UDA',
                'cdf_office_location': 'Mathioya',
                'cdf_office_email': 'cdf@mathioya.go.ke',
                'cdf_office_phone': '+254722333333',
                'annual_cdf_allocation': Decimal('140000000.00'),
                'cdf_bursary_allocation': Decimal('49000000.00'),
                'population': 165000
            },
            {
                'name': 'Kigumo',
                'code': '047-04',
                'current_mp': 'Hon. Joseph Munyoro',
                'mp_party': 'UDA',
                'cdf_office_location': 'Kigumo Town',
                'cdf_office_email': 'cdf@kigumo.go.ke',
                'cdf_office_phone': '+254722444444',
                'annual_cdf_allocation': Decimal('142000000.00'),
                'cdf_bursary_allocation': Decimal('49700000.00'),
                'population': 168000
            },
            {
                'name': 'Maragua',
                'code': '047-05',
                'current_mp': 'Hon. Mary Wamaua',
                'mp_party': 'UDA',
                'cdf_office_location': 'Maragua Town',
                'cdf_office_email': 'cdf@maragua.go.ke',
                'cdf_office_phone': '+254722555555',
                'annual_cdf_allocation': Decimal('148000000.00'),
                'cdf_bursary_allocation': Decimal('51800000.00'),
                'population': 172000
            }
        ]
        
        for const_data in constituencies_data:
            constituency, created = Constituency.objects.get_or_create(
                name=const_data['name'],
                county=self.muranga,
                defaults=const_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Constituency: {constituency.name}'))

    def create_wards(self):
        """Create wards for constituencies"""
        self.stdout.write('Creating wards...')
        
        # Get all constituencies in Murang'a
        constituencies = Constituency.objects.filter(county=self.muranga)
        
        ward_names = [
            ['Muguru', 'Kanyenya-ini', 'Rwathia', 'Kangema'],
            ['Wangu', 'Mugoiri', 'Mbiri', 'Kiharu'],
            ['Gitugi', 'Kamacharia', 'Kiru', 'Mathioya'],
            ['Kigumo', 'Muthithi', 'Kinyona', 'Kahumbu'],
            ['Makuyu', 'Kambiti', 'Ichagaki', 'Kimorori']
        ]
        
        for idx, constituency in enumerate(constituencies):
            for ward_name in ward_names[idx]:
                ward, created = Ward.objects.get_or_create(
                    name=ward_name,
                    constituency=constituency,
                    defaults={
                        'code': f'W{idx+1}{ward_names[idx].index(ward_name)+1:02d}',
                        'current_mca': f'Hon. {random.choice(["James", "Mary", "Peter", "Grace", "John", "Jane"])} {random.choice(["Kamau", "Wanjiku", "Mwangi", "Njeri", "Kariuki"])}',
                        'mca_party': random.choice(['UDA', 'Jubilee', 'ODM']),
                        'mca_phone': f'+2547227{random.randint(10000, 99999)}',
                        'population': random.randint(25000, 45000)
                    }
                )
                if created:
                    self.stdout.write(self.style.SUCCESS(f'  ✓ Created Ward: {ward.name}'))
        
        self.all_wards = list(Ward.objects.filter(constituency__county=self.muranga))

    def create_locations(self):
        """Create locations, sublocations, and villages"""
        self.stdout.write('Creating administrative locations...')
        
        location_names = ['Gathanga', 'Kiriaini', 'Gatukuyu', 'Kamacharia', 'Gatura', 'Kimorori']
        sublocation_names = ['Central', 'East', 'West', 'North', 'South']
        village_names = ['Gatukuyu', 'Kamacharia', 'Kiriaini', 'Gatura', 'Kambiti', 'Makuyu']
        
        for ward in self.all_wards[:10]:  # Create for first 10 wards
            for loc_name in random.sample(location_names, 2):
                location, created = Location.objects.get_or_create(
                    name=f'{loc_name} ({ward.name})',
                    ward=ward,
                    defaults={'population': random.randint(8000, 15000)}
                )
                
                if created:
                    # Create sublocations
                    for subloc_name in random.sample(sublocation_names, 2):
                        sublocation, subloc_created = SubLocation.objects.get_or_create(
                            name=f'{subloc_name} {loc_name}',
                            location=location
                        )
                        
                        if subloc_created:
                            # Create villages
                            for village_name in random.sample(village_names, 2):
                                Village.objects.get_or_create(
                                    name=f'{village_name} Village',
                                    sublocation=sublocation,
                                    defaults={
                                        'village_elder': f'Mzee {random.choice(["Kamau", "Wanjiku", "Mwangi", "Njeri"])}',
                                        'elder_phone': f'+2547229999{random.randint(10, 99)}'
                                    }
                                )

    def create_institutions(self):
        """Create educational institutions"""
        self.stdout.write('Creating institutions...')
        
        # High Schools
        high_schools = [
            'Murang\'a High School', 'Kangema Girls', 'Kiharu Boys', 'Mathioya Mixed',
            'Kigumo High School', 'Maragua High', 'Kiriaini Secondary', 'Gatanga Secondary',
            'Mugoiri Secondary', 'Rwathia Girls', 'Wangu Boys', 'Gatura Mixed',
            'Kahumbu Secondary', 'Kinyona High', 'Makuyu Secondary', 'Kambiti Girls'
        ]
        
        # Universities
        universities = [
            'Karatina University', 'Murang\'a University of Technology', 
            'University of Nairobi', 'Kenyatta University', 'Jomo Kenyatta University',
            'Egerton University', 'Moi University', 'Maseno University'
        ]
        
        # Colleges and Technical Institutes
        colleges = [
            'Murang\'a Technical Training Institute', 'Kirinyaga National Polytechnic',
            'Kenya Medical Training College - Murang\'a', 'Thika Technical Training Institute',
            'Embu University College', 'Muranga Teachers College'
        ]
        
        all_institutions = []
        
        # Create high schools
        for school_name in high_schools:
            institution, created = Institution.objects.get_or_create(
                name=school_name,
                defaults={
                    'institution_type': 'highschool',
                    'county': self.muranga,
                    'sub_county': random.choice(['Murang\'a South', 'Murang\'a North', 'Kangema', 'Kiharu']),
                    'postal_address': f'P.O. Box {random.randint(100, 999)} Murang\'a',
                    'phone_number': f'+2547221{random.randint(10000, 99999)}',
                    'email': f'info@{school_name.lower().replace(" ", "").replace("\'", "")}.ac.ke',
                    'principal_name': f'{random.choice(["Mr.", "Mrs.", "Ms."])} {random.choice(["James", "Mary", "Peter", "Grace"])} {random.choice(["Kamau", "Wanjiku", "Mwangi", "Njeri"])}',
                    'bank_name': random.choice(['Kenya Commercial Bank', 'Equity Bank', 'Co-operative Bank']),
                    'bank_branch': 'Murang\'a',
                    'account_number': f'{random.randint(1000000000, 9999999999)}',
                    'account_name': school_name
                }
            )
            if created:
                all_institutions.append(institution)
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created High School: {institution.name}'))
        
        # Create universities
        for uni_name in universities:
            institution, created = Institution.objects.get_or_create(
                name=uni_name,
                defaults={
                    'institution_type': 'university',
                    'county': self.muranga if 'Murang\'a' in uni_name or 'Karatina' in uni_name else None,
                    'postal_address': f'P.O. Box {random.randint(1000, 9999)}',
                    'phone_number': f'+2547222{random.randint(10000, 99999)}',
                    'email': f'info@{uni_name.lower().replace(" ", "").replace("\'", "")}.ac.ke',
                    'principal_name': f'Prof. {random.choice(["James", "Mary", "Peter", "Grace"])} {random.choice(["Kamau", "Wanjiku", "Mwangi", "Njeri"])}',
                    'bank_name': random.choice(['Kenya Commercial Bank', 'Equity Bank', 'Co-operative Bank']),
                    'account_number': f'{random.randint(1000000000, 9999999999)}',
                    'account_name': uni_name
                }
            )
            if created:
                all_institutions.append(institution)
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created University: {institution.name}'))
        
        # Create colleges
        for college_name in colleges:
            institution, created = Institution.objects.get_or_create(
                name=college_name,
                defaults={
                    'institution_type': random.choice(['college', 'technical_institute']),
                    'county': self.muranga,
                    'postal_address': f'P.O. Box {random.randint(100, 999)} Murang\'a',
                    'phone_number': f'+2547223{random.randint(10000, 99999)}',
                    'email': f'info@{college_name.lower().replace(" ", "").replace("\'", "")}.ac.ke',
                    'principal_name': f'{random.choice(["Mr.", "Mrs.", "Dr."])} {random.choice(["James", "Mary", "Peter", "Grace"])} {random.choice(["Kamau", "Wanjiku", "Mwangi", "Njeri"])}',
                    'bank_name': random.choice(['Kenya Commercial Bank', 'Equity Bank', 'Co-operative Bank']),
                    'account_number': f'{random.randint(1000000000, 9999999999)}',
                    'account_name': college_name
                }
            )
            if created:
                all_institutions.append(institution)
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created College/Institute: {institution.name}'))
        
        self.all_institutions = Institution.objects.all()

    def create_fiscal_years(self):
        """Create fiscal years from 2021-2022 to 2024-2025"""
        self.stdout.write('Creating fiscal years...')
        
        fiscal_years_data = [
            {
                'name': '2021-2022',
                'start_date': datetime(2021, 7, 1).date(),
                'end_date': datetime(2022, 6, 30).date(),
                'total_bursary_allocation': Decimal('180000000.00'),
                'is_active': False,
                'application_open': False,
            },
            {
                'name': '2022-2023',
                'start_date': datetime(2022, 7, 1).date(),
                'end_date': datetime(2023, 6, 30).date(),
                'total_bursary_allocation': Decimal('200000000.00'),
                'is_active': False,
                'application_open': False,
            },
            {
                'name': '2023-2024',
                'start_date': datetime(2023, 7, 1).date(),
                'end_date': datetime(2024, 6, 30).date(),
                'total_bursary_allocation': Decimal('230000000.00'),
                'is_active': False,
                'application_open': False,
            },
            {
                'name': '2024-2025',
                'start_date': datetime(2024, 7, 1).date(),
                'end_date': datetime(2025, 6, 30).date(),
                'total_bursary_allocation': Decimal('250000000.00'),
                'is_active': True,
                'application_open': True,
                'application_deadline': datetime(2025, 2, 28).date(),
            }
        ]
        
        self.fiscal_years = []
        for fy_data in fiscal_years_data:
            fiscal_year, created = FiscalYear.objects.get_or_create(
                name=fy_data['name'],
                defaults={
                    **fy_data,
                    'county': self.muranga,
                    'total_county_budget': Decimal('12000000000.00'),
                    'education_budget': Decimal('3600000000.00'),
                    'equitable_share': Decimal('8000000000.00'),
                    'conditional_grants': Decimal('2000000000.00'),
                    'number_of_disbursement_rounds': 2,
                    'created_by': self.county_admin
                }
            )
            if created:
                self.fiscal_years.append(fiscal_year)
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Fiscal Year: {fiscal_year.name}'))
        
        self.current_fiscal_year = FiscalYear.objects.get(name='2024-2025')

    def create_ward_allocations(self):
        """Create ward allocations for all fiscal years"""
        self.stdout.write('Creating ward allocations...')
        
        for fiscal_year in FiscalYear.objects.all():
            wards = Ward.objects.filter(constituency__county=self.muranga)
            total_allocation = fiscal_year.total_bursary_allocation
            per_ward_allocation = total_allocation / wards.count()
            
            for ward in wards:
                # Vary spending based on year (older years have more spent)
                if fiscal_year.name in ['2021-2022', '2022-2023']:
                    spent_percentage = Decimal(random.uniform(0.85, 0.98))
                elif fiscal_year.name == '2023-2024':
                    spent_percentage = Decimal(random.uniform(0.70, 0.85))
                else:  # 2024-2025 (current)
                    spent_percentage = Decimal(random.uniform(0.20, 0.40))
                
                allocation, created = WardAllocation.objects.get_or_create(
                    fiscal_year=fiscal_year,
                    ward=ward,
                    defaults={
                        'allocated_amount': per_ward_allocation,
                        'spent_amount': per_ward_allocation * spent_percentage,
                        'beneficiaries_count': int((per_ward_allocation * spent_percentage) / 25000)
                    }
                )
                if created and fiscal_year == self.current_fiscal_year:
                    self.stdout.write(self.style.SUCCESS(f'  ✓ Created allocation for: {ward.name} ({fiscal_year.name})'))

    def create_bursary_categories(self):
        """Create bursary categories for all fiscal years"""
        self.stdout.write('Creating bursary categories...')
        
        categories_template = [
            {
                'name': 'High School Bursary',
                'category_type': 'highschool',
                'allocation_percentage': 0.32,
                'max_amount_per_applicant': Decimal('30000.00'),
                'min_amount_per_applicant': Decimal('10000.00'),
            },
            {
                'name': 'University Bursary',
                'category_type': 'university',
                'allocation_percentage': 0.40,
                'max_amount_per_applicant': Decimal('60000.00'),
                'min_amount_per_applicant': Decimal('20000.00'),
            },
            {
                'name': 'College Bursary',
                'category_type': 'college',
                'allocation_percentage': 0.16,
                'max_amount_per_applicant': Decimal('40000.00'),
                'min_amount_per_applicant': Decimal('15000.00'),
            },
            {
                'name': 'Technical/Vocational Bursary',
                'category_type': 'technical',
                'allocation_percentage': 0.12,
                'max_amount_per_applicant': Decimal('35000.00'),
                'min_amount_per_applicant': Decimal('12000.00'),
            }
        ]
        
        for fiscal_year in FiscalYear.objects.all():
            for cat_template in categories_template:
                allocation_amount = fiscal_year.total_bursary_allocation * Decimal(str(cat_template['allocation_percentage']))
                avg_amount = (cat_template['max_amount_per_applicant'] + cat_template['min_amount_per_applicant']) / 2
                target_beneficiaries = int(allocation_amount / avg_amount)
                
                category, created = BursaryCategory.objects.get_or_create(
                    name=cat_template['name'],
                    fiscal_year=fiscal_year,
                    defaults={
                        'category_type': cat_template['category_type'],
                        'allocation_amount': allocation_amount,
                        'max_amount_per_applicant': cat_template['max_amount_per_applicant'],
                        'min_amount_per_applicant': cat_template['min_amount_per_applicant'],
                        'target_beneficiaries': target_beneficiaries
                    }
                )
                if created and fiscal_year == self.current_fiscal_year:
                    self.stdout.write(self.style.SUCCESS(f'  ✓ Created Category: {category.name} ({fiscal_year.name})'))

    def create_disbursement_rounds(self):
        """Create disbursement rounds for all fiscal years"""
        self.stdout.write('Creating disbursement rounds...')
        
        for fiscal_year in FiscalYear.objects.all():
            year_start = int(fiscal_year.name.split('-')[0])
            
            # Round 1
            round1, created = DisbursementRound.objects.get_or_create(
                fiscal_year=fiscal_year,
                round_number=1,
                defaults={
                    'name': f'First Semester {year_start}',
                    'application_start_date': datetime(year_start, 7, 1).date(),
                    'application_end_date': datetime(year_start, 10, 31).date(),
                    'review_deadline': datetime(year_start, 11, 30).date(),
                    'disbursement_date': datetime(year_start, 12, 15).date(),
                    'allocated_amount': fiscal_year.total_bursary_allocation / 2,
                    'disbursed_amount': fiscal_year.total_bursary_allocation / 2 if fiscal_year.name != '2024-2025' else Decimal('0.00'),
                    'is_open': False,
                    'is_completed': fiscal_year.name not in ['2024-2025']
                }
            )
            
            if created and fiscal_year == self.current_fiscal_year:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Disbursement Round: {round1.name}'))

            # Round 2
            round2, created = DisbursementRound.objects.get_or_create(
                fiscal_year=fiscal_year,
                round_number=2,
                defaults={
                    'name': f'Second Semester {year_start + 1}',
                    'application_start_date': datetime(year_start + 1, 1, 1).date(),
                    'application_end_date': datetime(year_start + 1, 4, 30).date(),
                    'review_deadline': datetime(year_start + 1, 5, 31).date(),
                    'disbursement_date': datetime(year_start + 1, 6, 15).date(),
                    'allocated_amount': fiscal_year.total_bursary_allocation / 2,
                    'disbursed_amount': fiscal_year.total_bursary_allocation / 2 if fiscal_year.name != '2024-2025' else Decimal('0.00'),
                    'is_open': False,
                    'is_completed': fiscal_year.name not in ['2024-2025']
                }
            )
            if created and fiscal_year == self.current_fiscal_year:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Disbursement Round: {round2.name}'))

    def create_applicants(self):
        """Create 300 sample applicants"""
        self.stdout.write('Creating 300 applicants...')
        
        # Kenyan first names
        male_first_names = [
            'John', 'Peter', 'David', 'James', 'Joseph', 'Samuel', 'Daniel', 'Paul',
            'Michael', 'Stephen', 'Anthony', 'Francis', 'Patrick', 'Thomas', 'Moses',
            'Benjamin', 'Simon', 'Timothy', 'Isaac', 'Joshua', 'Emmanuel', 'Mark',
            'Luke', 'Matthew', 'Andrew', 'Philip', 'George', 'Robert', 'Kenneth',
            'Brian', 'Dennis', 'Eric', 'Felix', 'Victor', 'Collins', 'Kevin', 'Allan'
        ]
        
        female_first_names = [
            'Mary', 'Grace', 'Jane', 'Lucy', 'Faith', 'Joyce', 'Anne', 'Rose',
            'Catherine', 'Margaret', 'Ruth', 'Esther', 'Sarah', 'Rebecca', 'Rachel',
            'Hannah', 'Elizabeth', 'Agnes', 'Beatrice', 'Christine', 'Diana', 'Emily',
            'Florence', 'Helen', 'Irene', 'Janet', 'Joan', 'Lydia', 'Martha', 'Nancy',
            'Patricia', 'Susan', 'Teresa', 'Violet', 'Winnie', 'Alice', 'Eunice'
        ]
        
        # Kikuyu surnames
        last_names = [
            'Kamau', 'Wanjiku', 'Mwangi', 'Njeri', 'Kariuki', 'Wambui', 'Njoroge',
            'Nyambura', 'Kimani', 'Wangari', 'Githinji', 'Wairimu', 'Karanja', 'Wanjiru',
            'Gathoni', 'Muchoki', 'Njoki', 'Kiarie', 'Wangui', 'Muturi', 'Muthoni',
            'Mbugua', 'Nyokabi', 'Ndung\'u', 'Waweru', 'Gitau', 'Kinyanjui', 'Mugo',
            'Nderitu', 'Njihia', 'Kahiga', 'Gachie', 'Muriithi', 'Thuo', 'Kamakia',
            'Kihara', 'Nduta', 'Macharia', 'Muiruri', 'Gakii'
        ]
        
        self.applicants = []
        
        for i in range(1, 301):  # Create 300 applicants
            # Alternate gender
            gender = 'M' if i % 2 == 0 else 'F'
            first_name = random.choice(male_first_names if gender == 'M' else female_first_names)
            last_name = random.choice(last_names)
            
            # Generate unique username
            username = f'{first_name.lower()}.{last_name.lower()}{i}'
            
            # Age range for students (15-24 years old)
            birth_year = random.randint(2000, 2009)
            birth_month = random.randint(1, 12)
            birth_day = random.randint(1, 28)
            date_of_birth = datetime(birth_year, birth_month, birth_day).date()
            
            # Random ward
            ward = random.choice(self.all_wards)
            
            # Create user
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': f'{username}@email.com',
                    'first_name': first_name,
                    'last_name': last_name,
                    'user_type': 'applicant',
                    'phone_number': f'+25472{random.randint(1000000, 9999999)}'
                }
            )
            if created:
                user.set_password('applicant123')
                user.save()
            
            # Create applicant profile
            applicant, created = Applicant.objects.get_or_create(
                user=user,
                defaults={
                    'gender': gender,
                    'date_of_birth': date_of_birth,
                    'id_number': f'{random.randint(30000000, 39999999)}',
                    'county': self.muranga,
                    'constituency': ward.constituency,
                    'ward': ward,
                    'physical_address': f'{random.choice(["Gatukuyu", "Kamacharia", "Kiriaini", "Gatura", "Gathanga"])} Village, {ward.name} Ward',
                    'special_needs': random.choice([False, False, False, False, True]),
                    'special_needs_description': 'Visual impairment' if random.choice([True, False]) else None,
                    'is_verified': random.choice([True, True, True, False]),
                    'verified_by': self.county_admin if random.choice([True, False]) else None,
                    'verification_date': timezone.now() - timedelta(days=random.randint(1, 180)) if random.choice([True, False]) else None
                }
            )
            
            if created:
                self.applicants.append(applicant)
                if i % 50 == 0:  # Progress indicator every 50 applicants
                    self.stdout.write(self.style.SUCCESS(f'  ✓ Created {i} applicants...'))
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Total Applicants Created: {len(self.applicants)}'))

    def create_guardians(self):
        """Create guardians for applicants"""
        self.stdout.write('Creating guardians...')
        
        occupations = [
            'Farmer', 'Teacher', 'Driver', 'Businessman', 'Trader', 'Mechanic',
            'Carpenter', 'Mason', 'Shop Keeper', 'Salesperson', 'Accountant',
            'Nurse', 'Police Officer', 'Civil Servant', 'Casual Laborer',
            'Tailor', 'Electrician', 'Plumber', 'Security Guard', 'Cook'
        ]
        
        for idx, applicant in enumerate(self.applicants):
            # Father
            Guardian.objects.get_or_create(
                applicant=applicant,
                name=f'{applicant.user.last_name} Senior',
                defaults={
                    'relationship': random.choice(['father', 'father', 'guardian', 'uncle']),
                    'phone_number': f'+25472{random.randint(1000000, 9999999)}',
                    'employment_status': random.choice(['employed', 'self_employed', 'casual', 'unemployed', 'deceased']),
                    'occupation': random.choice(occupations),
                    'monthly_income': Decimal(random.randint(10000, 60000)),
                    'is_primary_contact': True
                }
            )
            
            # Mother
            Guardian.objects.get_or_create(
                applicant=applicant,
                name=f'{applicant.user.first_name}\'s Mother',
                defaults={
                    'relationship': random.choice(['mother', 'mother', 'guardian', 'aunt']),
                    'phone_number': f'+25472{random.randint(1000000, 9999999)}',
                    'employment_status': random.choice(['self_employed', 'casual', 'unemployed', 'employed', 'deceased']),
                    'occupation': random.choice(occupations),
                    'monthly_income': Decimal(random.randint(5000, 40000)),
                    'is_primary_contact': False
                }
            )
            
            # Create siblings
            num_siblings = random.randint(1, 5)
            for i in range(num_siblings):
                SiblingInformation.objects.get_or_create(
                    applicant=applicant,
                    name=f'{applicant.user.last_name} Sibling {i+1}',
                    defaults={
                        'age': random.randint(5, 22),
                        'education_level': random.choice(['Primary', 'Form 1', 'Form 2', 'Form 3', 'Form 4', 'College', 'University']),
                        'school_name': f'{random.choice(["St. Mary\'s", "Kangema", "Murang\'a", "Kiharu", "Mathioya"])} School',
                        'is_in_school': random.choice([True, True, True, False])
                    }
                )
            
            if (idx + 1) % 100 == 0:  # Progress indicator
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created guardians for {idx + 1} applicants...'))

    def create_applications(self):
        """Create applications for applicants across different fiscal years"""
        self.stdout.write('Creating applications...')
        
        all_fiscal_years = list(FiscalYear.objects.all().order_by('start_date'))
        institutions_by_type = {
            'highschool': list(self.all_institutions.filter(institution_type='highschool')),
            'university': list(self.all_institutions.filter(institution_type='university')),
            'college': list(self.all_institutions.filter(institution_type='college')),
            'technical_institute': list(self.all_institutions.filter(institution_type='technical_institute'))
        }
        
        courses = {
            'university': [
                'Bachelor of Education', 'Bachelor of Science', 'Bachelor of Commerce',
                'Bachelor of Arts', 'Bachelor of Engineering', 'Bachelor of Medicine',
                'Bachelor of Law', 'Bachelor of Nursing', 'Bachelor of Computer Science',
                'Bachelor of Business Administration'
            ],
            'college': [
                'Diploma in Business Management', 'Diploma in Information Technology',
                'Diploma in Nursing', 'Diploma in Journalism', 'Diploma in Accounting',
                'Diploma in Marketing', 'Diploma in Social Work'
            ],
            'technical_institute': [
                'Certificate in Electrical Engineering', 'Certificate in Motor Vehicle Mechanics',
                'Certificate in Plumbing', 'Certificate in Carpentry', 'Certificate in Masonry',
                'Diploma in Building Construction', 'Diploma in Automotive Engineering'
            ]
        }
        
        application_count = 0
        
        for idx, applicant in enumerate(self.applicants):
            # Determine how many years this applicant has been applying
            years_applying = random.randint(1, min(4, len(all_fiscal_years)))
            
            # Get the fiscal years this applicant will apply in
            fiscal_years_for_applicant = all_fiscal_years[-years_applying:]
            
            for year_idx, fiscal_year in enumerate(fiscal_years_for_applicant):
                # Get categories for this fiscal year
                categories = list(BursaryCategory.objects.filter(fiscal_year=fiscal_year))
                category = random.choice(categories)
                
                # Select institution based on category
                if category.category_type == 'highschool':
                    if institutions_by_type['highschool']:
                        institution = random.choice(institutions_by_type['highschool'])
                    else:
                        continue
                    year_of_study = min(year_idx + 1, 4)
                    course_name = None
                    total_fees = Decimal(random.randint(40000, 80000))
                    amount_requested = Decimal(random.randint(10000, 30000))
                elif category.category_type == 'university':
                    if institutions_by_type['university']:
                        institution = random.choice(institutions_by_type['university'])
                    else:
                        continue
                    year_of_study = min(year_idx + 1, 4)
                    course_name = random.choice(courses['university'])
                    total_fees = Decimal(random.randint(120000, 280000))
                    amount_requested = Decimal(random.randint(20000, 60000))
                elif category.category_type == 'college':
                    if institutions_by_type['college']:
                        institution = random.choice(institutions_by_type['college'])
                    else:
                        continue
                    year_of_study = min(year_idx + 1, 3)
                    course_name = random.choice(courses['college'])
                    total_fees = Decimal(random.randint(80000, 150000))
                    amount_requested = Decimal(random.randint(15000, 40000))
                else:  # technical
                    if institutions_by_type['technical_institute']:
                        institution = random.choice(institutions_by_type['technical_institute'])
                    else:
                        continue
                    year_of_study = min(year_idx + 1, 2)
                    course_name = random.choice(courses['technical_institute'])
                    total_fees = Decimal(random.randint(50000, 100000))
                    amount_requested = Decimal(random.randint(12000, 35000))
                
                # Calculate fees
                fees_paid = total_fees * Decimal(random.uniform(0.1, 0.4))
                fees_balance = total_fees - fees_paid
                
                # Determine status based on fiscal year
                if fiscal_year.name in ['2021-2022', '2022-2023', '2023-2024']:
                    status = random.choice(['disbursed', 'disbursed', 'approved', 'rejected'])
                else:  # 2024-2025
                    status = random.choice(['submitted', 'under_review', 'approved', 'disbursed', 'pending_documents'])
                
                # Get disbursement round
                disbursement_round = DisbursementRound.objects.filter(
                    fiscal_year=fiscal_year, 
                    round_number=random.choice([1, 2])
                ).first()
                
                # Submission date within the fiscal year
                year_start = int(fiscal_year.name.split('-')[0])
                days_offset = random.randint(30, 300)
                date_submitted = datetime(year_start, 7, 1) + timedelta(days=days_offset)
                
                application, created = Application.objects.get_or_create(
                    applicant=applicant,
                    fiscal_year=fiscal_year,
                    defaults={
                        'disbursement_round': disbursement_round,
                        'bursary_category': category,
                        'institution': institution,
                        'bursary_source': random.choice(['county', 'county', 'county', 'cdf']),
                        'status': status,
                        'admission_number': f'{institution.name[:3].upper()}/{random.randint(1000, 9999)}/{year_start}',
                        'year_of_study': year_of_study,
                        'course_name': course_name,
                        'expected_completion_date': datetime(year_start + year_of_study, 12, 15).date(),
                        'previous_academic_year_average': Decimal(random.uniform(50, 90)),
                        'total_fees_payable': total_fees,
                        'fees_paid': fees_paid,
                        'fees_balance': fees_balance,
                        'amount_requested': amount_requested,
                        'other_bursaries': random.choice([True, False, False]),
                        'other_bursaries_amount': Decimal(random.randint(5000, 20000)) if random.choice([True, False]) else Decimal('0.00'),
                        'other_bursaries_source': random.choice(['NG-CDF', 'HELB', 'Private Sponsor']) if random.choice([True, False]) else None,
                        'is_orphan': random.choice([True, False, False, False, False]),
                        'is_total_orphan': random.choice([True, False, False, False, False, False]),
                        'is_disabled': random.choice([True, False, False, False, False, False]),
                        'has_chronic_illness': random.choice([True, False, False, False, False]),
                        'number_of_siblings': random.randint(1, 6),
                        'number_of_siblings_in_school': random.randint(0, 4),
                        'household_monthly_income': Decimal(random.randint(10000, 60000)),
                        'date_submitted': date_submitted,
                        'has_received_previous_allocation': year_idx > 0,
                        'previous_allocation_year': all_fiscal_years[-year_idx].name if year_idx > 0 else None,
                        'previous_allocation_amount': Decimal(random.randint(10000, 40000)) if year_idx > 0 else Decimal('0.00'),
                        'priority_score': Decimal(random.uniform(50, 98))
                    }
                )
                
                if created:
                    application_count += 1
            
            if (idx + 1) % 50 == 0:  # Progress indicator
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created applications for {idx + 1} applicants... (Total applications: {application_count})'))
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Total Applications Created: {application_count}'))

    def create_reviews(self):
        """Create reviews for applications"""
        self.stdout.write('Creating reviews...')
        
        # Get applications that should have reviews
        applications_to_review = Application.objects.filter(
            status__in=['under_review', 'approved', 'disbursed']
        )
        
        review_count = 0
        for application in applications_to_review:
            # Ward level review
            Review.objects.get_or_create(
                application=application,
                review_level='ward',
                defaults={
                    'reviewer': self.ward_admin,
                    'comments': f'Verified applicant from {application.applicant.ward.name} Ward. {random.choice(["Family situation confirmed.", "Documents verified.", "Needs assessment completed.", "Background check done."])}',
                    'recommendation': random.choice(['forward', 'approve', 'approve']),
                    'recommended_amount': application.amount_requested * Decimal(random.uniform(0.6, 0.9)),
                    'need_score': random.randint(6, 10),
                    'merit_score': random.randint(5, 9),
                    'vulnerability_score': random.randint(5, 10),
                    'review_date': application.date_submitted + timedelta(days=random.randint(5, 25))
                }
            )
            review_count += 1
            
            # County level review for approved/disbursed applications
            if application.status in ['approved', 'disbursed']:
                Review.objects.get_or_create(
                    application=application,
                    review_level='county',
                    defaults={
                        'reviewer': self.reviewer,
                        'comments': random.choice([
                            'Application meets all criteria. Recommended for allocation.',
                            'Strong academic performance. Family needs verified.',
                            'Documents complete. Needs assessment satisfactory.',
                            'Approved based on vulnerability and academic merit.'
                        ]),
                        'recommendation': 'approve',
                        'recommended_amount': application.amount_requested * Decimal(random.uniform(0.5, 0.8)),
                        'need_score': random.randint(7, 10),
                        'merit_score': random.randint(6, 9),
                        'vulnerability_score': random.randint(6, 10),
                        'review_date': application.date_submitted + timedelta(days=random.randint(30, 50))
                    }
                )
                review_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Total Reviews Created: {review_count}'))

    def create_allocations(self):
        """Create allocations for approved/disbursed applications"""
        self.stdout.write('Creating allocations...')
        
        approved_applications = Application.objects.filter(
            status__in=['approved', 'disbursed']
        )
        
        allocation_count = 0
        for application in approved_applications:
            # Calculate allocation amount (60-80% of requested)
            allocation_amount = application.amount_requested * Decimal(random.uniform(0.6, 0.8))
            
            # Determine if disbursed based on fiscal year and status
            is_disbursed = application.status == 'disbursed' or application.fiscal_year.name in ['2021-2022', '2022-2023', '2023-2024']
            
            allocation, created = Allocation.objects.get_or_create(
                application=application,
                defaults={
                    'amount_allocated': allocation_amount,
                    'approved_by': self.county_admin,
                    'payment_method': random.choice(['cheque', 'cheque', 'bulk_cheque', 'bank_transfer']),
                    'cheque_number': f'CHQ/{random.randint(100000, 999999)}' if random.choice([True, False]) else None,
                    'is_disbursed': is_disbursed,
                    'disbursement_date': (application.date_submitted + timedelta(days=random.randint(60, 120))).date() if is_disbursed else None,
                    'disbursed_by': self.finance_officer if is_disbursed else None,
                    'is_received_by_institution': is_disbursed and random.choice([True, True, False]),
                    'institution_confirmation_date': (application.date_submitted + timedelta(days=random.randint(70, 130))).date() if is_disbursed and random.choice([True, False]) else None,
                    'institution_receipt_number': f'RCP/{random.randint(1000, 9999)}' if is_disbursed and random.choice([True, False]) else None,
                    'remarks': random.choice([
                        'Allocation approved based on need assessment.',
                        'Disbursed as per approved budget.',
                        'Payment processed successfully.',
                        'Verified and approved for disbursement.'
                    ])
                }
            )
            
            if created:
                allocation_count += 1
                
                # Update application status if not already disbursed
                if application.status == 'approved' and is_disbursed:
                    application.status = 'disbursed'
                    application.save()
                
                # Update ward allocation
                ward_allocation = WardAllocation.objects.get(
                    fiscal_year=application.fiscal_year,
                    ward=application.applicant.ward
                )
                ward_allocation.spent_amount += allocation_amount
                ward_allocation.beneficiaries_count += 1
                ward_allocation.save()
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Total Allocations Created: {allocation_count}'))

    def create_faqs(self):
        """Create FAQs"""
        self.stdout.write('Creating FAQs...')
        
        faqs_data = [
            {
                'question': 'Who is eligible to apply for the Murang\'a County Bursary?',
                'answer': 'Any student who is a resident of Murang\'a County and is enrolled in a recognized educational institution (high school, college, university, or technical institute) is eligible to apply. Priority is given to needy and vulnerable students.',
                'category': 'eligibility',
                'order': 1
            },
            {
                'question': 'What documents do I need to apply?',
                'answer': 'You need: 1) National ID or Birth Certificate, 2) Admission letter, 3) Fee structure, 4) Fee balance statement, 5) Parent/Guardian ID, 6) Academic transcripts, 7) Chief\'s recommendation letter (optional but helpful).',
                'category': 'documents',
                'order': 2
            },
            {
                'question': 'When do applications open?',
                'answer': 'Applications typically open twice a year: July-October for first semester and January-April for second semester. Check announcements for exact dates.',
                'category': 'application',
                'order': 3
            },
            {
                'question': 'How much bursary will I receive?',
                'answer': 'The amount varies based on need assessment, available budget, and education level. High school students typically receive KES 10,000-30,000, while university students receive KES 20,000-60,000 per semester.',
                'category': 'general',
                'order': 4
            },
            {
                'question': 'How long does the review process take?',
                'answer': 'The review process typically takes 4-8 weeks from the application deadline. You will receive SMS and email updates on your application status.',
                'category': 'application',
                'order': 5
            },
            {
                'question': 'When will the bursary be disbursed?',
                'answer': 'Disbursement is done within 2-4 weeks after approval. Payment is made directly to your institution via cheque or bank transfer.',
                'category': 'disbursement',
                'order': 6
            },
            {
                'question': 'Can I apply for both County and NG-CDF bursaries?',
                'answer': 'Yes, you can apply for both. However, you must disclose any other bursaries received in your application.',
                'category': 'eligibility',
                'order': 7
            },
            {
                'question': 'I forgot my password. How do I reset it?',
                'answer': 'Click on "Forgot Password" on the login page. Enter your email or phone number, and you will receive a password reset link via SMS or email.',
                'category': 'technical',
                'order': 8
            },
            {
                'question': 'Can I edit my application after submission?',
                'answer': 'Once submitted, you cannot edit your application. However, if you need to update information, contact the County Education Office at education@muranga.go.ke or call +254722100101.',
                'category': 'application',
                'order': 9
            },
            {
                'question': 'What if my application is rejected?',
                'answer': 'You will receive a notification with reasons for rejection. You can reapply in the next disbursement round after addressing the issues mentioned.',
                'category': 'general',
                'order': 10
            }
        ]
        
        for faq_data in faqs_data:
            faq, created = FAQ.objects.get_or_create(
                question=faq_data['question'],
                defaults=faq_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created FAQ'))

    def create_announcements(self):
        """Create announcements"""
        self.stdout.write('Creating announcements...')
        
        announcements_data = [
            {
                'title': 'First Semester 2024 Applications Now Open',
                'content': 'The Murang\'a County Bursary applications for the first semester 2024 are now open. Deadline for submission is October 31, 2024. Apply online through the Nyota Zetu portal.',
                'announcement_type': 'general',
                'published_date': timezone.now() - timedelta(days=30),
                'expiry_date': timezone.now() + timedelta(days=60),
                'is_active': True,
                'is_featured': True,
                'target_audience': 'all'
            },
            {
                'title': 'Application Deadline Extended',
                'content': 'Due to high demand, the application deadline has been extended to November 15, 2024. This is the final extension.',
                'announcement_type': 'deadline',
                'published_date': timezone.now() - timedelta(days=15),
                'expiry_date': timezone.now() + timedelta(days=45),
                'is_active': True,
                'is_featured': True,
                'target_audience': 'applicants'
            },
            {
                'title': 'System Maintenance Scheduled',
                'content': 'The Nyota Zetu system will undergo maintenance on Saturday, November 10, 2024, from 2:00 AM to 6:00 AM. The system will be unavailable during this time.',
                'announcement_type': 'maintenance',
                'published_date': timezone.now() - timedelta(days=5),
                'expiry_date': timezone.now() + timedelta(days=10),
                'is_active': True,
                'is_featured': False,
                'target_audience': 'all'
            },
            {
                'title': 'Disbursement Update - Round 1',
                'content': 'Congratulations to all successful applicants! Disbursement for Round 1 (2024) has commenced. Cheques will be delivered to institutions starting December 15, 2024.',
                'announcement_type': 'disbursement',
                'published_date': timezone.now() - timedelta(days=2),
                'expiry_date': timezone.now() + timedelta(days=30),
                'is_active': True,
                'is_featured': True,
                'target_audience': 'applicants'
            },
            {
                'title': 'Required Documents Reminder',
                'content': 'All applicants must upload clear, legible copies of required documents. Applications with missing or unclear documents will be rejected.',
                'announcement_type': 'urgent',
                'published_date': timezone.now() - timedelta(days=10),
                'expiry_date': timezone.now() + timedelta(days=20),
                'is_active': True,
                'is_featured': False,
                'target_audience': 'applicants'
            }
        ]
        
        for ann_data in announcements_data:
            announcement, created = Announcement.objects.get_or_create(
                title=ann_data['title'],
                defaults={
                    **ann_data,
                    'created_by': self.county_admin
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Announcement'))

    def create_system_settings(self):
        """Create system settings"""
        self.stdout.write('Creating system settings...')
        
        settings_data = [
            {
                'setting_name': 'MAX_APPLICATION_FILE_SIZE',
                'setting_category': 'application',
                'setting_value': '5242880',
                'description': 'Maximum file size for document uploads in bytes (5MB)'
            },

            
          
            
             {
                'setting_name': 'ALLOWED_FILE_TYPES',
                'setting_category': 'application',
                'setting_value': 'pdf,jpg,jpeg,png,doc,docx',
                'description': 'Allowed file types for document uploads'
            },
            {
                'setting_name': 'APPLICATION_EDIT_DAYS',
                'setting_category': 'application',
                'setting_value': '7',
                'description': 'Number of days applicants can edit application after submission'
            },
            {
                'setting_name': 'SMS_NOTIFICATIONS_ENABLED',
                'setting_category': 'notification',
                'setting_value': 'true',
                'description': 'Enable SMS notifications to applicants'
            },
            {
                'setting_name': 'EMAIL_NOTIFICATIONS_ENABLED',
                'setting_category': 'notification',
                'setting_value': 'true',
                'description': 'Enable email notifications to applicants'
            },
            {
                'setting_name': 'MAX_LOGIN_ATTEMPTS',
                'setting_category': 'security',
                'setting_value': '5',
                'description': 'Maximum failed login attempts before account lockout'
            },
            {
                'setting_name': 'ACCOUNT_LOCKOUT_DURATION',
                'setting_category': 'security',
                'setting_value': '30',
                'description': 'Account lockout duration in minutes'
            },
            {
                'setting_name': 'TFA_ENABLED',
                'setting_category': 'security',
                'setting_value': 'true',
                'description': 'Enable two-factor authentication'
            },
            {
                'setting_name': 'TFA_CODE_EXPIRY',
                'setting_category': 'security',
                'setting_value': '2',
                'description': '2FA code expiry time in minutes'
            },
            {
                'setting_name': 'MIN_BURSARY_AMOUNT',
                'setting_category': 'finance',
                'setting_value': '5000',
                'description': 'Minimum bursary amount that can be allocated'
            },
            {
                'setting_name': 'COUNTY_NAME',
                'setting_category': 'general',
                'setting_value': 'Murang\'a County',
                'description': 'County name for system branding'
            },
            {
                'setting_name': 'SUPPORT_EMAIL',
                'setting_category': 'general',
                'setting_value': 'support@muranga.go.ke',
                'description': 'Support email for applicant inquiries'
            },
            {
                'setting_name': 'SUPPORT_PHONE',
                'setting_category': 'general',
                'setting_value': '+254722100100',
                'description': 'Support phone number for applicant inquiries'
            }
        ]
        
        for setting_data in settings_data:
            setting, created = SystemSettings.objects.get_or_create(
                setting_name=setting_data['setting_name'],
                defaults={
                    **setting_data,
                    'updated_by': self.county_admin
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Setting: {setting.setting_name}'))
        
        self.print_summary()

    def print_summary(self):
        """Print comprehensive summary of seeded data"""
        self.stdout.write(self.style.SUCCESS('\n' + '='*80))
        self.stdout.write(self.style.SUCCESS('DATA SEEDING SUMMARY'))
        self.stdout.write(self.style.SUCCESS('='*80))
        
        self.stdout.write(self.style.WARNING('\n📊 ADMINISTRATIVE DATA:'))
        self.stdout.write(f'  Counties: {County.objects.count()}')
        self.stdout.write(f'  Constituencies: {Constituency.objects.count()}')
        self.stdout.write(f'  Wards: {Ward.objects.count()}')
        self.stdout.write(f'  Locations: {Location.objects.count()}')
        self.stdout.write(f'  Sub-locations: {SubLocation.objects.count()}')
        self.stdout.write(f'  Villages: {Village.objects.count()}')
        
        self.stdout.write(self.style.WARNING('\n🏫 INSTITUTIONS:'))
        self.stdout.write(f'  Total Institutions: {Institution.objects.count()}')
        self.stdout.write(f'    - High Schools: {Institution.objects.filter(institution_type="highschool").count()}')
        self.stdout.write(f'    - Universities: {Institution.objects.filter(institution_type="university").count()}')
        self.stdout.write(f'    - Colleges: {Institution.objects.filter(institution_type="college").count()}')
        self.stdout.write(f'    - Technical Institutes: {Institution.objects.filter(institution_type="technical_institute").count()}')
        
        self.stdout.write(self.style.WARNING('\n💰 FISCAL & BUDGET DATA:'))
        self.stdout.write(f'  Fiscal Years: {FiscalYear.objects.count()}')
        for fy in FiscalYear.objects.all().order_by('start_date'):
            self.stdout.write(f'    - {fy.name}: KES {fy.total_bursary_allocation:,.2f}')
        self.stdout.write(f'  Ward Allocations: {WardAllocation.objects.count()}')
        self.stdout.write(f'  Bursary Categories: {BursaryCategory.objects.count()}')
        self.stdout.write(f'  Disbursement Rounds: {DisbursementRound.objects.count()}')
        
        self.stdout.write(self.style.WARNING('\n👥 USERS & APPLICANTS:'))
        self.stdout.write(f'  Total Users: {User.objects.count()}')
        self.stdout.write(f'    - Staff Users: {User.objects.filter(is_staff=True).count()}')
        self.stdout.write(f'    - Applicant Users: {User.objects.filter(user_type="applicant").count()}')
        self.stdout.write(f'  Applicant Profiles: {Applicant.objects.count()}')
        self.stdout.write(f'  Guardians: {Guardian.objects.count()}')
        self.stdout.write(f'  Siblings: {SiblingInformation.objects.count()}')
        
        self.stdout.write(self.style.WARNING('\n📝 APPLICATIONS & REVIEWS:'))
        