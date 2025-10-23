"""
Django management command to seed the database with realistic Kenyan data
Place this file in: my_application/management/commands/seed_data.py
Run with: python manage.py seed_data
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
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
    help = 'Seeds the database with realistic Kenyan bursary data'

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
        self.create_fiscal_year()
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
                'code': '047',
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
        
        self.kangema = Constituency.objects.get(name='Kangema', county=self.muranga)
        self.kiharu = Constituency.objects.get(name='Kiharu', county=self.muranga)

    def create_wards(self):
        """Create wards for constituencies"""
        self.stdout.write('Creating wards...')
        
        kangema_wards = [
            {
                'name': 'Muguru',
                'code': 'W001',
                'current_mca': 'Hon. James Kariuki',
                'mca_party': 'UDA',
                'mca_phone': '+254722444444',
                'population': 35000
            },
            {
                'name': 'Kanyenya-ini',
                'code': 'W002',
                'current_mca': 'Hon. Grace Wambui',
                'mca_party': 'UDA',
                'mca_phone': '+254722555555',
                'population': 38000
            },
            {
                'name': 'Rwathia',
                'code': 'W003',
                'current_mca': 'Hon. Paul Njoroge',
                'mca_party': 'Jubilee',
                'mca_phone': '+254722666666',
                'population': 32000
            }
        ]
        
        kiharu_wards = [
            {
                'name': 'Wangu',
                'code': 'W004',
                'current_mca': 'Hon. Mary Nyambura',
                'mca_party': 'UDA',
                'mca_phone': '+254722777777',
                'population': 40000
            },
            {
                'name': 'Mugoiri',
                'code': 'W005',
                'current_mca': 'Hon. Samuel Kamau',
                'mca_party': 'UDA',
                'mca_phone': '+254722888888',
                'population': 38000
            }
        ]
        
        for ward_data in kangema_wards:
            ward, created = Ward.objects.get_or_create(
                name=ward_data['name'],
                constituency=self.kangema,
                defaults=ward_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Ward: {ward.name}'))
        
        for ward_data in kiharu_wards:
            ward, created = Ward.objects.get_or_create(
                name=ward_data['name'],
                constituency=self.kiharu,
                defaults=ward_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Ward: {ward.name}'))
        
        self.muguru_ward = Ward.objects.get(name='Muguru')
        self.wangu_ward = Ward.objects.get(name='Wangu')

    def create_locations(self):
        """Create locations, sublocations, and villages"""
        self.stdout.write('Creating administrative locations...')
        
        # Locations in Muguru Ward
        location, created = Location.objects.get_or_create(
            name='Gathanga',
            ward=self.muguru_ward,
            defaults={'population': 12000}
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created Location: {location.name}'))
        
        # Sub-location
        sublocation, created = SubLocation.objects.get_or_create(
            name='Gatura',
            location=location
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created Sub-location: {sublocation.name}'))
        
        # Villages
        villages = ['Gatukuyu', 'Kamacharia', 'Kiriaini']
        for village_name in villages:
            village, created = Village.objects.get_or_create(
                name=village_name,
                sublocation=sublocation,
                defaults={
                    'village_elder': f'Mzee {village_name} Elder',
                    'elder_phone': f'+2547229999{random.randint(10, 99)}'
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Village: {village.name}'))

    def create_institutions(self):
        """Create educational institutions"""
        self.stdout.write('Creating institutions...')
        
        institutions_data = [
            {
                'name': 'Murang\'a High School',
                'institution_type': 'highschool',
                'county': self.muranga,
                'sub_county': 'Murang\'a South',
                'postal_address': 'P.O. Box 123 Murang\'a',
                'phone_number': '+254722101010',
                'email': 'info@murangahigh.ac.ke',
                'principal_name': 'Mr. Joseph Kamau',
                'principal_phone': '+254722101011',
                'principal_email': 'principal@murangahigh.ac.ke',
                'bank_name': 'Kenya Commercial Bank',
                'bank_branch': 'Murang\'a',
                'account_number': '1234567890',
                'account_name': 'Murang\'a High School'
            },
            {
                'name': 'Karatina University',
                'institution_type': 'university',
                'county': self.muranga,
                'postal_address': 'P.O. Box 1957-10101 Karatina',
                'phone_number': '+254722202020',
                'email': 'info@karu.ac.ke',
                'principal_name': 'Prof. Mucai Muchiri',
                'principal_phone': '+254722202021',
                'principal_email': 'vc@karu.ac.ke',
                'bank_name': 'Equity Bank',
                'bank_branch': 'Karatina',
                'account_number': '0987654321',
                'account_name': 'Karatina University'
            },
            {
                'name': 'Murang\'a University of Technology',
                'institution_type': 'university',
                'county': self.muranga,
                'postal_address': 'P.O. Box 75-10200 Murang\'a',
                'phone_number': '+254722303030',
                'email': 'info@mut.ac.ke',
                'principal_name': 'Prof. Romanus Odhiambo',
                'bank_name': 'Co-operative Bank',
                'bank_branch': 'Murang\'a',
                'account_number': '1122334455',
                'account_name': 'Murang\'a University of Technology'
            },
            {
                'name': 'Kangema Girls High School',
                'institution_type': 'highschool',
                'county': self.muranga,
                'sub_county': 'Kangema',
                'postal_address': 'P.O. Box 50 Kangema',
                'phone_number': '+254722404040',
                'principal_name': 'Mrs. Jane Wanjiru',
                'bank_name': 'KCB Bank',
                'bank_branch': 'Kangema',
                'account_number': '2233445566',
                'account_name': 'Kangema Girls High School'
            },
            {
                'name': 'Murang\'a Technical Training Institute',
                'institution_type': 'technical_institute',
                'county': self.muranga,
                'postal_address': 'P.O. Box 220 Murang\'a',
                'phone_number': '+254722505050',
                'principal_name': 'Mr. David Githinji',
                'bank_name': 'Equity Bank',
                'bank_branch': 'Murang\'a',
                'account_number': '3344556677',
                'account_name': 'Murang\'a TTI'
            }
        ]
        
        for inst_data in institutions_data:
            institution, created = Institution.objects.get_or_create(
                name=inst_data['name'],
                defaults=inst_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Institution: {institution.name}'))
        
        self.muranga_high = Institution.objects.get(name='Murang\'a High School')
        self.karatina_uni = Institution.objects.get(name='Karatina University')
        self.mut = Institution.objects.get(name='Murang\'a University of Technology')

    def create_fiscal_year(self):
        """Create fiscal year"""
        self.stdout.write('Creating fiscal year...')
        
        self.fiscal_year, created = FiscalYear.objects.get_or_create(
            name='2024-2025',
            defaults={
                'start_date': datetime(2024, 7, 1).date(),
                'end_date': datetime(2025, 6, 30).date(),
                'county': self.muranga,
                'total_county_budget': Decimal('12000000000.00'),
                'education_budget': Decimal('3600000000.00'),
                'total_bursary_allocation': Decimal('250000000.00'),
                'equitable_share': Decimal('8000000000.00'),
                'conditional_grants': Decimal('2000000000.00'),
                'number_of_disbursement_rounds': 2,
                'is_active': True,
                'application_open': True,
                'application_deadline': datetime(2025, 2, 28).date(),
                'created_by': self.county_admin
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created Fiscal Year: {self.fiscal_year.name}'))

    def create_ward_allocations(self):
        """Create ward allocations"""
        self.stdout.write('Creating ward allocations...')
        
        wards = Ward.objects.filter(constituency__county=self.muranga)
        total_allocation = self.fiscal_year.total_bursary_allocation
        per_ward_allocation = total_allocation / wards.count()
        
        for ward in wards:
            allocation, created = WardAllocation.objects.get_or_create(
                fiscal_year=self.fiscal_year,
                ward=ward,
                defaults={
                    'allocated_amount': per_ward_allocation,
                    'spent_amount': Decimal('0.00'),
                    'beneficiaries_count': 0
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created allocation for: {ward.name}'))

    def create_bursary_categories(self):
        """Create bursary categories"""
        self.stdout.write('Creating bursary categories...')
        
        categories_data = [
            {
                'name': 'High School Bursary',
                'category_type': 'highschool',
                'allocation_amount': Decimal('80000000.00'),
                'max_amount_per_applicant': Decimal('30000.00'),
                'min_amount_per_applicant': Decimal('10000.00'),
                'target_beneficiaries': 3000
            },
            {
                'name': 'University Bursary',
                'category_type': 'university',
                'allocation_amount': Decimal('100000000.00'),
                'max_amount_per_applicant': Decimal('60000.00'),
                'min_amount_per_applicant': Decimal('20000.00'),
                'target_beneficiaries': 2000
            },
            {
                'name': 'College Bursary',
                'category_type': 'college',
                'allocation_amount': Decimal('40000000.00'),
                'max_amount_per_applicant': Decimal('40000.00'),
                'min_amount_per_applicant': Decimal('15000.00'),
                'target_beneficiaries': 1200
            },
            {
                'name': 'Technical/Vocational Bursary',
                'category_type': 'technical',
                'allocation_amount': Decimal('30000000.00'),
                'max_amount_per_applicant': Decimal('35000.00'),
                'min_amount_per_applicant': Decimal('12000.00'),
                'target_beneficiaries': 1000
            }
        ]
        
        for cat_data in categories_data:
            category, created = BursaryCategory.objects.get_or_create(
                name=cat_data['name'],
                fiscal_year=self.fiscal_year,
                defaults=cat_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Category: {category.name}'))
        
        self.highschool_category = BursaryCategory.objects.get(
            name='High School Bursary',
            fiscal_year=self.fiscal_year
        )
        self.university_category = BursaryCategory.objects.get(
            name='University Bursary',
            fiscal_year=self.fiscal_year
        )

    def create_disbursement_rounds(self):
        """Create disbursement rounds"""
        self.stdout.write('Creating disbursement rounds...')
        
        rounds_data = [
            {
                'round_number': 1,
                'name': 'First Semester 2024',
                'application_start_date': datetime(2024, 7, 1).date(),
                'application_end_date': datetime(2024, 10, 31).date(),
                'review_deadline': datetime(2024, 11, 30).date(),
                'disbursement_date': datetime(2024, 12, 15).date(),
                'allocated_amount': Decimal('125000000.00'),
                'disbursed_amount': Decimal('0.00'),
                'is_open': True,
                'is_completed': False
            },
            {
                'round_number': 2,
                'name': 'Second Semester 2025',
                'application_start_date': datetime(2025, 1, 1).date(),
                'application_end_date': datetime(2025, 4, 30).date(),
                'review_deadline': datetime(2025, 5, 31).date(),
                'disbursement_date': datetime(2025, 6, 15).date(),
                'allocated_amount': Decimal('125000000.00'),
                'disbursed_amount': Decimal('0.00'),
                'is_open': False,
                'is_completed': False
            }
        ]
        
        for round_data in rounds_data:
            round_obj, created = DisbursementRound.objects.get_or_create(
                fiscal_year=self.fiscal_year,
                round_number=round_data['round_number'],
                defaults=round_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Round: {round_obj.name}'))
        
        self.round_1 = DisbursementRound.objects.get(fiscal_year=self.fiscal_year, round_number=1)

    def create_applicants(self):
        """Create sample applicants"""
        self.stdout.write('Creating applicants...')
        
        applicants_data = [
            {
                'username': 'john.kamau',
                'email': 'john.kamau@email.com',
                'first_name': 'John',
                'last_name': 'Kamau',
                'phone_number': '+254722111000',
                'gender': 'M',
                'date_of_birth': datetime(2006, 5, 15).date(),
                'id_number': '34567890',
                'ward': self.muguru_ward,
                'physical_address': 'Gathanga, Gatura Village'
            },
            {
                'username': 'mary.wanjiku',
                'email': 'mary.wanjiku@email.com',
                'first_name': 'Mary',
                'last_name': 'Wanjiku',
                'phone_number': '+254722222000',
                'gender': 'F',
                'date_of_birth': datetime(2003, 8, 20).date(),
                'id_number': '35678901',
                'ward': self.wangu_ward,
                'physical_address': 'Wangu Town'
            },
            {
                'username': 'peter.njoroge',
                'email': 'peter.njoroge@email.com',
                'first_name': 'Peter',
                'last_name': 'Njoroge',
                'phone_number': '+254722333000',
                'gender': 'M',
                'date_of_birth': datetime(2004, 3, 10).date(),
                'id_number': '36789012',
                'ward': self.muguru_ward,
                'physical_address': 'Kiriaini Village'
            },
            {
                'username': 'grace.nyambura',
                'email': 'grace.nyambura@email.com',
                'first_name': 'Grace',
                'last_name': 'Nyambura',
                'phone_number': '+254722444000',
                'gender': 'F',
                'date_of_birth': datetime(2005, 11, 25).date(),
                'id_number': '37890123',
                'ward': self.wangu_ward,
                'physical_address': 'Mugoiri Area'
            },
            {
                'username': 'david.mwangi',
                'email': 'david.mwangi@email.com',
                'first_name': 'David',
                'last_name': 'Mwangi',
                'phone_number': '+254722555000',
                'gender': 'M',
                'date_of_birth': datetime(2006, 1, 8).date(),
                'id_number': '38901234',
                'ward': self.muguru_ward,
                'physical_address': 'Kamacharia Village'
            }
        ]
        
        self.applicants = []
        for app_data in applicants_data:
            # Create user
            user, created = User.objects.get_or_create(
                username=app_data['username'],
                defaults={
                    'email': app_data['email'],
                    'first_name': app_data['first_name'],
                    'last_name': app_data['last_name'],
                    'user_type': 'applicant',
                    'phone_number': app_data['phone_number']
                }
            )
            if created:
                user.set_password('applicant123')
                user.save()
            
            # Create applicant profile
            applicant, created = Applicant.objects.get_or_create(
                user=user,
                defaults={
                    'gender': app_data['gender'],
                    'date_of_birth': app_data['date_of_birth'],
                    'id_number': app_data['id_number'],
                    'county': self.muranga,
                    'constituency': app_data['ward'].constituency,
                    'ward': app_data['ward'],
                    'physical_address': app_data['physical_address'],
                    'is_verified': True,
                    'verified_by': self.county_admin,
                    'verification_date': timezone.now()
                }
            )
            
            if created:
                self.applicants.append(applicant)
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Applicant: {applicant}'))

    def create_guardians(self):
        """Create guardians for applicants"""
        self.stdout.write('Creating guardians...')
        
        for applicant in self.applicants:
            # Father
            Guardian.objects.get_or_create(
                applicant=applicant,
                name=f'{applicant.user.last_name} Senior',
                defaults={
                    'relationship': 'father',
                    'phone_number': f'+2547227777{random.randint(10, 99)}',
                    'employment_status': random.choice(['employed', 'self_employed', 'casual']),
                    'occupation': random.choice(['Farmer', 'Teacher', 'Driver', 'Businessman']),
                    'monthly_income': Decimal(random.randint(15000, 50000)),
                    'is_primary_contact': True
                }
            )
            
            # Mother
            Guardian.objects.get_or_create(
                applicant=applicant,
                name=f'{applicant.user.first_name}\'s Mother',
                defaults={
                    'relationship': 'mother',
                    'phone_number': f'+2547228888{random.randint(10, 99)}',
                    'employment_status': random.choice(['self_employed', 'casual', 'unemployed']),
                    'occupation': random.choice(['Small Business', 'Housewife', 'Casual Laborer']),
                    'monthly_income': Decimal(random.randint(5000, 25000)),
                    'is_primary_contact': False
                }
            )
            
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created guardians for: {applicant}'))
            
            # Create siblings
            for i in range(random.randint(2, 4)):
                SiblingInformation.objects.get_or_create(
                    applicant=applicant,
                    name=f'{applicant.user.last_name} Sibling {i+1}',
                    defaults={
                        'age': random.randint(8, 20),
                        'education_level': random.choice(['Primary', 'Form 1', 'Form 2', 'Form 3', 'Form 4']),
                        'school_name': f'{random.choice(["St. Mary\'s", "Kangema", "Murang\'a"])} School',
                        'is_in_school': random.choice([True, True, True, False])
                    }
                )

    def create_applications(self):
        """Create applications"""
        self.stdout.write('Creating applications...')
        
        institutions = [self.muranga_high, self.karatina_uni, self.mut]
        
        for i, applicant in enumerate(self.applicants):
            institution = institutions[i % len(institutions)]
            
            if institution.institution_type == 'highschool':
                category = self.highschool_category
                year_of_study = random.randint(1, 4)
                total_fees = Decimal(random.randint(40000, 80000))
                amount_requested = Decimal(random.randint(15000, 30000))
            else:
                category = self.university_category
                year_of_study = random.randint(1, 4)
                total_fees = Decimal(random.randint(120000, 250000))
                amount_requested = Decimal(random.randint(30000, 60000))
            
            fees_paid = total_fees * Decimal(random.uniform(0.1, 0.3))
            fees_balance = total_fees - fees_paid
            
            application, created = Application.objects.get_or_create(
                applicant=applicant,
                fiscal_year=self.fiscal_year,
                defaults={
                    'disbursement_round': self.round_1,
                    'bursary_category': category,
                    'institution': institution,
                    'bursary_source': 'county',
                    'status': random.choice(['submitted', 'under_review', 'approved']),
                    'admission_number': f'{institution.name[:3].upper()}/{random.randint(1000, 9999)}/2024',
                    'year_of_study': year_of_study,
                    'course_name': random.choice([
                        'Bachelor of Education',
                        'Bachelor of Science',
                        'Bachelor of Commerce',
                        'Diploma in Business',
                        'Certificate in IT'
                    ]) if institution.institution_type != 'highschool' else None,
                    'expected_completion_date': datetime(2025 + year_of_study, 12, 15).date(),
                    'previous_academic_year_average': Decimal(random.uniform(55, 85)),
                    'total_fees_payable': total_fees,
                    'fees_paid': fees_paid,
                    'fees_balance': fees_balance,
                    'amount_requested': amount_requested,
                    'other_bursaries': random.choice([True, False]),
                    'other_bursaries_amount': Decimal(random.randint(5000, 15000)) if random.choice([True, False]) else Decimal('0.00'),
                    'other_bursaries_source': 'NG-CDF' if random.choice([True, False]) else None,
                    'is_orphan': random.choice([True, False, False, False]),
                    'is_total_orphan': False,
                    'is_disabled': random.choice([True, False, False, False, False]),
                    'has_chronic_illness': False,
                    'number_of_siblings': random.randint(2, 5),
                    'number_of_siblings_in_school': random.randint(1, 3),
                    'household_monthly_income': Decimal(random.randint(15000, 50000)),
                    'date_submitted': timezone.now() - timedelta(days=random.randint(10, 60)),
                    'has_received_previous_allocation': random.choice([True, False, False]),
                    'previous_allocation_year': '2023-2024' if random.choice([True, False]) else None,
                    'previous_allocation_amount': Decimal(random.randint(10000, 30000)) if random.choice([True, False]) else Decimal('0.00'),
                    'priority_score': Decimal(random.uniform(60, 95))
                }
            )
            
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Application: {application.application_number}'))

    def create_reviews(self):
        """Create reviews for applications"""
        self.stdout.write('Creating reviews...')
        
        applications = Application.objects.filter(
            status__in=['under_review', 'approved']
        )[:3]  # Review first 3 applications
        
        for application in applications:
            # Ward level review
            Review.objects.get_or_create(
                application=application,
                review_level='ward',
                defaults={
                    'reviewer': self.ward_admin,
                    'comments': f'Verified applicant from {application.applicant.ward.name} Ward. Family situation confirmed with village elder.',
                    'recommendation': 'forward',
                    'recommended_amount': application.amount_requested * Decimal('0.8'),
                    'need_score': random.randint(7, 10),
                    'merit_score': random.randint(6, 9),
                    'vulnerability_score': random.randint(6, 9),
                    'review_date': timezone.now() - timedelta(days=random.randint(5, 20))
                }
            )
            
            # County level review (for approved applications)
            if application.status == 'approved':
                Review.objects.get_or_create(
                    application=application,
                    review_level='county',
                    defaults={
                        'reviewer': self.reviewer,
                        'comments': 'Application meets all criteria. Documents verified. Recommended for allocation.',
                        'recommendation': 'approve',
                        'recommended_amount': application.amount_requested * Decimal('0.7'),
                        'need_score': random.randint(7, 10),
                        'merit_score': random.randint(7, 9),
                        'vulnerability_score': random.randint(6, 9),
                        'review_date': timezone.now() - timedelta(days=random.randint(1, 10))
                    }
                )
            
            self.stdout.write(self.style.SUCCESS(f'  ✓ Created reviews for: {application.application_number}'))

    def create_allocations(self):
        """Create allocations for approved applications"""
        self.stdout.write('Creating allocations...')
        
        approved_applications = Application.objects.filter(status='approved')[:2]
        
        for application in approved_applications:
            allocation, created = Allocation.objects.get_or_create(
                application=application,
                defaults={
                    'amount_allocated': application.amount_requested * Decimal('0.7'),
                    'approved_by': self.county_admin,
                    'payment_method': 'cheque',
                    'cheque_number': f'CHQ/{random.randint(100000, 999999)}',
                    'is_disbursed': random.choice([True, False]),
                    'disbursement_date': timezone.now().date() if random.choice([True, False]) else None,
                    'disbursed_by': self.finance_officer if random.choice([True, False]) else None,
                    'is_received_by_institution': False,
                    'remarks': 'Allocation approved based on need assessment and available budget.'
                }
            )
            
            if created:
                # Update application status
                application.status = 'disbursed' if allocation.is_disbursed else 'approved'
                application.save()
                
                # Update ward allocation
                ward_allocation = WardAllocation.objects.get(
                    fiscal_year=self.fiscal_year,
                    ward=application.applicant.ward
                )
                ward_allocation.spent_amount += allocation.amount_allocated
                ward_allocation.beneficiaries_count += 1
                ward_allocation.save()
                
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Allocation: {allocation}'))

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
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created FAQ: {faq.question[:50]}...'))

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
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created Announcement: {announcement.title}'))

    def create_system_settings(self):
        """Create system settings"""
        self.stdout.write('Creating system settings...')
        
        settings_data = [
            {
                'setting_name': 'MAX_APPLICATION_FILE_SIZE',
                'setting_category': 'application',
                'setting_value': '5242880',  # 5MB in bytes
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
        
        self.stdout.write(self.style.SUCCESS('\n' + '='*70))
        self.stdout.write(self.style.SUCCESS('DATA SEEDING SUMMARY'))
        self.stdout.write(self.style.SUCCESS('='*70))
        self.stdout.write(f'Counties: {County.objects.count()}')
        self.stdout.write(f'Constituencies: {Constituency.objects.count()}')
        self.stdout.write(f'Wards: {Ward.objects.count()}')
        self.stdout.write(f'Locations: {Location.objects.count()}')
        self.stdout.write(f'Institutions: {Institution.objects.count()}')
        self.stdout.write(f'Users: {User.objects.count()}')
        self.stdout.write(f'Applicants: {Applicant.objects.count()}')
        self.stdout.write(f'Applications: {Application.objects.count()}')
        self.stdout.write(f'Reviews: {Review.objects.count()}')
        self.stdout.write(f'Allocations: {Allocation.objects.count()}')
        self.stdout.write(f'FAQs: {FAQ.objects.count()}')
        self.stdout.write(f'Announcements: {Announcement.objects.count()}')
        self.stdout.write(self.style.SUCCESS('='*70))
        self.stdout.write(self.style.SUCCESS('\nLOGIN CREDENTIALS:'))
        self.stdout.write(self.style.SUCCESS('='*70))
        self.stdout.write('County Admin:')
        self.stdout.write('  Username: county_admin')
        self.stdout.write('  Password: admin123')
        self.stdout.write('\nFinance Officer:')
        self.stdout.write('  Username: finance_officer')
        self.stdout.write('  Password: finance123')
        self.stdout.write('\nWard Admin:')
        self.stdout.write('  Username: ward_admin')
        self.stdout.write('  Password: ward123')
        self.stdout.write('\nReviewer:')
        self.stdout.write('  Username: reviewer')
        self.stdout.write('  Password: reviewer123')
        self.stdout.write('\nApplicants (sample):')
        self.stdout.write('  Username: john.kamau')
        self.stdout.write('  Password: applicant123')
        self.stdout.write(self.style.SUCCESS('='*70))