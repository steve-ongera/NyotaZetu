"""
Management command to seed the database with real Kenyan data from Murang'a County.
Focus on Kiharu and Mathioya constituencies with correct wards.
Includes ~100 schools, ~1000 applicants, and data spanning 2024-present.

Usage:
    python manage.py seed_data

Place this file at:
    main_application/management/commands/seed_data.py
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from django.db import transaction
from datetime import date, timedelta, datetime
import random
import string
import uuid
import decimal


class Command(BaseCommand):
    help = 'Seed database with real Murang\'a County data (Kiharu & Mathioya constituencies)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--skip-delete',
            action='store_true',
            help='Skip deleting existing data',
        )

    def handle(self, *args, **options):
        from main_application.models import (
            User, County, Constituency, Ward, Location, SubLocation, Village,
            Institution, FiscalYear, WardAllocation, BursaryCategory,
            DisbursementRound, Applicant, Guardian, SiblingInformation,
            Application, Document, Review, Allocation, Notification,
            AuditLog, SystemSettings, FAQ, Announcement
        )

        if not options['skip_delete']:
            self.stdout.write(self.style.WARNING('🗑️  Deleting all existing data...'))
            self._delete_all_data()
            self.stdout.write(self.style.SUCCESS('✅ Data deleted.'))

        self.stdout.write(self.style.MIGRATE_HEADING('🌱 Seeding Murang\'a County data...'))

        with transaction.atomic():
            county = self._seed_county()
            constituencies = self._seed_constituencies(county)
            wards = self._seed_wards(constituencies)
            locations = self._seed_locations(wards)
            sublocations = self._seed_sublocations(locations)
            villages = self._seed_villages(sublocations)
            institutions = self._seed_institutions(county)
            users_staff = self._seed_staff_users(county, constituencies, wards)
            fiscal_years = self._seed_fiscal_years(county, users_staff['admin'])
            ward_allocations = self._seed_ward_allocations(fiscal_years, wards)
            categories = self._seed_bursary_categories(fiscal_years, constituencies, wards)
            rounds = self._seed_disbursement_rounds(fiscal_years)
            applicants = self._seed_applicants(county, constituencies, wards, locations, sublocations, villages)
            applications = self._seed_applications(applicants, fiscal_years, categories, institutions, rounds, users_staff)
            self._seed_system_settings(users_staff['admin'])
            self._seed_faqs()
            self._seed_announcements(users_staff['admin'], fiscal_years)

        self.stdout.write(self.style.SUCCESS(
            f'\n✅ Seeding complete!\n'
            f'   County: Murang\'a\n'
            f'   Constituencies: {len(constituencies)}\n'
            f'   Wards: {len(wards)}\n'
            f'   Institutions: {len(institutions)}\n'
            f'   Staff users: {len(users_staff)}\n'
            f'   Applicants: {len(applicants)}\n'
            f'   Applications: {len(applications)}\n'
        ))

    # =========================================================
    # DELETE ALL DATA
    # =========================================================
    def _delete_all_data(self):
        from main_application.models import (
            User, County, Constituency, Ward, Location, SubLocation, Village,
            Institution, FiscalYear, WardAllocation, BursaryCategory,
            DisbursementRound, Applicant, Guardian, SiblingInformation,
            Application, Document, Review, Allocation, Notification,
            AuditLog, SystemSettings, FAQ, Announcement, BulkCheque,
            BulkChequeAllocation, ChequeDeliveryTracking, InstitutionPaymentReceipt,
            StudentDisbursementConfirmation, DeliveryAgent, ChequeCollectionRegister,
            Testimonial, Disbursement, URLVisit, UserURLVisit, SecurityThreat,
            UserSession, SuspiciousActivity, AccountLock, TwoFactorCode,
            SecurityNotification, LoginAttempt, AIAnalysisReport, PredictionModel,
            DataSnapshot, PublicReport, BeneficiaryTestimonial, SMSLog, EmailLog
        )
        models_to_delete = [
            StudentDisbursementConfirmation, BulkChequeAllocation, ChequeCollectionRegister,
            ChequeDeliveryTracking, InstitutionPaymentReceipt, BulkCheque,
            Disbursement, Testimonial, BeneficiaryTestimonial, Review, Document,
            Allocation, Application, SiblingInformation, Guardian, Applicant,
            Notification, AuditLog, EmailLog, SMSLog, AccountLock, TwoFactorCode,
            SecurityNotification, LoginAttempt, SecurityThreat, SuspiciousActivity,
            UserSession, UserURLVisit, URLVisit, AIAnalysisReport, DataSnapshot,
            PublicReport, PredictionModel, WardAllocation, BursaryCategory,
            DisbursementRound, FiscalYear, Institution, Village, SubLocation,
            Location, Ward, Constituency, County, SystemSettings, FAQ,
            Announcement, User,
        ]
        for model in models_to_delete:
            try:
                count = model.objects.all().count()
                model.objects.all().delete()
                self.stdout.write(f'   Deleted {count} {model.__name__} records')
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'   Could not delete {model.__name__}: {e}'))

    # =========================================================
    # COUNTY
    # =========================================================
    def _seed_county(self):
        from main_application.models import County
        self.stdout.write('  Creating Murang\'a County...')
        county = County.objects.create(
            name="Murang'a",
            code="022",
            headquarters="Murang'a Town",
            population=1056640,
            governor_name="Irungu Kang'ata",
            county_website="https://muranga.go.ke",
            treasury_email="treasury@muranga.go.ke",
            treasury_phone="+254710000100",
            education_cec_name="Dr. Jane Wanjiku Mwangi",
            education_office_email="education@muranga.go.ke",
            education_office_phone="+254710000200",
            system_county="Murang'a",
            is_active=True,
        )
        self.stdout.write(f'    ✓ Created county: {county.name}')
        return county

    # =========================================================
    # CONSTITUENCIES
    # =========================================================
    def _seed_constituencies(self, county):
        from main_application.models import Constituency
        self.stdout.write('  Creating constituencies...')

        constituencies_data = [
            # Kiharu Constituency
            {
                'name': 'Kiharu',
                'code': 'KIH',
                'current_mp': 'Wangui Ngirichi',
                'mp_party': 'UDA',
                'cdf_office_location': 'Murang\'a Town, Kiharu CDF Office',
                'cdf_office_email': 'kiharu.cdf@ngcdf.go.ke',
                'cdf_office_phone': '+254724000001',
                'annual_cdf_allocation': decimal.Decimal('85000000.00'),
                'cdf_bursary_allocation': decimal.Decimal('29750000.00'),
                'population': 191338,
            },
            # Mathioya Constituency
            {
                'name': 'Mathioya',
                'code': 'MTH',
                'current_mp': 'Peter Kihungi Kimari',
                'mp_party': 'UDA',
                'cdf_office_location': 'Mathioya CDF Office, Kangari Town',
                'cdf_office_email': 'mathioya.cdf@ngcdf.go.ke',
                'cdf_office_phone': '+254724000002',
                'annual_cdf_allocation': decimal.Decimal('78000000.00'),
                'cdf_bursary_allocation': decimal.Decimal('27300000.00'),
                'population': 182237,
            },
            # Kangema Constituency
            {
                'name': 'Kangema',
                'code': 'KGM',
                'current_mp': 'Joseph Munyoro',
                'mp_party': 'UDA',
                'cdf_office_location': 'Kangema CDF Office, Kangema Town',
                'cdf_office_email': 'kangema.cdf@ngcdf.go.ke',
                'cdf_office_phone': '+254724000003',
                'annual_cdf_allocation': decimal.Decimal('72000000.00'),
                'cdf_bursary_allocation': decimal.Decimal('25200000.00'),
                'population': 131498,
            },
            # Gatanga Constituency
            {
                'name': 'Gatanga',
                'code': 'GTG',
                'current_mp': 'Edward Muriu Kamau',
                'mp_party': 'Jubilee',
                'cdf_office_location': 'Gatanga CDF Office, Thika Road',
                'cdf_office_email': 'gatanga.cdf@ngcdf.go.ke',
                'cdf_office_phone': '+254724000004',
                'annual_cdf_allocation': decimal.Decimal('80000000.00'),
                'cdf_bursary_allocation': decimal.Decimal('28000000.00'),
                'population': 168890,
            },
            # Maragwa Constituency
            {
                'name': 'Maragwa',
                'code': 'MRG',
                'current_mp': 'Mary Waithiegeni Njoroge',
                'mp_party': 'UDA',
                'cdf_office_location': 'Maragwa CDF Office',
                'cdf_office_email': 'maragwa.cdf@ngcdf.go.ke',
                'cdf_office_phone': '+254724000005',
                'annual_cdf_allocation': decimal.Decimal('76000000.00'),
                'cdf_bursary_allocation': decimal.Decimal('26600000.00'),
                'population': 163452,
            },
            # Kahuro Constituency
            {
                'name': 'Kahuro',
                'code': 'KHR',
                'current_mp': 'Wanjiru Kamau',
                'mp_party': 'UDA',
                'cdf_office_location': 'Kahuro CDF Office, Kahuro Town',
                'cdf_office_email': 'kahuro.cdf@ngcdf.go.ke',
                'cdf_office_phone': '+254724000006',
                'annual_cdf_allocation': decimal.Decimal('74000000.00'),
                'cdf_bursary_allocation': decimal.Decimal('25900000.00'),
                'population': 157223,
            },
        ]

        created = []
        for data in constituencies_data:
            c = Constituency.objects.create(county=county, **data)
            created.append(c)
            self.stdout.write(f'    ✓ {c.name} Constituency')

        return created

    # =========================================================
    # WARDS
    # =========================================================
    def _seed_wards(self, constituencies):
        from main_application.models import Ward
        self.stdout.write('  Creating wards...')

        # Key: constituency name -> list of ward data
        wards_data = {
            'Kiharu': [
                # 9 wards in Kiharu
                {'name': 'Wangu', 'code': 'KIH-01', 'current_mca': 'Samuel Kamau Njoroge', 'mca_party': 'UDA', 'mca_phone': '+254722100001', 'population': 21480},
                {'name': 'Mugoiri', 'code': 'KIH-02', 'current_mca': 'Peter Ndichu Kamau', 'mca_party': 'UDA', 'mca_phone': '+254722100002', 'population': 22340},
                {'name': 'Mbiri', 'code': 'KIH-03', 'current_mca': 'Agnes Wanjiku Mwangi', 'mca_party': 'Jubilee', 'mca_phone': '+254722100003', 'population': 19870},
                {'name': "Murang'a", 'code': 'KIH-04', 'current_mca': 'James Kamande Githinji', 'mca_party': 'UDA', 'mca_phone': '+254722100004', 'population': 25600},
                {'name': 'Gaturi', 'code': 'KIH-05', 'current_mca': 'Grace Nyambura Waweru', 'mca_party': 'UDA', 'mca_phone': '+254722100005', 'population': 20120},
                {'name': 'Kigumo', 'code': 'KIH-06', 'current_mca': 'John Mwangi Njoroge', 'mca_party': 'UDA', 'mca_phone': '+254722100006', 'population': 22800},
                {'name': 'Kamahuha', 'code': 'KIH-07', 'current_mca': 'Mary Wangui Kamau', 'mca_party': 'Jubilee', 'mca_phone': '+254722100007', 'population': 21300},
                {'name': 'Ichagaki', 'code': 'KIH-08', 'current_mca': 'Daniel Maina Gichuhi', 'mca_party': 'UDA', 'mca_phone': '+254722100008', 'population': 19650},
                {'name': 'Nginda', 'code': 'KIH-09', 'current_mca': 'Susan Wairimu Gitau', 'mca_party': 'UDA', 'mca_phone': '+254722100009', 'population': 18178},
            ],
            'Mathioya': [
                # 6 wards in Mathioya
                {'name': 'Gitugi', 'code': 'MTH-01', 'current_mca': 'David Mwangi Kamau', 'mca_party': 'UDA', 'mca_phone': '+254722200001', 'population': 30980},
                {'name': 'Kamacharia', 'code': 'MTH-02', 'current_mca': 'Josephine Njeri Mwangi', 'mca_party': 'UDA', 'mca_phone': '+254722200002', 'population': 28450},
                {'name': 'Kiriani', 'code': 'MTH-03', 'current_mca': 'Charles Githinji Waweru', 'mca_party': 'Jubilee', 'mca_phone': '+254722200003', 'population': 32100},
                {'name': 'Ithiru', 'code': 'MTH-04', 'current_mca': 'Catherine Wanjiru Njoroge', 'mca_party': 'UDA', 'mca_phone': '+254722200004', 'population': 29870},
                {'name': 'Ruchu', 'code': 'MTH-05', 'current_mca': 'Patrick Kariuki Kamau', 'mca_party': 'UDA', 'mca_phone': '+254722200005', 'population': 31500},
                {'name': 'Kiru', 'code': 'MTH-06', 'current_mca': 'Ann Wambui Gichuhi', 'mca_party': 'UDA', 'mca_phone': '+254722200006', 'population': 29337},
            ],
            'Kangema': [
                {'name': 'Rwathia', 'code': 'KGM-01', 'current_mca': 'Eric Mwangi Njoroge', 'mca_party': 'UDA', 'mca_phone': '+254722300001', 'population': 26450},
                {'name': 'Kangema', 'code': 'KGM-02', 'current_mca': 'Ruth Njoki Waweru', 'mca_party': 'UDA', 'mca_phone': '+254722300002', 'population': 28900},
                {'name': 'Ng\'araria', 'code': 'KGM-03', 'current_mca': 'Stephen Kamau Githinji', 'mca_party': 'Jubilee', 'mca_phone': '+254722300003', 'population': 25670},
                {'name': 'Kariara', 'code': 'KGM-04', 'current_mca': 'Lucy Wangui Kariuki', 'mca_party': 'UDA', 'mca_phone': '+254722300004', 'population': 24780},
                {'name': 'Muguru', 'code': 'KGM-05', 'current_mca': 'Michael Ndichu Waweru', 'mca_party': 'UDA', 'mca_phone': '+254722300005', 'population': 25698},
            ],
            'Gatanga': [
                {'name': 'Gatanga', 'code': 'GTG-01', 'current_mca': 'Thomas Kamande Mwangi', 'mca_party': 'Jubilee', 'mca_phone': '+254722400001', 'population': 28900},
                {'name': 'Mugumo-ini', 'code': 'GTG-02', 'current_mca': 'Alice Wanjiru Kariuki', 'mca_party': 'UDA', 'mca_phone': '+254722400002', 'population': 27450},
                {'name': 'Njiiri', 'code': 'GTG-03', 'current_mca': 'Robert Gichuhi Njoroge', 'mca_party': 'UDA', 'mca_phone': '+254722400003', 'population': 26700},
                {'name': 'Kirwara', 'code': 'GTG-04', 'current_mca': 'Eunice Wambui Kamau', 'mca_party': 'UDA', 'mca_phone': '+254722400004', 'population': 29540},
                {'name': 'Kakuzi/Mitubiri', 'code': 'GTG-05', 'current_mca': 'Francis Mwangi Njoroge', 'mca_party': 'Jubilee', 'mca_phone': '+254722400005', 'population': 30100},
                {'name': 'Ithanga', 'code': 'GTG-06', 'current_mca': 'Priscilla Nyambura Gitau', 'mca_party': 'UDA', 'mca_phone': '+254722400006', 'population': 26200},
            ],
            'Maragwa': [
                {'name': 'Maragwa', 'code': 'MRG-01', 'current_mca': 'George Kamau Mwangi', 'mca_party': 'UDA', 'mca_phone': '+254722500001', 'population': 31200},
                {'name': 'Kambiti', 'code': 'MRG-02', 'current_mca': 'Hannah Wanjiku Githinji', 'mca_party': 'UDA', 'mca_phone': '+254722500002', 'population': 28900},
                {'name': 'Kamahuha', 'code': 'MRG-03', 'current_mca': 'Lawrence Kariuki Njoroge', 'mca_party': 'Jubilee', 'mca_phone': '+254722500003', 'population': 27850},
                {'name': 'Makuyu', 'code': 'MRG-04', 'current_mca': 'Janet Nyambura Kamau', 'mca_party': 'UDA', 'mca_phone': '+254722500004', 'population': 34500},
                {'name': 'Ichagaki', 'code': 'MRG-05', 'current_mca': 'Paul Mwangi Gichuhi', 'mca_party': 'UDA', 'mca_phone': '+254722500005', 'population': 29790},
                {'name': 'Kigumo East', 'code': 'MRG-06', 'current_mca': 'Lydia Wangui Waweru', 'mca_party': 'UDA', 'mca_phone': '+254722500006', 'population': 11212},
            ],
            'Kahuro': [
                {'name': 'Kahuro', 'code': 'KHR-01', 'current_mca': 'Simon Ndichu Kamau', 'mca_party': 'UDA', 'mca_phone': '+254722600001', 'population': 28900},
                {'name': 'Gaichanjiru', 'code': 'KHR-02', 'current_mca': 'Tabitha Wanjiku Njoroge', 'mca_party': 'UDA', 'mca_phone': '+254722600002', 'population': 27350},
                {'name': 'Kinyona', 'code': 'KHR-03', 'current_mca': 'Henry Mwangi Kariuki', 'mca_party': 'Jubilee', 'mca_phone': '+254722600003', 'population': 26780},
                {'name': 'Ithare', 'code': 'KHR-04', 'current_mca': 'Leah Nyambura Waweru', 'mca_party': 'UDA', 'mca_phone': '+254722600004', 'population': 29400},
                {'name': 'Muguru', 'code': 'KHR-05', 'current_mca': 'Vincent Kamande Githinji', 'mca_party': 'UDA', 'mca_phone': '+254722600005', 'population': 24793},
            ],
        }

        created = []
        const_map = {c.name: c for c in constituencies}

        for const_name, ward_list in wards_data.items():
            constituency = const_map.get(const_name)
            if not constituency:
                continue
            for wd in ward_list:
                w = Ward.objects.create(
                    constituency=constituency,
                    ward_office_location=f'{wd["name"]} Ward Office, {const_name}',
                    is_active=True,
                    **wd
                )
                created.append(w)
                self.stdout.write(f'    ✓ {w.name} Ward ({const_name})')

        return created

    # =========================================================
    # LOCATIONS
    # =========================================================
    def _seed_locations(self, wards):
        from main_application.models import Location
        self.stdout.write('  Creating locations...')

        # Representative locations per ward (abbreviated for brevity, ~3 per ward)
        location_map = {
            'Wangu': ['Wangu', 'Ngurubani', 'Kiawara'],
            'Mugoiri': ['Mugoiri', 'Kambirwa', 'Kiawara South'],
            'Mbiri': ['Mbiri', 'Nginda', 'Gitiri'],
            "Murang'a": ["Murang'a Town", 'Makongeni', 'Kiharu'],
            'Gaturi': ['Gaturi', 'Ruiru', 'Kihumba'],
            'Kigumo': ['Kigumo', 'Kambirwa North', 'Kirichu'],
            'Kamahuha': ['Kamahuha', 'Kahuhia', 'Kimorori'],
            'Ichagaki': ['Ichagaki', 'Muthithi', 'Kiganjo'],
            'Nginda': ['Nginda', 'Kambirwa East', 'Kariga'],
            'Gitugi': ['Gitugi', 'Kamuthe', 'Kanyagia'],
            'Kamacharia': ['Kamacharia', 'Kimorori South', 'Gikindu'],
            'Kiriani': ['Kiriani', 'Muguru', 'Gakoigo'],
            'Ithiru': ['Ithiru', 'Kiaruhiu', 'Mucagara'],
            'Ruchu': ['Ruchu', 'Kagoni', 'Kambirwa West'],
            'Kiru': ['Kiru', 'Kirie', 'Muthu'],
            'Rwathia': ['Rwathia', 'Kangari', 'Githimu'],
            'Kangema': ['Kangema Town', 'Kariara', 'Kagumo'],
            "Ng'araria": ["Ng'araria", 'Kiaritha', 'Kagaari'],
            'Kariara': ['Kariara', 'Kimbimbi', 'Muthangene'],
            'Muguru': ['Muguru', 'Kairi', 'Iganjo'],
            'Gatanga': ['Gatanga', 'Kiganjo East', 'Kaaing'],
            'Mugumo-ini': ['Mugumo-ini', 'Kibiko', 'Thika Border'],
            'Njiiri': ['Njiiri', 'Kiangome', 'Ruiru East'],
            'Kirwara': ['Kirwara', 'Githumu', 'Kiambaa'],
            'Kakuzi/Mitubiri': ['Kakuzi', 'Mitubiri', 'Kiboko'],
            'Ithanga': ['Ithanga', 'Gatanga South', 'Karembu'],
            'Maragwa': ['Maragwa', 'Kangari South', 'Kirimukuyu'],
            'Kambiti': ['Kambiti', 'Kiharu North', 'Giathenge'],
            'Kamahuha': ['Kamahuha East', 'Kibichiku', 'Gikandu'],
            'Makuyu': ['Makuyu', 'Kanduti', 'Gacharage'],
            'Ichagaki': ['Ichagaki East', 'Kiangari', 'Gatei'],
            'Kigumo East': ['Kigumo East', 'Kiria-ini', 'Gatuura'],
            'Kahuro': ['Kahuro Town', 'Gikandu South', 'Kiria'],
            'Gaichanjiru': ['Gaichanjiru', 'Muruka', 'Kianjogu'],
            'Kinyona': ['Kinyona', 'Githioro', 'Kambirwa South'],
            'Ithare': ['Ithare', 'Kagunuini', 'Mbiriri'],
            'Muguru': ['Muguru West', 'Gikanga', 'Kiangari East'],
        }

        created = []
        for ward in wards:
            locs = location_map.get(ward.name, [f'{ward.name} Location'])
            for loc_name in locs:
                try:
                    loc = Location.objects.create(name=loc_name, ward=ward, population=random.randint(3000, 8000))
                    created.append(loc)
                except Exception:
                    pass

        self.stdout.write(f'    ✓ Created {len(created)} locations')
        return created

    # =========================================================
    # SUB-LOCATIONS
    # =========================================================
    def _seed_sublocations(self, locations):
        from main_application.models import SubLocation
        self.stdout.write('  Creating sub-locations...')
        created = []
        for loc in locations:
            for i in range(1, random.randint(2, 4)):
                try:
                    sl = SubLocation.objects.create(
                        name=f'{loc.name} Sub-Location {i}',
                        location=loc
                    )
                    created.append(sl)
                except Exception:
                    pass
        self.stdout.write(f'    ✓ Created {len(created)} sub-locations')
        return created

    # =========================================================
    # VILLAGES
    # =========================================================
    def _seed_villages(self, sublocations):
        from main_application.models import Village
        self.stdout.write('  Creating villages...')

        village_names = [
            'Kamuri', 'Kiambu', 'Gathanga', 'Kahuho', 'Rurigi', 'Thaita',
            'Gituto', 'Kagumo', 'Karuri', 'Kiawara', 'Kihara', 'Kimondo',
            'Githambo', 'Rwathia', 'Karurumo', 'Gatundu', 'Kigumo',
            'Gathagira', 'Karimba', 'Kiambogo', 'Gachagi', 'Gikabu',
            'Ngaita', 'Karatina', 'Muringari', 'Githunguri', 'Kigutha',
            'Gachoka', 'Mutero', 'Waceke', 'Mbugi', 'Kagira', 'Kanyoro',
            'Gitari', 'Kiamuruga', 'Gacharage', 'Kiamugumo', 'Rugendo',
        ]

        created = []
        elder_names = [
            'Mwangi Kamau', 'Njoroge Kariuki', 'Waweru Githinji', 'Kamau Ndichu',
            'Njoroge Gichuhi', 'Kariuki Mwangi', 'Gitau Kamau', 'Wanjiku Mwangi'
        ]
        for sl in sublocations[:60]:  # Limit to manage scale
            num_villages = random.randint(2, 4)
            for i in range(num_villages):
                vname = random.choice(village_names) + f' {i+1}'
                try:
                    v = Village.objects.create(
                        name=vname,
                        sublocation=sl,
                        village_elder=random.choice(elder_names),
                        elder_phone=f'+2547{random.randint(10000000, 99999999)}'
                    )
                    created.append(v)
                except Exception:
                    pass
        self.stdout.write(f'    ✓ Created {len(created)} villages')
        return created

    # =========================================================
    # INSTITUTIONS (TARGET ~100 SCHOOLS)
    # =========================================================
    def _seed_institutions(self, county):
        from main_application.models import Institution
        self.stdout.write('  Creating institutions (~100 schools)...')

        banks = ['Kenya Commercial Bank', 'Equity Bank', 'Co-operative Bank', 'Barclays Bank Kenya', 'Family Bank']
        branches = ["Murang'a Branch", 'Kangema Branch', 'Kiharu Branch', 'Mathioya Branch', 'Maragwa Branch']

        institutions_data = [
            # HIGH SCHOOLS (National, Extra County, County, District)
            # Kiharu Constituency Schools
            ('Murang\'a High School', 'highschool', 'Murang\'a Town', 'Mr. James Kariuki Njoroge', '+254720300001', 'muranga.high@schools.go.ke'),
            ('Kiharu High School', 'highschool', 'Kiharu', 'Mrs. Grace Wanjiku Kamau', '+254720300002', 'kiharu.high@schools.go.ke'),
            ('Wangu Mixed Secondary School', 'highschool', 'Wangu', 'Mr. Peter Mwangi Githinji', '+254720300003', 'wangu.sec@schools.go.ke'),
            ('Mugoiri Girls High School', 'highschool', 'Mugoiri', 'Mrs. Alice Nyambura Waweru', '+254720300004', 'mugoiri.girls@schools.go.ke'),
            ('Mbiri Girls Secondary School', 'highschool', 'Mbiri', 'Ms. Esther Wangui Kariuki', '+254720300005', 'mbiri.girls@schools.go.ke'),
            ('Gaturi Secondary School', 'highschool', 'Gaturi', 'Mr. Joseph Kamande Mwangi', '+254720300006', 'gaturi.sec@schools.go.ke'),
            ('Kigumo Secondary School', 'highschool', 'Kigumo', 'Mrs. Mary Njoki Njoroge', '+254720300007', 'kigumo.sec@schools.go.ke'),
            ('Kamahuha Boys Secondary School', 'highschool', 'Kamahuha', 'Mr. David Gichuhi Kamau', '+254720300008', 'kamahuha.boys@schools.go.ke'),
            ('Ichagaki Secondary School', 'highschool', 'Ichagaki', 'Mrs. Susan Wambui Gitau', '+254720300009', 'ichagaki.sec@schools.go.ke'),
            ('Nginda Secondary School', 'highschool', 'Nginda', 'Mr. Charles Maina Waweru', '+254720300010', 'nginda.sec@schools.go.ke'),
            ('St. Joseph\'s Kamahuha Girls', 'highschool', 'Kamahuha', 'Sr. Mary Francis', '+254720300011', 'st.josephs.khs@schools.go.ke'),
            ('Alliance Girls High School Muranga', 'highschool', "Murang'a", 'Mrs. Teresia Wanjiku Mwangi', '+254720300012', 'aghs.muranga@schools.go.ke'),
            ("Murang'a School", 'highschool', "Murang'a", 'Mr. Patrick Kamau Njoroge', '+254720300013', 'muranga.sch@schools.go.ke'),

            # Mathioya Constituency Schools
            ('Gitugi Secondary School', 'highschool', 'Gitugi', 'Mr. Daniel Kariuki Kamau', '+254720300014', 'gitugi.sec@schools.go.ke'),
            ('Kiriani Secondary School', 'highschool', 'Kiriani', 'Mrs. Rose Nyambura Githinji', '+254720300015', 'kiriani.sec@schools.go.ke'),
            ('Kamacharia Mixed Secondary', 'highschool', 'Kamacharia', 'Mr. Bernard Mwangi Njoroge', '+254720300016', 'kamacharia.sec@schools.go.ke'),
            ('Ithiru Secondary School', 'highschool', 'Ithiru', 'Mrs. Anne Wanjiku Kariuki', '+254720300017', 'ithiru.sec@schools.go.ke'),
            ('Ruchu Secondary School', 'highschool', 'Ruchu', 'Mr. Geoffrey Kamande Waweru', '+254720300018', 'ruchu.sec@schools.go.ke'),
            ('Kiru Mixed Secondary School', 'highschool', 'Kiru', 'Mrs. Dorothy Wangui Gitau', '+254720300019', 'kiru.sec@schools.go.ke'),
            ('Mathioya Mixed Secondary School', 'highschool', 'Gitugi', 'Mr. Francis Gichuhi Mwangi', '+254720300020', 'mathioya.sec@schools.go.ke'),
            ('Mugoiri Mixed Day Secondary', 'highschool', 'Ithiru', 'Ms. Patricia Njoki Kamau', '+254720300021', 'mugoiri.day@schools.go.ke'),
            ('Kambirwa Secondary School', 'highschool', 'Kiriani', 'Mr. Timothy Kariuki Githinji', '+254720300022', 'kambirwa.sec@schools.go.ke'),

            # Kangema Constituency Schools
            ('Kangema High School', 'highschool', 'Kangema', 'Mr. Simon Njoroge Kamau', '+254720300023', 'kangema.high@schools.go.ke'),
            ('Rwathia Secondary School', 'highschool', 'Rwathia', 'Mrs. Victoria Wambui Waweru', '+254720300024', 'rwathia.sec@schools.go.ke'),
            ("Ng'araria Secondary School", 'highschool', "Ng'araria", 'Mr. Andrew Maina Njoroge', '+254720300025', 'ngararia.sec@schools.go.ke'),
            ('Kariara Secondary School', 'highschool', 'Kariara', 'Mrs. Cecilia Nyambura Kariuki', '+254720300026', 'kariara.sec@schools.go.ke'),
            ('Muguru Secondary School', 'highschool', 'Muguru', 'Mr. Kevin Kamau Githinji', '+254720300027', 'muguru.sec@schools.go.ke'),
            ('Kirathimo Secondary School', 'highschool', 'Kangema', 'Mrs. Beatrice Wanjiku Mwangi', '+254720300028', 'kirathimo.sec@schools.go.ke'),

            # Gatanga Constituency Schools
            ('Gatanga Secondary School', 'highschool', 'Gatanga', 'Mr. Richard Kariuki Kamau', '+254720300029', 'gatanga.sec@schools.go.ke'),
            ('Mugumo-ini Secondary School', 'highschool', 'Mugumo-ini', 'Mrs. Phyllis Wangui Gitau', '+254720300030', 'mugumo.sec@schools.go.ke'),
            ('Njiiri Secondary School', 'highschool', 'Njiiri', 'Mr. Albert Mwangi Njoroge', '+254720300031', 'njiiri.sec@schools.go.ke'),
            ('Kirwara Secondary School', 'highschool', 'Kirwara', 'Mrs. Caroline Nyambura Waweru', '+254720300032', 'kirwara.sec@schools.go.ke'),
            ('Kakuzi Secondary School', 'highschool', 'Kakuzi', 'Mr. Martin Gichuhi Kariuki', '+254720300033', 'kakuzi.sec@schools.go.ke'),
            ('Mitubiri Secondary School', 'highschool', 'Mitubiri', 'Mrs. Emma Wanjiku Kamau', '+254720300034', 'mitubiri.sec@schools.go.ke'),
            ('Ithanga Secondary School', 'highschool', 'Ithanga', 'Mr. Cornelius Kamande Mwangi', '+254720300035', 'ithanga.sec@schools.go.ke'),

            # Maragwa Constituency Schools
            ('Maragwa Secondary School', 'highschool', 'Maragwa', 'Mr. Moses Njoroge Githinji', '+254720300036', 'maragwa.sec@schools.go.ke'),
            ('Kambiti Secondary School', 'highschool', 'Kambiti', 'Mrs. Tabitha Wambui Kariuki', '+254720300037', 'kambiti.sec@schools.go.ke'),
            ('Makuyu Secondary School', 'highschool', 'Makuyu', 'Mr. Elijah Kamau Njoroge', '+254720300038', 'makuyu.sec@schools.go.ke'),
            ('Maragwa Girls Secondary', 'highschool', 'Maragwa', 'Mrs. Faith Wanjiku Waweru', '+254720300039', 'maragwa.girls@schools.go.ke'),
            ('Kamahuha Secondary Maragwa', 'highschool', 'Kamahuha', 'Mr. Solomon Mwangi Kamau', '+254720300040', 'kamahuha.maragwa@schools.go.ke'),

            # Kahuro Constituency Schools
            ('Kahuro Secondary School', 'highschool', 'Kahuro', 'Mr. Hudson Kariuki Gitau', '+254720300041', 'kahuro.sec@schools.go.ke'),
            ('Gaichanjiru Secondary School', 'highschool', 'Gaichanjiru', 'Mrs. Lydia Nyambura Njoroge', '+254720300042', 'gaichanjiru.sec@schools.go.ke'),
            ('Kinyona Secondary School', 'highschool', 'Kinyona', 'Mr. Hezekiah Kamande Kamau', '+254720300043', 'kinyona.sec@schools.go.ke'),
            ('Ithare Secondary School', 'highschool', 'Ithare', 'Mrs. Gladys Wangui Githinji', '+254720300044', 'ithare.sec@schools.go.ke'),
            ('Muruka Secondary School', 'highschool', 'Gaichanjiru', 'Mr. Laban Mwangi Waweru', '+254720300045', 'muruka.sec@schools.go.ke'),
            ('Kianjogu Secondary School', 'highschool', 'Gaichanjiru', 'Mrs. Naomi Wanjiku Kariuki', '+254720300046', 'kianjogu.sec@schools.go.ke'),

            # Special Schools
            ("Murang'a Special School", 'special_school', "Murang'a Town", 'Mrs. Patricia Wambui Mwangi', '+254720300047', 'muranga.special@schools.go.ke'),
            ('Kiharu School for the Deaf', 'special_school', 'Kiharu', 'Mr. Philip Njoroge Kariuki', '+254720300048', 'kiharu.deaf@schools.go.ke'),

            # UNIVERSITIES
            ("Murang'a University of Technology", 'university', "Murang'a Town", 'Prof. John Kamau Mwangi (VC)', '+254720400001', 'info@mut.ac.ke'),
            ('University of Nairobi', 'university', 'Nairobi', 'Prof. Stephen Kiama (VC)', '+254720400002', 'registrar@uonbi.ac.ke'),
            ('Kenyatta University', 'university', 'Nairobi', 'Prof. Paul Wainaina (VC)', '+254720400003', 'registrar@ku.ac.ke'),
            ('Jomo Kenyatta University (JKUAT)', 'university', 'Juja', 'Prof. Victoria Wambua (VC)', '+254720400004', 'registrar@jkuat.ac.ke'),
            ('Dedan Kimathi University', 'university', 'Nyeri', 'Prof. Isaac Kamau Mwangi (VC)', '+254720400005', 'registrar@dkut.ac.ke'),
            ('Karatina University', 'university', 'Karatina', 'Prof. Mary Wanjiku Kariuki (VC)', '+254720400006', 'registrar@karu.ac.ke'),
            ('Mount Kenya University', 'university', 'Thika', 'Dr. Simon Gicharu (Founder/VC)', '+254720400007', 'registrar@mku.ac.ke'),
            ('Gretsa University', 'university', 'Thika', 'Prof. Charles Kamau (VC)', '+254720400008', 'registrar@gretsa.ac.ke'),

            # COLLEGES / TVETs
            ("Murang'a Technical Training Institute", 'technical_institute', "Murang'a", 'Mr. Isaac Njoroge Githinji', '+254720500001', 'info@muranga.tti.go.ke'),
            ('Kangema Technical Training Institute', 'technical_institute', 'Kangema', 'Mr. Samuel Gichuhi Kamau', '+254720500002', 'kangema.tti@go.ke'),
            ('Mathioya Technical Training Institute', 'technical_institute', 'Gitugi', 'Mrs. Helen Wanjiku Waweru', '+254720500003', 'mathioya.tti@go.ke'),
            ('Maragwa Technical Institute', 'technical_institute', 'Maragwa', 'Mr. Ezra Kamande Njoroge', '+254720500004', 'maragwa.ti@go.ke'),
            ('Kahuro VTC', 'technical_institute', 'Kahuro', 'Mrs. Joyce Nyambura Kariuki', '+254720500005', 'kahuro.vtc@go.ke'),
            ('Gatanga VTC', 'technical_institute', 'Gatanga', 'Mr. Leonard Mwangi Kamau', '+254720500006', 'gatanga.vtc@go.ke'),
            ("Kenya Medical Training College - Murang'a", 'college', "Murang'a", 'Mr. Benjamin Kariuki Githinji', '+254720500007', 'kmtc.muranga@health.go.ke'),
            ('Kenya National Polytechnic - Thika', 'technical_institute', 'Thika', 'Dr. Ruth Wambui Njoroge', '+254720500008', 'knp.thika@tvet.go.ke'),
            ("Murang'a Teachers Training College", 'college', "Murang'a", 'Mr. Frederick Njoki Kamau', '+254720500009', 'ttc.muranga@tsc.go.ke'),
            ('Nginda Vocational Training Centre', 'technical_institute', 'Nginda', 'Mrs. Dorcas Wanjiku Waweru', '+254720500010', 'nginda.vtc@go.ke'),

            # Additional high schools to reach ~100
            ('Kabiru High School', 'highschool', 'Kahuro', 'Mr. Josphat Kamau Mwangi', '+254720300049', 'kabiru.high@schools.go.ke'),
            ('Gikandu Secondary School', 'highschool', 'Kahuro', 'Mrs. Cynthia Wambui Gitau', '+254720300050', 'gikandu.sec@schools.go.ke'),
            ('Kamuthe Secondary School', 'highschool', 'Gitugi', 'Mr. Caleb Njoroge Kariuki', '+254720300051', 'kamuthe.sec@schools.go.ke'),
            ('Kianjibu Secondary School', 'highschool', 'Kiriani', 'Mrs. Judith Nyambura Kamau', '+254720300052', 'kianjibu.sec@schools.go.ke'),
            ('Githimu Secondary School', 'highschool', 'Rwathia', 'Mr. Adrian Mwangi Githinji', '+254720300053', 'githimu.sec@schools.go.ke'),
            ('Muruaki Secondary School', 'highschool', 'Kangema', 'Mrs. Harriet Wanjiku Njoroge', '+254720300054', 'muruaki.sec@schools.go.ke'),
            ('Thitha Secondary School', 'highschool', "Ng'araria", 'Mr. Oscar Kamande Waweru', '+254720300055', 'thitha.sec@schools.go.ke'),
            ('Mururi Secondary School', 'highschool', 'Kariara', 'Mrs. Christine Wangui Kariuki', '+254720300056', 'mururi.sec@schools.go.ke'),
            ('Muruka Girls Secondary', 'highschool', 'Gaichanjiru', 'Ms. Angela Nyambura Gitau', '+254720300057', 'muruka.girls@schools.go.ke'),
            ('Kariara Mixed Day Secondary', 'highschool', 'Kariara', 'Mr. Denis Mwangi Kamau', '+254720300058', 'kariara.day@schools.go.ke'),
            ('Githutha Secondary School', 'highschool', 'Kiriani', 'Mrs. Monica Wambui Njoroge', '+254720300059', 'githutha.sec@schools.go.ke'),
            ('Kagaari Secondary School', 'highschool', "Ng'araria", 'Mr. Anthony Kariuki Githinji', '+254720300060', 'kagaari.sec@schools.go.ke'),
            ('Kiria-ini Secondary School', 'highschool', 'Kigumo East', 'Mrs. Eunice Wanjiku Kamau', '+254720300061', 'kiria.ini.sec@schools.go.ke'),
            ('Gacharage Secondary School', 'highschool', 'Makuyu', 'Mr. Nathan Njoroge Mwangi', '+254720300062', 'gacharage.sec@schools.go.ke'),
            ('Kanduti Secondary School', 'highschool', 'Makuyu', 'Mrs. Pauline Nyambura Waweru', '+254720300063', 'kanduti.sec@schools.go.ke'),
            ('Githioro Secondary School', 'highschool', 'Kinyona', 'Mr. Elias Kamau Kariuki', '+254720300064', 'githioro.sec@schools.go.ke'),
            ('Kimbimbi Secondary School', 'highschool', 'Kariara', 'Mrs. Florence Wanjiku Githinji', '+254720300065', 'kimbimbi.sec@schools.go.ke'),
            ('Iganjo Secondary School', 'highschool', 'Muguru', 'Mr. Ezekiel Mwangi Njoroge', '+254720300066', 'iganjo.sec@schools.go.ke'),
            ('Kiangome Secondary School', 'highschool', 'Njiiri', 'Mrs. Veronica Wangui Kamau', '+254720300067', 'kiangome.sec@schools.go.ke'),
            ('Githumu Secondary School', 'highschool', 'Kirwara', 'Mr. Stephen Kamande Gitau', '+254720300068', 'githumu.sec@schools.go.ke'),
            ('Kiambaa Secondary School', 'highschool', 'Kirwara', 'Mrs. Irene Nyambura Waweru', '+254720300069', 'kiambaa.sec@schools.go.ke'),
            ('Karembu Secondary School', 'highschool', 'Ithanga', 'Mr. Julius Kariuki Kamau', '+254720300070', 'karembu.sec@schools.go.ke'),
            ('Murinduko Secondary School', 'highschool', 'Kigumo', 'Mrs. Mercy Wambui Njoroge', '+254720300071', 'murinduko.sec@schools.go.ke'),
            ('Gikindu Secondary School', 'highschool', 'Kamacharia', 'Mr. Hosea Mwangi Githinji', '+254720300072', 'gikindu.sec@schools.go.ke'),
            ('Gakoigo Secondary School', 'highschool', 'Kiriani', 'Mrs. Priscilla Wanjiku Kariuki', '+254720300073', 'gakoigo.sec@schools.go.ke'),
            ('Munyaka Secondary School', 'highschool', 'Ithiru', 'Mr. Lawrence Njoroge Kamau', '+254720300074', 'munyaka.sec@schools.go.ke'),
            ('Ngaita Secondary School', 'highschool', 'Gitugi', 'Mrs. Magdalene Nyambura Gitau', '+254720300075', 'ngaita.sec@schools.go.ke'),
            ('Kiamugumo Secondary School', 'highschool', 'Kiru', 'Mr. Valentine Kamau Waweru', '+254720300076', 'kiamugumo.sec@schools.go.ke'),
            ('Karungu Secondary School', 'highschool', 'Ruchu', 'Mrs. Abigail Wanjiku Kariuki', '+254720300077', 'karungu.sec@schools.go.ke'),
            ('Gakanga Secondary School', 'highschool', 'Mugoiri', 'Mr. Amos Mwangi Njoroge', '+254720300078', 'gakanga.sec@schools.go.ke'),
            ("St. Peter's Mbugi Secondary", 'highschool', 'Kamahuha', 'Rev. Peter Kamande Githinji', '+254720300079', 'st.peters.mbugi@schools.go.ke'),
            ('Kihumba Secondary School', 'highschool', 'Gaturi', 'Mrs. Rebecca Wangui Kamau', '+254720300080', 'kihumba.sec@schools.go.ke'),
            ('Kiriti Secondary School', 'highschool', 'Kigumo', 'Mr. Solomon Kariuki Waweru', '+254720300081', 'kiriti.sec@schools.go.ke'),
            ('Giakanja Secondary School', 'highschool', 'Mbiri', 'Mrs. Stella Nyambura Githinji', '+254720300082', 'giakanja.sec@schools.go.ke'),
            ('Ngurwe Secondary School', 'highschool', 'Nginda', 'Mr. Boniface Njoroge Kariuki', '+254720300083', 'ngurwe.sec@schools.go.ke'),
            ('Wangige Mixed Day Secondary', 'highschool', 'Wangu', 'Mrs. Josephine Wambui Kamau', '+254720300084', 'wangige.day@schools.go.ke'),
            ('Gitaru Secondary School', 'highschool', 'Kambiti', 'Mr. Reuben Mwangi Githinji', '+254720300085', 'gitaru.sec@schools.go.ke'),
        ]

        created = []
        for name, itype, sub_county, principal, phone, email in institutions_data:
            bank = random.choice(banks)
            branch = random.choice(branches)
            acct = f'ACC{random.randint(1000000, 9999999)}'
            inst = Institution.objects.create(
                name=name,
                institution_type=itype,
                county=county,
                sub_county=sub_county,
                phone_number=phone,
                email=email,
                principal_name=principal,
                principal_phone=f'+2547{random.randint(10000000, 99999999)}',
                principal_email=email.replace('schools.go.ke', 'principal.ke'),
                bank_name=bank,
                bank_branch=branch,
                account_number=acct,
                account_name=name,
                is_active=True,
                postal_address=f'P.O. Box {random.randint(1, 999)}-10200, Murang\'a',
                physical_address=f'{sub_county}, Murang\'a County',
            )
            created.append(inst)

        self.stdout.write(f'    ✓ Created {len(created)} institutions')
        return created

    # =========================================================
    # STAFF USERS
    # =========================================================
    def _seed_staff_users(self, county, constituencies, wards):
        from main_application.models import User
        self.stdout.write('  Creating staff users...')

        hashed_pw = make_password('password123')

        # Super admin
        admin = User.objects.create(
            username='admin',
            email='admin@muranga.go.ke',
            first_name='System',
            last_name='Administrator',
            user_type='admin',
            id_number='12345678',
            phone_number='+254710000001',
            password=hashed_pw,
            is_staff=True,
            is_superuser=True,
            is_active=True,
        )

        # County admin
        county_admin = User.objects.create(
            username='county_admin_muranga',
            email='county.admin@muranga.go.ke',
            first_name='Jane',
            last_name='Wanjiku Mwangi',
            user_type='county_admin',
            id_number='23456789',
            phone_number='+254710000002',
            password=hashed_pw,
            is_staff=True,
            is_active=True,
            assigned_county=county,
        )

        # Finance officer
        finance = User.objects.create(
            username='finance_muranga',
            email='finance@muranga.go.ke',
            first_name='Samuel',
            last_name='Kariuki Njoroge',
            user_type='finance',
            id_number='34567890',
            phone_number='+254710000003',
            password=hashed_pw,
            is_staff=True,
            is_active=True,
        )

        # Reviewers
        reviewer1 = User.objects.create(
            username='reviewer_kiharu',
            email='reviewer.kiharu@muranga.go.ke',
            first_name='David',
            last_name='Kamau Githinji',
            user_type='reviewer',
            id_number='45678901',
            phone_number='+254710000004',
            password=hashed_pw,
            is_staff=True,
            is_active=True,
        )
        reviewer2 = User.objects.create(
            username='reviewer_mathioya',
            email='reviewer.mathioya@muranga.go.ke',
            first_name='Mary',
            last_name='Nyambura Kariuki',
            user_type='reviewer',
            id_number='56789012',
            phone_number='+254710000005',
            password=hashed_pw,
            is_staff=True,
            is_active=True,
        )

        # Constituency admins
        const_admins = []
        const_data = [
            ('Kiharu', 'Peter', 'Ndichu Waweru', '67890123', '+254710000006'),
            ('Mathioya', 'Grace', 'Wangui Kamau', '78901234', '+254710000007'),
            ('Kangema', 'John', 'Mwangi Gitau', '89012345', '+254710000008'),
            ('Gatanga', 'Susan', 'Njoki Njoroge', '90123456', '+254710000009'),
            ('Maragwa', 'Michael', 'Kariuki Waweru', '01234567', '+254710000010'),
            ('Kahuro', 'Catherine', 'Wambui Mwangi', '11234567', '+254710000011'),
        ]
        const_map = {c.name: c for c in constituencies}
        for idx, (const_name, fname, lname, id_no, phone) in enumerate(const_data):
            const = const_map.get(const_name)
            ca = User.objects.create(
                username=f'const_admin_{const_name.lower().replace("\'", "").replace(" ", "_")}',
                email=f'admin.{const_name.lower().replace(" ", ".")}@muranga.go.ke',
                first_name=fname,
                last_name=lname,
                user_type='constituency_admin',
                id_number=id_no,
                phone_number=phone,
                password=hashed_pw,
                is_staff=True,
                is_active=True,
                assigned_constituency=const,
            )
            const_admins.append(ca)

        # Ward admins (one per ward for Kiharu & Mathioya)
        ward_admins = []
        kiharu_mathioya_wards = [w for w in wards if w.constituency.name in ('Kiharu', 'Mathioya')]
        wnames_f = ['Faith', 'Lucy', 'Anne', 'Rose', 'Joyce', 'Esther', 'Ruth', 'Hannah', 'Sarah', 'Rebecca',
                    'Agnes', 'Beatrice', 'Gladys', 'Tabitha', 'Eunice', 'Grace', 'Mary', 'Susan', 'Lydia']
        wnames_m = ['James', 'John', 'Peter', 'Paul', 'David', 'Samuel', 'Daniel', 'Philip', 'Andrew', 'Thomas',
                    'Simon', 'Mark', 'Luke', 'Joseph', 'Moses', 'Elijah', 'Aaron', 'Joshua', 'Nathan']
        for i, ward in enumerate(kiharu_mathioya_wards):
            gender = 'F' if i % 2 == 0 else 'M'
            fname = random.choice(wnames_f if gender == 'F' else wnames_m)
            uname = f'ward_admin_{ward.name.lower().replace(" ", "_").replace("\'", "").replace("/", "_").replace("\'", "")[:20]}_{i}'
            wa = User.objects.create(
                username=uname,
                email=f'ward{i}@muranga.go.ke',
                first_name=fname,
                last_name=f'Kamau Ward{i}',
                user_type='ward_admin',
                id_number=f'W{str(i).zfill(7)}',
                phone_number=f'+2547{str(30000000 + i).zfill(8)}',
                password=hashed_pw,
                is_staff=True,
                is_active=True,
                assigned_ward=ward,
            )
            ward_admins.append(wa)

        self.stdout.write(f'    ✓ Created staff: admin, county_admin, finance, 2 reviewers, 6 const_admins, {len(ward_admins)} ward_admins')
        return {
            'admin': admin,
            'county_admin': county_admin,
            'finance': finance,
            'reviewer1': reviewer1,
            'reviewer2': reviewer2,
            'const_admins': const_admins,
            'ward_admins': ward_admins,
        }

    # =========================================================
    # FISCAL YEARS
    # =========================================================
    def _seed_fiscal_years(self, county, admin_user):
        from main_application.models import FiscalYear
        self.stdout.write('  Creating fiscal years (2022-2025)...')

        fy_data = [
            {
                'name': '2022-2023',
                'start_date': date(2022, 7, 1),
                'end_date': date(2023, 6, 30),
                'total_county_budget': decimal.Decimal('6500000000.00'),
                'education_budget': decimal.Decimal('850000000.00'),
                'total_bursary_allocation': decimal.Decimal('120000000.00'),
                'equitable_share': decimal.Decimal('5800000000.00'),
                'conditional_grants': decimal.Decimal('700000000.00'),
                'is_active': False,
                'application_open': False,
                'application_deadline': date(2022, 10, 31),
                'number_of_disbursement_rounds': 2,
            },
            {
                'name': '2023-2024',
                'start_date': date(2023, 7, 1),
                'end_date': date(2024, 6, 30),
                'total_county_budget': decimal.Decimal('7000000000.00'),
                'education_budget': decimal.Decimal('950000000.00'),
                'total_bursary_allocation': decimal.Decimal('140000000.00'),
                'equitable_share': decimal.Decimal('6200000000.00'),
                'conditional_grants': decimal.Decimal('800000000.00'),
                'is_active': False,
                'application_open': False,
                'application_deadline': date(2023, 10, 31),
                'number_of_disbursement_rounds': 2,
            },
            {
                'name': '2024-2025',
                'start_date': date(2024, 7, 1),
                'end_date': date(2025, 6, 30),
                'total_county_budget': decimal.Decimal('7800000000.00'),
                'education_budget': decimal.Decimal('1050000000.00'),
                'total_bursary_allocation': decimal.Decimal('160000000.00'),
                'equitable_share': decimal.Decimal('6900000000.00'),
                'conditional_grants': decimal.Decimal('900000000.00'),
                'is_active': True,
                'application_open': True,
                'application_deadline': date(2025, 2, 28),
                'number_of_disbursement_rounds': 2,
            },
        ]

        created = []
        for data in fy_data:
            fy = FiscalYear.objects.create(county=county, created_by=admin_user, **data)
            created.append(fy)
            self.stdout.write(f'    ✓ Fiscal Year {fy.name}')
        return created

    # =========================================================
    # WARD ALLOCATIONS
    # =========================================================
    def _seed_ward_allocations(self, fiscal_years, wards):
        from main_application.models import WardAllocation
        self.stdout.write('  Creating ward allocations...')
        created = []
        # Allocations per fiscal year (total roughly matching bursary allocation)
        fy_amounts = {
            '2022-2023': 3500000,
            '2023-2024': 4200000,
            '2024-2025': 4800000,
        }
        for fy in fiscal_years:
            base = fy_amounts.get(fy.name, 4000000)
            for ward in wards:
                amount = decimal.Decimal(str(random.randint(int(base * 0.85), int(base * 1.15))))
                spent = decimal.Decimal(str(random.randint(int(float(amount) * 0.4), int(float(amount) * 0.9)))) if not fy.is_active else decimal.Decimal('0')
                bcount = random.randint(20, 80)
                wa = WardAllocation.objects.create(
                    fiscal_year=fy,
                    ward=ward,
                    allocated_amount=amount,
                    spent_amount=spent,
                    beneficiaries_count=bcount,
                )
                created.append(wa)
        self.stdout.write(f'    ✓ Created {len(created)} ward allocations')
        return created

    # =========================================================
    # BURSARY CATEGORIES
    # =========================================================
    def _seed_bursary_categories(self, fiscal_years, constituencies, wards):
        from main_application.models import BursaryCategory
        self.stdout.write('  Creating bursary categories...')
        created = []

        categories_template = [
            ('Secondary School Bursary', 'secondary_boarding', 50000000, 30000, 5000, 1500, 'county'),
            ('University/College Bursary', 'university', 40000000, 50000, 10000, 800, 'county'),
            ('Primary School Bursary', 'primary', 15000000, 15000, 3000, 1000, 'county'),
            ('TVET/Technical Bursary', 'tvet', 20000000, 40000, 8000, 500, 'county'),
            ('Special Schools Bursary', 'special_school', 5000000, 50000, 10000, 100, 'county'),
            ('Orphan & Vulnerable Children', 'orphan', 10000000, 50000, 10000, 200, 'county'),
            ('Persons with Disability', 'disability', 5000000, 60000, 12000, 100, 'county'),
            ('University Freshers Bursary', 'freshers', 15000000, 50000, 10000, 300, 'county'),
        ]

        for fy in fiscal_years:
            for name, cat_type, alloc, max_pp, min_pp, target, scope in categories_template:
                start_date = fy.start_date
                end_date = fy.application_deadline or fy.end_date
                try:
                    cat = BursaryCategory.objects.create(
                        name=name,
                        category_type=cat_type,
                        fiscal_year=fy,
                        scope=scope,
                        allocation_amount=decimal.Decimal(str(alloc)),
                        max_amount_per_applicant=decimal.Decimal(str(max_pp)),
                        min_amount_per_applicant=decimal.Decimal(str(min_pp)),
                        target_beneficiaries=target,
                        spent_amount=decimal.Decimal('0'),
                        current_beneficiaries=0,
                        application_start_date=start_date,
                        application_end_date=end_date,
                        is_open=fy.is_active,
                        is_active=True,
                        description=f'{name} for Murang\'a County students - {fy.name}',
                        eligibility_criteria='Must be a resident of Murang\'a County. Must demonstrate financial need.',
                        required_documents='National ID / Birth Certificate, Fee Structure, Admission Letter, Parents\' ID',
                    )
                    created.append(cat)
                except Exception as e:
                    pass

        self.stdout.write(f'    ✓ Created {len(created)} bursary categories')
        return created

    # =========================================================
    # DISBURSEMENT ROUNDS
    # =========================================================
    def _seed_disbursement_rounds(self, fiscal_years):
        from main_application.models import DisbursementRound
        self.stdout.write('  Creating disbursement rounds...')
        created = []
        for fy in fiscal_years:
            for r in range(1, 3):
                offset_months = (r - 1) * 6
                app_start = fy.start_date + timedelta(days=offset_months * 30)
                app_end = app_start + timedelta(days=60)
                review = app_end + timedelta(days=30)
                disburse = review + timedelta(days=14)
                amount = fy.total_bursary_allocation / 2
                is_open = fy.is_active and r == 1
                is_completed = not fy.is_active
                try:
                    rd = DisbursementRound.objects.create(
                        fiscal_year=fy,
                        round_number=r,
                        name=f'{"First" if r == 1 else "Second"} Disbursement {fy.name}',
                        application_start_date=app_start,
                        application_end_date=app_end,
                        review_deadline=review,
                        disbursement_date=disburse,
                        allocated_amount=amount,
                        disbursed_amount=amount if is_completed else decimal.Decimal('0'),
                        is_open=is_open,
                        is_completed=is_completed,
                    )
                    created.append(rd)
                except Exception as e:
                    pass
        self.stdout.write(f'    ✓ Created {len(created)} disbursement rounds')
        return created

    # =========================================================
    # APPLICANTS (TARGET: 1000)
    # =========================================================
    def _seed_applicants(self, county, constituencies, wards, locations, sublocations, villages):
        from main_application.models import User, Applicant, Guardian, SiblingInformation
        self.stdout.write('  Creating 1000 applicants...')

        hashed_pw = make_password('password123')

        # Kikuyu/Murang'a names pool
        first_names_m = [
            'James', 'John', 'Peter', 'Paul', 'David', 'Samuel', 'Daniel', 'Philip', 'Andrew', 'Thomas',
            'Simon', 'Mark', 'Luke', 'Joseph', 'Moses', 'Elijah', 'Aaron', 'Joshua', 'Nathan', 'Caleb',
            'Michael', 'Gabriel', 'Raphael', 'Emmanuel', 'Francis', 'Patrick', 'Kevin', 'Brian', 'Dennis',
            'George', 'Charles', 'Henry', 'Victor', 'Edward', 'Anthony', 'Robert', 'Richard', 'Eric',
            'Benjamin', 'Solomon', 'Ezra', 'Timothy', 'Titus', 'Cornelius', 'Felix', 'Stephen', 'Philip',
            'Geoffrey', 'Boniface', 'Hezekiah', 'Josphat', 'Ezekiel', 'Laban', 'Hosea', 'Amos', 'Joel',
        ]
        first_names_f = [
            'Mary', 'Grace', 'Faith', 'Hope', 'Joyce', 'Susan', 'Jane', 'Agnes', 'Rose', 'Ruth',
            'Hannah', 'Esther', 'Lydia', 'Priscilla', 'Dorcas', 'Tabitha', 'Eunice', 'Elizabeth', 'Miriam',
            'Sarah', 'Rebecca', 'Rachel', 'Leah', 'Deborah', 'Abigail', 'Catherine', 'Christine', 'Cynthia',
            'Dorothy', 'Eunice', 'Florence', 'Gladys', 'Harriet', 'Irene', 'Judith', 'Josephine', 'Karen',
            'Lucy', 'Mercy', 'Naomi', 'Pauline', 'Phyllis', 'Patricia', 'Stella', 'Veronica', 'Wanjiku',
            'Nyambura', 'Wangui', 'Njeri', 'Wambui', 'Njoki', 'Wairimu', 'Gathoni', 'Wahu', 'Mumbi',
        ]
        surnames = [
            'Kamau', 'Njoroge', 'Kariuki', 'Mwangi', 'Githinji', 'Waweru', 'Gichuhi', 'Gitau',
            'Ndichu', 'Kamande', 'Maina', 'Njoki', 'Wanjiku', 'Wangui', 'Nyambura', 'Wairimu',
            'Githumbi', 'Muigai', 'Mugo', 'Kimani', 'Kiragu', 'Kiarie', 'Macharia', 'Muchai',
            'Kahura', 'Githae', 'Karuga', 'Murigi', 'Gacheru', 'Gitonga', 'Ndegwa', 'Nganga',
            'Njenga', 'Njogu', 'Muriithi', 'Muthoni', 'Ndungu', 'Ngugi', 'Waithaka', 'Wainaina',
        ]

        relationship_choices = ['father', 'mother', 'guardian', 'grandfather', 'grandmother', 'uncle', 'aunt']
        employment_choices = ['employed', 'self_employed', 'casual', 'unemployed', 'retired', 'deceased']

        # Weight wards: more from Kiharu & Mathioya
        kiharu_mathioya_wards = [w for w in wards if w.constituency.name in ('Kiharu', 'Mathioya')]
        other_wards = [w for w in wards if w.constituency.name not in ('Kiharu', 'Mathioya')]

        created_applicants = []
        existing_ids = set()
        existing_usernames = set()

        for i in range(1000):
            gender = 'F' if i % 2 == 0 else 'M'
            first_name = random.choice(first_names_f if gender == 'F' else first_names_m)
            surname = random.choice(surnames)
            middle = random.choice(surnames)

            # Unique username
            base_uname = f'{first_name.lower()}.{surname.lower()}{i}'
            username = base_uname
            while username in existing_usernames:
                username = f'{base_uname}_{random.randint(1, 999)}'
            existing_usernames.add(username)

            # Unique ID number
            id_num = f'{random.randint(30000000, 40000000)}'
            while id_num in existing_ids:
                id_num = f'{random.randint(30000000, 40000000)}'
            existing_ids.add(id_num)

            # DOB: 15-30 years ago
            dob = date(random.randint(1994, 2009), random.randint(1, 12), random.randint(1, 28))

            # Pick ward: 60% Kiharu/Mathioya, 40% others
            if random.random() < 0.6 and kiharu_mathioya_wards:
                ward = random.choice(kiharu_mathioya_wards)
            else:
                ward = random.choice(other_wards) if other_wards else random.choice(wards)

            constituency = ward.constituency

            # Locations
            ward_locs = [l for l in locations if l.ward == ward]
            loc = random.choice(ward_locs) if ward_locs else None
            sl = None
            if loc:
                loc_sls = [s for s in sublocations if s.location == loc]
                sl = random.choice(loc_sls) if loc_sls else None

            # Create user
            user = User.objects.create(
                username=username,
                email=f'{username}@gmail.com',
                first_name=first_name,
                last_name=f'{middle} {surname}',
                user_type='applicant',
                id_number=id_num,
                phone_number=f'+2547{random.randint(10000000, 99999999)}',
                password=hashed_pw,
                is_active=True,
            )

            # Create applicant profile
            applicant = Applicant.objects.create(
                user=user,
                gender=gender,
                date_of_birth=dob,
                id_number=id_num,
                county=county,
                constituency=constituency,
                ward=ward,
                location=loc,
                sublocation=sl,
                physical_address=f'P.O. Box {random.randint(1, 999)}, {ward.name}, Murang\'a',
                special_needs=random.random() < 0.05,
                is_verified=random.random() < 0.7,
            )

            # Create 1-2 guardians
            num_guardians = random.randint(1, 2)
            is_orphan = random.random() < 0.15  # 15% orphans
            for g in range(num_guardians):
                relationship = random.choice(relationship_choices)
                if is_orphan and g == 0:
                    relationship = 'guardian'
                employment = random.choice(employment_choices)
                if is_orphan:
                    employment = random.choice(['unemployed', 'casual', 'deceased'])
                Guardian.objects.create(
                    applicant=applicant,
                    name=f'{random.choice(first_names_m)} {random.choice(surnames)}',
                    relationship=relationship,
                    phone_number=f'+2547{random.randint(10000000, 99999999)}',
                    employment_status=employment,
                    occupation=random.choice(['Farmer', 'Teacher', 'Casual Laborer', 'Shopkeeper', 'Driver', 'Nurse']),
                    monthly_income=decimal.Decimal(str(random.randint(3000, 45000))) if employment not in ['unemployed', 'deceased'] else None,
                    is_primary_contact=g == 0,
                )

            # Create siblings
            num_siblings = random.randint(0, 5)
            for s in range(num_siblings):
                SiblingInformation.objects.create(
                    applicant=applicant,
                    name=f'{random.choice(first_names_f + first_names_m)} {surname}',
                    age=random.randint(5, 25),
                    education_level=random.choice(['Primary', 'Secondary', 'University', 'TVET', 'None']),
                    school_name=random.choice(['Local Primary', 'District Secondary', 'County University', '']),
                    is_in_school=random.random() < 0.6,
                )

            created_applicants.append(applicant)

            if (i + 1) % 100 == 0:
                self.stdout.write(f'    ... {i+1}/1000 applicants created')

        self.stdout.write(f'    ✓ Created {len(created_applicants)} applicants with guardians & siblings')
        return created_applicants

    # =========================================================
    # APPLICATIONS
    # =========================================================
    def _seed_applications(self, applicants, fiscal_years, categories, institutions, rounds, users_staff):
        from main_application.models import Application, Review, Allocation, Notification
        self.stdout.write('  Creating applications, reviews & allocations...')

        reviewers = [users_staff['reviewer1'], users_staff['reviewer2']]
        finance_user = users_staff['finance']

        # Filter institutions by type
        highschools = [i for i in institutions if i.institution_type == 'highschool']
        universities = [i for i in institutions if i.institution_type == 'university']
        colleges = [i for i in institutions if i.institution_type in ('college', 'technical_institute', 'tvet')]
        specials = [i for i in institutions if i.institution_type == 'special_school']

        # Categories per fiscal year
        fy_cat_map = {}
        for cat in categories:
            fy_id = cat.fiscal_year_id
            if fy_id not in fy_cat_map:
                fy_cat_map[fy_id] = {}
            fy_cat_map[fy_id][cat.category_type] = cat

        # Rounds per fiscal year
        fy_round_map = {}
        for rd in rounds:
            fy_id = rd.fiscal_year_id
            if fy_id not in fy_round_map:
                fy_round_map[fy_id] = []
            fy_round_map[fy_id].append(rd)

        statuses_weights = {
            '2022-2023': ['approved', 'disbursed', 'rejected'],
            '2023-2024': ['approved', 'disbursed', 'approved', 'rejected'],
            '2024-2025': ['submitted', 'under_review', 'approved', 'draft', 'rejected'],
        }

        all_apps = []
        all_allocs = []
        used_app_numbers = set()

        # Each applicant gets 1-2 applications spread across fiscal years
        for appl in applicants:
            # Pick 1-3 fiscal years to apply in
            num_fy = random.randint(1, min(3, len(fiscal_years)))
            selected_fys = random.sample(fiscal_years, num_fy)

            for fy in selected_fys:
                cats_this_fy = fy_cat_map.get(fy.id, {})
                if not cats_this_fy:
                    continue

                # Pick institution type based on applicant age
                dob = appl.date_of_birth
                age_at_fy = fy.start_date.year - dob.year
                if age_at_fy < 18:
                    inst_pool = highschools
                    cat_key = 'secondary_boarding'
                elif age_at_fy < 22:
                    inst_pool = universities + colleges
                    cat_key = random.choice(['university', 'tvet'])
                else:
                    inst_pool = universities + colleges
                    cat_key = 'university'

                if appl.special_needs:
                    inst_pool = specials if specials else highschools
                    cat_key = 'special_school'

                cat = cats_this_fy.get(cat_key) or cats_this_fy.get('secondary_boarding') or list(cats_this_fy.values())[0]
                institution = random.choice(inst_pool) if inst_pool else random.choice(institutions)

                # Status based on fiscal year
                status_options = statuses_weights.get(fy.name, ['submitted'])
                status = random.choice(status_options)

                # Fees
                if cat_key == 'university':
                    total_fees = decimal.Decimal(str(random.randint(60000, 150000)))
                elif cat_key in ('tvet', 'college'):
                    total_fees = decimal.Decimal(str(random.randint(30000, 80000)))
                else:
                    total_fees = decimal.Decimal(str(random.randint(30000, 70000)))

                fees_paid = total_fees * decimal.Decimal(str(random.uniform(0.1, 0.5)))
                fees_balance = total_fees - fees_paid
                amount_req = min(fees_balance, cat.max_amount_per_applicant)

                # Submission date within fiscal year
                submit_date = timezone.make_aware(datetime(
                    fy.start_date.year,
                    random.randint(7, 12) if fy.start_date.month <= 7 else random.randint(1, 6),
                    random.randint(1, 28)
                ))

                # Year of study
                yos = 1
                if cat_key in ('secondary_boarding', 'secondary_day'):
                    yos = random.randint(1, 4)
                elif cat_key in ('university', 'freshers'):
                    yos = random.randint(1, 4)
                elif cat_key in ('tvet', 'technical'):
                    yos = random.randint(1, 2)

                course = ''
                if cat_key in ('university', 'freshers'):
                    course = random.choice([
                        'Bachelor of Commerce', 'Bachelor of Education', 'Bachelor of Science',
                        'Bachelor of Nursing', 'Bachelor of Engineering', 'Bachelor of Laws',
                        'Bachelor of Arts', 'Bachelor of Business Administration',
                        'Bachelor of Information Technology', 'Bachelor of Computer Science',
                    ])
                elif cat_key in ('tvet', 'technical'):
                    course = random.choice([
                        'Certificate in Electrical Engineering', 'Diploma in Plumbing',
                        'Certificate in Automotive Engineering', 'Diploma in ICT',
                        'Certificate in Catering', 'Diploma in Business Management',
                    ])

                # Unique application number
                year = fy.name.split('-')[0][-2:]
                county_code = 'MR'
                rand_part = uuid.uuid4().hex[:4].upper()
                app_no = f'KB{year}{county_code}{rand_part}'
                while app_no in used_app_numbers:
                    rand_part = uuid.uuid4().hex[:4].upper()
                    app_no = f'KB{year}{county_code}{rand_part}'
                used_app_numbers.add(app_no)

                is_orphan = appl.guardians.filter(employment_status='deceased').count() > 0

                round_qs = fy_round_map.get(fy.id, [])
                disburse_round = random.choice(round_qs) if round_qs else None

                try:
                    app = Application.objects.create(
                        application_number=app_no,
                        applicant=appl,
                        fiscal_year=fy,
                        disbursement_round=disburse_round,
                        bursary_category=cat,
                        institution=institution,
                        bursary_source=random.choice(['county', 'cdf', 'county']),
                        status=status,
                        admission_number=f'ADM{random.randint(1000, 9999)}/{fy.start_date.year}',
                        year_of_study=yos,
                        course_name=course,
                        expected_completion_date=date(fy.end_date.year + (4 - yos), 6, 30),
                        previous_academic_year_average=decimal.Decimal(str(random.randint(40, 90))) if random.random() > 0.3 else None,
                        total_fees_payable=total_fees,
                        fees_paid=fees_paid.quantize(decimal.Decimal('0.01')),
                        fees_balance=fees_balance.quantize(decimal.Decimal('0.01')),
                        amount_requested=amount_req.quantize(decimal.Decimal('0.01')),
                        other_bursaries=random.random() < 0.2,
                        other_bursaries_amount=decimal.Decimal(str(random.randint(3000, 10000))) if random.random() < 0.2 else decimal.Decimal('0'),
                        is_orphan=is_orphan,
                        is_total_orphan=is_orphan and random.random() < 0.3,
                        is_disabled=appl.special_needs,
                        has_chronic_illness=random.random() < 0.08,
                        number_of_siblings=appl.siblings.count(),
                        number_of_siblings_in_school=max(0, appl.siblings.filter(is_in_school=True).count()),
                        household_monthly_income=decimal.Decimal(str(random.randint(2000, 30000))),
                        date_submitted=submit_date if status != 'draft' else None,
                        has_received_previous_allocation=random.random() < 0.3,
                        previous_allocation_year=str(fy.start_date.year - 1) if random.random() < 0.3 else '',
                        previous_allocation_amount=decimal.Decimal(str(random.randint(5000, 30000))) if random.random() < 0.3 else decimal.Decimal('0'),
                        priority_score=decimal.Decimal(str(random.uniform(30, 95))),
                    )
                    all_apps.append(app)

                    # Reviews for submitted/approved/disbursed applications
                    if status in ('under_review', 'approved', 'disbursed', 'rejected'):
                        reviewer = random.choice(reviewers)
                        recommendation = 'approve' if status in ('approved', 'disbursed') else ('reject' if status == 'rejected' else 'forward')
                        rec_amount = amount_req * decimal.Decimal(str(random.uniform(0.5, 1.0))) if recommendation == 'approve' else None
                        try:
                            Review.objects.create(
                                application=app,
                                reviewer=reviewer,
                                review_level='ward' if status == 'under_review' else 'county',
                                comments=self._review_comment(status, appl),
                                recommendation=recommendation,
                                recommended_amount=rec_amount.quantize(decimal.Decimal('0.01')) if rec_amount else None,
                                need_score=random.randint(5, 10) if recommendation == 'approve' else random.randint(1, 5),
                                merit_score=random.randint(5, 10),
                                vulnerability_score=random.randint(4, 10) if is_orphan else random.randint(2, 8),
                            )
                        except Exception:
                            pass

                    # Allocations for approved/disbursed
                    if status in ('approved', 'disbursed'):
                        alloc_amount = amount_req * decimal.Decimal(str(random.uniform(0.6, 1.0)))
                        alloc_amount = alloc_amount.quantize(decimal.Decimal('0.01'))
                        try:
                            alloc = Allocation.objects.create(
                                application=app,
                                applicant=appl,
                                fiscal_year=fy,
                                bursary_category=cat,
                                amount_allocated=alloc_amount,
                                approved_amount=alloc_amount,
                                status='disbursed' if status == 'disbursed' else 'approved',
                                payment_method=random.choice(['cheque', 'cheque', 'bank_transfer']),
                                cheque_number=f'CHQ{random.randint(100000, 999999)}' if status == 'disbursed' else '',
                                is_disbursed=status == 'disbursed',
                                disbursement_date=date(fy.end_date.year, random.randint(1, 6), random.randint(1, 28)) if status == 'disbursed' else None,
                                disbursed_by=finance_user if status == 'disbursed' else None,
                                is_received_by_institution=status == 'disbursed',
                                approved_by=finance_user,
                                remarks=f'Approved for {fy.name} bursary cycle.',
                            )
                            all_allocs.append(alloc)

                            # Notification
                            msg = f'Congratulations! Your bursary application {app_no} has been {"disbursed" if status == "disbursed" else "approved"} for KES {alloc_amount:,.2f}.'
                            Notification.objects.create(
                                user=appl.user,
                                notification_type='allocation',
                                title='Bursary Application Update',
                                message=msg,
                                related_application=app,
                                is_read=random.random() < 0.6,
                            )
                        except Exception:
                            pass

                    elif status == 'rejected':
                        Notification.objects.create(
                            user=appl.user,
                            notification_type='application_status',
                            title='Bursary Application Update',
                            message=f'We regret to inform you that your application {app_no} was not successful. Please contact the bursary office for more information.',
                            related_application=app,
                            is_read=random.random() < 0.4,
                        )

                except Exception as e:
                    continue

        self.stdout.write(f'    ✓ Created {len(all_apps)} applications, {len(all_allocs)} allocations')
        return all_apps

    def _review_comment(self, status, applicant):
        comments = {
            'approved': [
                f'Application reviewed and found eligible. Applicant demonstrates genuine financial need. Ward committee recommends approval.',
                f'The applicant qualifies based on household income assessment. Family circumstances confirm needy status. Recommended for approval.',
                f'Verified with village elder and MCA office. Applicant is a bona fide resident of {applicant.ward.name if applicant.ward else "this"} ward. Approved.',
                f'Documents verified. Academic performance is satisfactory. Financial need confirmed through home visit.',
            ],
            'disbursed': [
                f'All documents verified. Bursary disbursed to institution account. Principal confirmed receipt.',
                f'Cheque issued and delivered via Wells Fargo. Institution confirmed receipt of funds.',
            ],
            'rejected': [
                f'Application rejected: Applicant does not meet residency requirements for Murang\'a County.',
                f'Application rejected: Incomplete documentation submitted. Missing fee structure and admission letter.',
                f'Application rejected: Household income exceeds the threshold for bursary eligibility.',
                f'Application rejected: Applicant already receiving adequate financial support from another bursary.',
            ],
            'under_review': [
                f'Application under review by ward committee. Awaiting home visit confirmation.',
                f'Documents submitted but require verification. Awaiting response from institution.',
            ],
        }
        return random.choice(comments.get(status, ['Application reviewed by committee.']))

    # =========================================================
    # SYSTEM SETTINGS
    # =========================================================
    def _seed_system_settings(self, admin_user):
        from main_application.models import SystemSettings
        settings_data = [
            ('system_name', 'general', "Murang'a County Bursary Management System", 'Name of the system'),
            ('county_name', 'general', "Murang'a", 'County this system serves'),
            ('county_code', 'general', '022', 'Official county code'),
            ('application_open', 'application', 'true', 'Whether applications are currently open'),
            ('max_applications_per_year', 'application', '1', 'Maximum applications per student per fiscal year'),
            ('min_required_documents', 'application', '3', 'Minimum documents required per application'),
            ('sms_gateway', 'notification', 'AfricasTalking', 'SMS gateway provider'),
            ('email_sender', 'notification', 'noreply@muranga.go.ke', 'Default email sender'),
            ('session_timeout_minutes', 'security', '30', 'Session timeout in minutes'),
            ('max_login_attempts', 'security', '5', 'Maximum login attempts before lockout'),
            ('cheque_delivery_company', 'finance', 'Wells Fargo Kenya', 'Primary cheque delivery company'),
            ('bursary_office_phone', 'general', '+254710000100', 'Bursary office contact'),
            ('bursary_office_email', 'general', 'bursary@muranga.go.ke', 'Bursary office email'),
            ('fiscal_year_start_month', 'finance', 'July', 'Month when fiscal year starts'),
        ]
        for name, cat, value, desc in settings_data:
            SystemSettings.objects.create(
                setting_name=name,
                setting_category=cat,
                setting_value=value,
                description=desc,
                updated_by=admin_user,
            )
        self.stdout.write('    ✓ System settings created')

    # =========================================================
    # FAQS
    # =========================================================
    def _seed_faqs(self):
        from main_application.models import FAQ
        faqs = [
            ('Who is eligible for the Murang\'a County bursary?', 'Any student who is a resident of Murang\'a County, enrolled in an accredited institution, and can demonstrate financial need.', 'eligibility'),
            ('How do I apply for the bursary?', 'Register on this portal, complete your profile, and submit your application with all required documents before the deadline.', 'application'),
            ('What documents do I need?', 'National ID/Birth Certificate, Admission Letter, Fee Structure, Fee Statement, and Parents\' ID cards.', 'documents'),
            ('How much can I receive?', 'The amount varies by education level: Primary (up to KES 15,000), Secondary (up to KES 30,000), University (up to KES 50,000).', 'disbursement'),
            ('When are bursaries disbursed?', 'Bursaries are typically disbursed in two rounds per fiscal year. Cheques are sent directly to your institution.', 'disbursement'),
            ('Can I apply for both county and CDF bursary?', 'Yes, you can apply for both Murang\'a County bursary and your constituency NG-CDF bursary.', 'general'),
            ('How long does the review process take?', 'Applications are reviewed within 30-60 days after the deadline. You will be notified via SMS and email.', 'application'),
            ('What if my application is rejected?', 'You can appeal the decision by visiting the bursary office with additional supporting documents within 14 days.', 'application'),
            ('Is the bursary renewable each year?', 'Yes. You must re-apply each fiscal year. Previous beneficiaries are encouraged to apply again.', 'general'),
            ('How is the bursary paid?', 'Bursaries are paid directly to your institution through cheque or bank transfer. Funds are never given in cash.', 'disbursement'),
        ]
        for q, a, cat in faqs:
            FAQ.objects.create(question=q, answer=a, category=cat, is_active=True, order=faqs.index((q, a, cat)) + 1)
        self.stdout.write('    ✓ FAQs created')

    # =========================================================
    # ANNOUNCEMENTS
    # =========================================================
    def _seed_announcements(self, admin_user, fiscal_years):
        from main_application.models import Announcement
        active_fy = next((f for f in fiscal_years if f.is_active), fiscal_years[-1])

        announcements = [
            ('Bursary Applications Now Open - 2024/2025', f'The Murang\'a County Bursary office is pleased to announce that applications for the {active_fy.name} fiscal year are now open. All eligible students are encouraged to apply before the deadline of {active_fy.application_deadline or "February 28, 2025"}.', 'general', True),
            ('Important: Document Verification Exercise', 'All shortlisted applicants are required to present original documents for verification at their respective ward offices. Check the schedule on the county website.', 'deadline', True),
            ('Disbursement Notice - First Round Complete', 'The first disbursement round for FY 2023/2024 has been completed. Over 3,000 students have benefited. Institutions should confirm receipt.', 'disbursement', False),
            ('System Maintenance Notice', 'The bursary portal will be under scheduled maintenance on Saturday from 10pm to 2am. Please plan your applications accordingly.', 'maintenance', False),
            ('Urgent: Additional Slots Available', 'Due to under-subscription in the university category, additional slots are available. Eligible university students who missed the deadline may contact the office.', 'urgent', True),
        ]

        for title, content, atype, active in announcements:
            pub_date = timezone.now() - timedelta(days=random.randint(1, 60))
            Announcement.objects.create(
                title=title,
                content=content,
                announcement_type=atype,
                published_date=pub_date,
                expiry_date=pub_date + timedelta(days=90),
                is_active=active,
                is_featured=atype in ('general', 'urgent'),
                target_audience='all',
                created_by=admin_user,
            )
        self.stdout.write('    ✓ Announcements created')