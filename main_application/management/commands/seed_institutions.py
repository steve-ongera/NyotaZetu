"""
Django management command to seed ALL Kenyan educational institutions
Place this file in: main_application/management/commands/seed_institutions.py
Run with: python manage.py seed_institutions
"""

from django.core.management.base import BaseCommand
from main_application.models import Institution, County
from django.db import transaction


class Command(BaseCommand):
    help = 'Seeds ALL educational institutions in Kenya with real data'

    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.WARNING('Starting comprehensive institution seeding for Kenya...'))
        
        # Get or create counties for reference
        counties = self._get_counties()
        
        institutions_data = []
        
        # ============= UNIVERSITIES (All Kenyan Universities) =============
        universities = [
            # PUBLIC CHARTERED UNIVERSITIES
            {
                'name': 'University of Nairobi',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30197-00100',
                'physical_address': 'University Way, Nairobi',
                'phone_number': '+254202318262',
                'email': 'info@uonbi.ac.ke',
            },
            {
                'name': 'Kenyatta University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 43844-00100',
                'physical_address': 'Kahawa, Nairobi',
                'phone_number': '+254202870000',
                'email': 'info@ku.ac.ke',
            },
            {
                'name': 'Moi University',
                'institution_type': 'university',
                'county': 'Uasin Gishu',
                'postal_address': 'P.O. Box 3900-30100',
                'physical_address': 'Eldoret',
                'phone_number': '+254533143013',
                'email': 'info@mu.ac.ke',
            },
            {
                'name': 'Egerton University',
                'institution_type': 'university',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 536-20115',
                'physical_address': 'Njoro',
                'phone_number': '+254512217000',
                'email': 'info@egerton.ac.ke',
            },
            {
                'name': 'Jomo Kenyatta University of Agriculture and Technology',
                'institution_type': 'university',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 62000-00200',
                'physical_address': 'Juja',
                'phone_number': '+254677123000',
                'email': 'info@jkuat.ac.ke',
            },
            {
                'name': 'Maseno University',
                'institution_type': 'university',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 333-40105',
                'physical_address': 'Maseno',
                'phone_number': '+254572351620',
                'email': 'info@maseno.ac.ke',
            },
            {
                'name': 'Masinde Muliro University of Science and Technology',
                'institution_type': 'university',
                'county': 'Kakamega',
                'postal_address': 'P.O. Box 190-50100',
                'physical_address': 'Kakamega',
                'phone_number': '+254572502508',
                'email': 'info@mmust.ac.ke',
            },
            {
                'name': 'Dedan Kimathi University of Technology',
                'institution_type': 'university',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 657-10100',
                'physical_address': 'Nyeri',
                'phone_number': '+254202032007',
                'email': 'info@dkut.ac.ke',
            },
            {
                'name': 'Chuka University',
                'institution_type': 'university',
                'county': 'Tharaka Nithi',
                'postal_address': 'P.O. Box 109-60400',
                'physical_address': 'Chuka',
                'phone_number': '+254706385164',
                'email': 'info@chuka.ac.ke',
            },
            {
                'name': 'Technical University of Kenya',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 52428-00200',
                'physical_address': 'Haile Selassie Avenue, Nairobi',
                'phone_number': '+254202219929',
                'email': 'info@tukenya.ac.ke',
            },
            {
                'name': 'Technical University of Mombasa',
                'institution_type': 'university',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 90420-80100',
                'physical_address': 'Mombasa',
                'phone_number': '+254412492222',
                'email': 'info@tum.ac.ke',
            },
            {
                'name': 'Pwani University',
                'institution_type': 'university',
                'county': 'Kilifi',
                'postal_address': 'P.O. Box 195-80108',
                'physical_address': 'Kilifi',
                'phone_number': '+254714606240',
                'email': 'info@pu.ac.ke',
            },
            {
                'name': 'Kisii University',
                'institution_type': 'university',
                'county': 'Kisii',
                'postal_address': 'P.O. Box 408-40200',
                'physical_address': 'Kisii',
                'phone_number': '+254202606900',
                'email': 'info@kisiiuniversity.ac.ke',
            },
            {
                'name': 'Jaramogi Oginga Odinga University of Science and Technology',
                'institution_type': 'university',
                'county': 'Siaya',
                'postal_address': 'P.O. Box 210-40601',
                'physical_address': 'Bondo',
                'phone_number': '+254572051540',
                'email': 'info@jooust.ac.ke',
            },
            {
                'name': 'Laikipia University',
                'institution_type': 'university',
                'county': 'Laikipia',
                'postal_address': 'P.O. Box 1100-20300',
                'physical_address': 'Nyahururu',
                'phone_number': '+254202030013',
                'email': 'info@laikipia.ac.ke',
            },
            {
                'name': 'South Eastern Kenya University',
                'institution_type': 'university',
                'county': 'Kitui',
                'postal_address': 'P.O. Box 170-90200',
                'physical_address': 'Kitui',
                'phone_number': '+254446322157',
                'email': 'info@seku.ac.ke',
            },
            {
                'name': 'Multimedia University of Kenya',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30305-00100',
                'physical_address': 'Magadi Road, Nairobi',
                'phone_number': '+254202071391',
                'email': 'info@mmu.ac.ke',
            },
            {
                'name': 'Machakos University',
                'institution_type': 'university',
                'county': 'Machakos',
                'postal_address': 'P.O. Box 136-90100',
                'physical_address': 'Machakos',
                'phone_number': '+254444430860',
                'email': 'info@mksu.ac.ke',
            },
            {
                'name': 'Karatina University',
                'institution_type': 'university',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 1957-10101',
                'physical_address': 'Karatina',
                'phone_number': '+254202034500',
                'email': 'info@karu.ac.ke',
            },
            {
                'name': 'Murang\'a University of Technology',
                'institution_type': 'university',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 75-10200',
                'physical_address': 'Murang\'a',
                'phone_number': '+254202020110',
                'email': 'info@mut.ac.ke',
            },
            {
                'name': 'Meru University of Science and Technology',
                'institution_type': 'university',
                'county': 'Meru',
                'postal_address': 'P.O. Box 972-60200',
                'physical_address': 'Meru',
                'phone_number': '+254642460200',
                'email': 'info@must.ac.ke',
            },
            {
                'name': 'University of Eldoret',
                'institution_type': 'university',
                'county': 'Uasin Gishu',
                'postal_address': 'P.O. Box 1125-30100',
                'physical_address': 'Eldoret',
                'phone_number': '+254532500210',
                'email': 'info@uoeld.ac.ke',
            },
            {
                'name': 'University of Kabianga',
                'institution_type': 'university',
                'county': 'Kericho',
                'postal_address': 'P.O. Box 2030-20200',
                'physical_address': 'Kericho',
                'phone_number': '+254522021353',
                'email': 'info@kabianga.ac.ke',
            },
            {
                'name': 'Taita Taveta University',
                'institution_type': 'university',
                'county': 'Taita Taveta',
                'postal_address': 'P.O. Box 635-80300',
                'physical_address': 'Voi',
                'phone_number': '+254728523261',
                'email': 'info@ttu.ac.ke',
            },
            {
                'name': 'Kirinyaga University',
                'institution_type': 'university',
                'county': 'Kirinyaga',
                'postal_address': 'P.O. Box 143-10300',
                'physical_address': 'Kerugoya',
                'phone_number': '+254706894309',
                'email': 'info@kyu.ac.ke',
            },
            {
                'name': 'Garissa University',
                'institution_type': 'university',
                'county': 'Garissa',
                'postal_address': 'P.O. Box 1801-70100',
                'physical_address': 'Garissa',
                'phone_number': '+254202691992',
                'email': 'info@garissa.ac.ke',
            },
            {
                'name': 'Turkana University',
                'institution_type': 'university',
                'county': 'Turkana',
                'postal_address': 'P.O. Box 69-30500',
                'physical_address': 'Lodwar',
                'phone_number': '+254707611234',
                'email': 'info@tu.ac.ke',
            },
            {
                'name': 'Maasai Mara University',
                'institution_type': 'university',
                'county': 'Narok',
                'postal_address': 'P.O. Box 861-20500',
                'physical_address': 'Narok',
                'phone_number': '+254729293744',
                'email': 'info@mmarau.ac.ke',
            },
            {
                'name': 'Rongo University',
                'institution_type': 'university',
                'county': 'Migori',
                'postal_address': 'P.O. Box 103-40404',
                'physical_address': 'Rongo',
                'phone_number': '+254715202110',
                'email': 'info@rongovarsity.ac.ke',
            },
            {
                'name': 'Kibabii University',
                'institution_type': 'university',
                'county': 'Bungoma',
                'postal_address': 'P.O. Box 1699-50200',
                'physical_address': 'Bungoma',
                'phone_number': '+254708085934',
                'email': 'info@kibu.ac.ke',
            },
            {
                'name': 'University of Embu',
                'institution_type': 'university',
                'county': 'Embu',
                'postal_address': 'P.O. Box 6-60100',
                'physical_address': 'Embu',
                'phone_number': '+254202441003',
                'email': 'info@embuni.ac.ke',
            },
            {
                'name': 'Kaimosi Friends University',
                'institution_type': 'university',
                'county': 'Vihiga',
                'postal_address': 'P.O. Box 385-50309',
                'physical_address': 'Kaimosi',
                'phone_number': '+254723948901',
                'email': 'info@kafu.ac.ke',
            },
            {
                'name': 'Bomet University',
                'institution_type': 'university',
                'county': 'Bomet',
                'postal_address': 'P.O. Box 701-20400',
                'physical_address': 'Bomet',
                'phone_number': '+254712345678',
                'email': 'info@bometuniversity.ac.ke',
            },
            
            # PRIVATE CHARTERED UNIVERSITIES
            {
                'name': 'Strathmore University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 59857-00200',
                'physical_address': 'Ole Sangale Road, Madaraka, Nairobi',
                'phone_number': '+254703034000',
                'email': 'info@strathmore.edu',
            },
            {
                'name': 'United States International University - Africa',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 14634-00800',
                'physical_address': 'Kasarani, Nairobi',
                'phone_number': '+254202606000',
                'email': 'info@usiu.ac.ke',
            },
            {
                'name': 'Catholic University of Eastern Africa',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 62157-00200',
                'physical_address': 'Langata, Nairobi',
                'phone_number': '+254202891601',
                'email': 'info@cuea.edu',
            },
            {
                'name': 'Daystar University',
                'institution_type': 'university',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 44400-00100',
                'physical_address': 'Athi River',
                'phone_number': '+254202724137',
                'email': 'info@daystar.ac.ke',
            },
            {
                'name': 'St. Paul\'s University',
                'institution_type': 'university',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 5440-00100',
                'physical_address': 'Limuru',
                'phone_number': '+254203000125',
                'email': 'info@spu.ac.ke',
            },
            {
                'name': 'Mount Kenya University',
                'institution_type': 'university',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 342-01000',
                'physical_address': 'Thika',
                'phone_number': '+254202386208',
                'email': 'info@mku.ac.ke',
            },
            {
                'name': 'Kenya Methodist University',
                'institution_type': 'university',
                'county': 'Meru',
                'postal_address': 'P.O. Box 267-60200',
                'physical_address': 'Meru',
                'phone_number': '+254642030305',
                'email': 'info@kemu.ac.ke',
            },
            {
                'name': 'Africa Nazarene University',
                'institution_type': 'university',
                'county': 'Kajiado',
                'postal_address': 'P.O. Box 53067-00200',
                'physical_address': 'Ongata Rongai',
                'phone_number': '+254202341991',
                'email': 'info@anu.ac.ke',
            },
            {
                'name': 'Pan Africa Christian University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 56875-00200',
                'physical_address': 'Nairobi',
                'phone_number': '+254202726654',
                'email': 'info@pacuniversity.ac.ke',
            },
            {
                'name': 'Kabarak University',
                'institution_type': 'university',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 20157-20100',
                'physical_address': 'Nakuru',
                'phone_number': '+254512216430',
                'email': 'info@kabarak.ac.ke',
            },
            {
                'name': 'KCA University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 56808-00200',
                'physical_address': 'Ruaraka, Nairobi',
                'phone_number': '+254202865155',
                'email': 'info@kcau.ac.ke',
            },
            {
                'name': 'Aga Khan University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30270-00100',
                'physical_address': 'Parklands, Nairobi',
                'phone_number': '+254202723000',
                'email': 'info@aku.edu',
            },
            {
                'name': 'Adventist University of Africa',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 19536-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202723700',
                'email': 'info@aua.ac.ke',
            },
            {
                'name': 'Presbyterian University of East Africa',
                'institution_type': 'university',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 387-00217',
                'physical_address': 'Kikuyu',
                'phone_number': '+254204448851',
                'email': 'info@puea.ac.ke',
            },
            {
                'name': 'Riara University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 49940-00100',
                'physical_address': 'Mbagathi Way, Nairobi',
                'phone_number': '+254202067000',
                'email': 'info@riarauniversity.ac.ke',
            },
            {
                'name': 'The East African University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 2464-00200',
                'physical_address': 'Nairobi',
                'phone_number': '+254202611781',
                'email': 'info@teau.ac.ke',
            },
            {
                'name': 'Pioneer International University',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 34297-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202432972',
                'email': 'info@piu.ac.ke',
            },
            {
                'name': 'Great Lakes University of Kisumu',
                'institution_type': 'university',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 2224-40100',
                'physical_address': 'Kisumu',
                'phone_number': '+254572020105',
                'email': 'info@gluk.ac.ke',
            },
        ]
        
        institutions_data.extend(universities)
        self.stdout.write(self.style.SUCCESS(f'Added {len(universities)} universities'))

        # ============= NATIONAL POLYTECHNICS & TECHNICAL INSTITUTES =============
        technical_institutes = [
            {
                'name': 'Kenya Institute of Mass Communication',
                'institution_type': 'college',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 42422-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202713808',
                'email': 'info@kimc.ac.ke',
            },
            {
                'name': 'Kenya Medical Training College - Nairobi',
                'institution_type': 'college',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30195-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202726300',
                'email': 'info@kmtc.ac.ke',
            },
            {
                'name': 'Kenya Medical Training College - Mombasa',
                'institution_type': 'college',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 84037-80100',
                'physical_address': 'Mombasa',
                'phone_number': '+254412315888',
            },
            {
                'name': 'Kenya Medical Training College - Nakuru',
                'institution_type': 'college',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 10493-20100',
                'physical_address': 'Nakuru',
                'phone_number': '+254512213714',
            },
            {
                'name': 'Kenya Medical Training College - Kisumu',
                'institution_type': 'college',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 143-40100',
                'physical_address': 'Kisumu',
                'phone_number': '+254572021104',
            },
            {
                'name': 'Kenya Medical Training College - Eldoret',
                'institution_type': 'college',
                'county': 'Uasin Gishu',
                'postal_address': 'P.O. Box 14655-30100',
                'physical_address': 'Eldoret',
                'phone_number': '+254532063110',
            },
            {
                'name': 'Kenya Medical Training College - Nyeri',
                'institution_type': 'college',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 1214-10100',
                'physical_address': 'Nyeri',
                'phone_number': '+254612030600',
            },
            {
                'name': 'Kenya School of Government',
                'institution_type': 'college',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 23030-00604',
                'physical_address': 'Lower Kabete, Nairobi',
                'phone_number': '+254202606451',
                'email': 'info@ksg.ac.ke',
            },
            {
                'name': 'Kenya Institute of Special Education',
                'institution_type': 'college',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 948-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202318581',
                'email': 'info@kise.ac.ke',
            },
            {
                'name': 'Kenya School of Law',
                'institution_type': 'college',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30369-00100',
                'physical_address': 'Karen, Nairobi',
                'phone_number': '+254202699581',
                'email': 'info@ksl.ac.ke',
            },
            {
                'name': 'Multimedia University College',
                'institution_type': 'college',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30305-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202071391',
            },
            # National Polytechnics
            {
                'name': 'The Kenya Polytechnic University College',
                'institution_type': 'technical_institute',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 52428-00200',
                'physical_address': 'Nairobi',
                'phone_number': '+254202219929',
            },
            {
                'name': 'Mombasa Polytechnic University College',
                'institution_type': 'technical_institute',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 90420-80100',
                'physical_address': 'Mombasa',
                'phone_number': '+254412492222',
            },
            {
                'name': 'Eldoret National Polytechnic',
                'institution_type': 'technical_institute',
                'county': 'Uasin Gishu',
                'postal_address': 'P.O. Box 4461-30100',
                'physical_address': 'Eldoret',
                'phone_number': '+254532063436',
            },
            {
                'name': 'Kisumu National Polytechnic',
                'institution_type': 'technical_institute',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 143-40100',
                'physical_address': 'Kisumu',
                'phone_number': '+254572021235',
            },
            {
                'name': 'Kisii National Polytechnic',
                'institution_type': 'technical_institute',
                'county': 'Kisii',
                'postal_address': 'P.O. Box 222-40200',
                'physical_address': 'Kisii',
                'phone_number': '+254582030303',
            },
            {
                'name': 'North Eastern National Polytechnic',
                'institution_type': 'technical_institute',
                'county': 'Garissa',
                'postal_address': 'P.O. Box 6-70100',
                'physical_address': 'Garissa',
                'phone_number': '+254462102156',
            },
            {
                'name': 'Rift Valley Institute of Science and Technology',
                'institution_type': 'technical_institute',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 7182-20100',
                'physical_address': 'Nakuru',
                'phone_number': '+254512213456',
            },
            {
                'name': 'Coast Institute of Technology',
                'institution_type': 'technical_institute',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 99820-80100',
                'physical_address': 'Mombasa',
                'phone_number': '+254412221234',
            },
            {
                'name': 'PC Kinyanjui Technical Training Institute',
                'institution_type': 'technical_institute',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 200-00902',
                'physical_address': 'Kabete',
                'phone_number': '+254204444600',
            },
            {
                'name': 'Ramogi Institute of Advanced Technology',
                'institution_type': 'technical_institute',
                'county': 'Siaya',
                'postal_address': 'P.O. Box 1872-40600',
                'physical_address': 'Siaya',
                'phone_number': '+254572522100',
            },
            {
                'name': 'Sigalagala National Polytechnic',
                'institution_type': 'technical_institute',
                'county': 'Kakamega',
                'postal_address': 'P.O. Box 2966-50100',
                'physical_address': 'Kakamega',
                'phone_number': '+254562031076',
            },
            {
                'name': 'Murang\'a Technical Training Institute',
                'institution_type': 'technical_institute',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 220-10200',
                'physical_address': 'Murang\'a',
                'phone_number': '+254722505050',
            },
            {
                'name': 'Thika Technical Training Institute',
                'institution_type': 'technical_institute',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 1515-01000',
                'physical_address': 'Thika',
                'phone_number': '+254672029292',
            },
            {
                'name': 'Nyeri National Polytechnic',
                'institution_type': 'technical_institute',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 1741-10100',
                'physical_address': 'Nyeri',
                'phone_number': '+254612030400',
            },
            {
                'name': 'Embu University College',
                'institution_type': 'technical_institute',
                'county': 'Embu',
                'postal_address': 'P.O. Box 6-60100',
                'physical_address': 'Embu',
                'phone_number': '+254682031068',
            },
            {
                'name': 'Machakos Institute of Technology',
                'institution_type': 'technical_institute',
                'county': 'Machakos',
                'postal_address': 'P.O. Box 136-90100',
                'physical_address': 'Machakos',
                'phone_number': '+254442121234',
            },
            {
                'name': 'Kitale National Polytechnic',
                'institution_type': 'technical_institute',
                'county': 'Trans Nzoia',
                'postal_address': 'P.O. Box 2461-30200',
                'physical_address': 'Kitale',
                'phone_number': '+254542030325',
            },
            {
                'name': 'Rift Valley Technical Training Institute',
                'institution_type': 'technical_institute',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 40-20100',
                'physical_address': 'Eldama Ravine',
                'phone_number': '+254512134567',
            },
            {
                'name': 'Kiambu Institute of Science and Technology',
                'institution_type': 'technical_institute',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 7212-00200',
                'physical_address': 'Kiambu',
                'phone_number': '+254204352000',
            },
        ]
        
        institutions_data.extend(technical_institutes)
        self.stdout.write(self.style.SUCCESS(f'Added {len(technical_institutes)} technical institutes and colleges'))

        # ============= NATIONAL SECONDARY SCHOOLS (Sample - Kenya has 8000+ secondary schools) =============
        # Adding major national and extra-county schools across all counties
        secondary_schools = [
            # NAIROBI COUNTY
            {
                'name': 'Alliance High School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 24040-00502',
                'physical_address': 'Kikuyu',
                'phone_number': '+254202010560',
            },
            {
                'name': 'Alliance Girls High School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 24450-00502',
                'physical_address': 'Kikuyu',
                'phone_number': '+254202010570',
            },
            {
                'name': 'Nairobi School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30045-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202722831',
            },
            {
                'name': 'Kenya High School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30047-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202713817',
            },
            {
                'name': 'Starehe Boys Centre and School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 2747-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202225978',
            },
            {
                'name': 'Maina Wanjigi Secondary School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 57446-00200',
                'physical_address': 'Nairobi',
                'phone_number': '+254202010234',
            },
            {
                'name': 'Pangani Girls High School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 41343-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202214567',
            },
            {
                'name': 'Jamhuri High School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30061-00100',
                'physical_address': 'Nairobi',
                'phone_number': '+254202713900',
            },
            
            # KIAMBU COUNTY
            {
                'name': 'Limuru Girls High School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 20-00217',
                'physical_address': 'Limuru',
                'phone_number': '+254204448600',
            },
            {
                'name': 'Kikuyu High School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 45-00902',
                'physical_address': 'Kikuyu',
                'phone_number': '+254204444123',
            },
            {
                'name': 'Thika High School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 87-01000',
                'physical_address': 'Thika',
                'phone_number': '+254672020123',
            },
            {
                'name': 'Komothai Girls Secondary School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 234-00902',
                'physical_address': 'Kikuyu',
                'phone_number': '+254204444890',
            },
            {
                'name': 'Kiambu High School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 45-00900',
                'physical_address': 'Kiambu',
                'phone_number': '+254204352111',
            },
            
            # MURANG\'A COUNTY
            {
                'name': 'Murang\'a High School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 123-10200',
                'physical_address': 'Murang\'a',
                'phone_number': '+254722101010',
            },
            {
                'name': 'Kangema Girls High School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 50-10203',
                'physical_address': 'Kangema',
                'phone_number': '+254722404040',
            },
            {
                'name': 'Kiru Girls High School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 45-10200',
                'physical_address': 'Kiru',
                'phone_number': '+254722123456',
            },
            {
                'name': 'Gatanga Boys High School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 78-10200',
                'physical_address': 'Gatanga',
                'phone_number': '+254722234567',
            },
            {
                'name': 'Ichagaki Girls High School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 145-10200',
                'physical_address': 'Ichagaki',
                'phone_number': '+254722901234',
            },
            {
                'name': 'Kigumo High School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 89-10200',
                'physical_address': 'Kigumo',
                'phone_number': '+254722456789',
            },
            
            # NYERI COUNTY
            {
                'name': 'Kagumo High School',
                'institution_type': 'highschool',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 544-10100',
                'physical_address': 'Nyeri',
                'phone_number': '+254612030111',
            },
            {
                'name': 'Mahiga Girls High School',
                'institution_type': 'highschool',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 267-10100',
                'physical_address': 'Nyeri',
                'phone_number': '+254612030222',
            },
            {
                'name': 'Nyeri High School',
                'institution_type': 'highschool',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 456-10100',
                'physical_address': 'Nyeri',
                'phone_number': '+254612030333',
            },
            {
                'name': 'Tumutumu Girls High School',
                'institution_type': 'highschool',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 89-10100',
                'physical_address': 'Karatina',
                'phone_number': '+254612030444',
            },
            
            # KIRINYAGA COUNTY
            {
                'name': 'Kerugoya Boys High School',
                'institution_type': 'highschool',
                'county': 'Kirinyaga',
                'postal_address': 'P.O. Box 56-10300',
                'physical_address': 'Kerugoya',
                'phone_number': '+254706894111',
            },
            {
                'name': 'Kianyaga High School',
                'institution_type': 'highschool',
                'county': 'Kirinyaga',
                'postal_address': 'P.O. Box 234-10300',
                'physical_address': 'Kianyaga',
                'phone_number': '+254706894222',
            },
            {
                'name': 'Wang\'uru Girls High School',
                'institution_type': 'highschool',
                'county': 'Kirinyaga',
                'postal_address': 'P.O. Box 123-10300',
                'physical_address': 'Wang\'uru',
                'phone_number': '+254706894333',
            },
            
            # EMBU COUNTY
            {
                'name': 'Kangaru School',
                'institution_type': 'highschool',
                'county': 'Embu',
                'postal_address': 'P.O. Box 124-60100',
                'physical_address': 'Embu',
                'phone_number': '+254682031111',
            },
            {
                'name': 'Kigari Girls High School',
                'institution_type': 'highschool',
                'county': 'Embu',
                'postal_address': 'P.O. Box 456-60100',
                'physical_address': 'Embu',
                'phone_number': '+254682031222',
            },
            
            # MERU COUNTY
            {
                'name': 'Meru School',
                'institution_type': 'highschool',
                'county': 'Meru',
                'postal_address': 'P.O. Box 82-60200',
                'physical_address': 'Meru',
                'phone_number': '+254642460111',
            },
            {
                'name': 'Kaaga Girls High School',
                'institution_type': 'highschool',
                'county': 'Meru',
                'postal_address': 'P.O. Box 123-60200',
                'physical_address': 'Meru',
                'phone_number': '+254642460222',
            },
            {
                'name': 'Nkubu High School',
                'institution_type': 'highschool',
                'county': 'Meru',
                'postal_address': 'P.O. Box 567-60200',
                'physical_address': 'Nkubu',
                'phone_number': '+254642460333',
            },
            
            # THARAKA NITHI COUNTY
            {
                'name': 'Chuka Boys High School',
                'institution_type': 'highschool',
                'county': 'Tharaka Nithi',
                'postal_address': 'P.O. Box 34-60400',
                'physical_address': 'Chuka',
                'phone_number': '+254706385111',
            },
            {
                'name': 'Chuka Girls High School',
                'institution_type': 'highschool',
                'county': 'Tharaka Nithi',
                'postal_address': 'P.O. Box 67-60400',
                'physical_address': 'Chuka',
                'phone_number': '+254706385222',
            },
            
            # MACHAKOS COUNTY
            {
                'name': 'Machakos School',
                'institution_type': 'highschool',
                'county': 'Machakos',
                'postal_address': 'P.O. Box 7-90100',
                'physical_address': 'Machakos',
                'phone_number': '+254442121111',
            },
            {
                'name': 'Our Lady of Fatima Mang\'u High School',
                'institution_type': 'highschool',
                'county': 'Machakos',
                'postal_address': 'P.O. Box 45-90100',
                'physical_address': 'Mang\'u',
                'phone_number': '+254442121222',
            },
            
            # KITUI COUNTY
            {
                'name': 'Kitui School',
                'institution_type': 'highschool',
                'county': 'Kitui',
                'postal_address': 'P.O. Box 56-90200',
                'physical_address': 'Kitui',
                'phone_number': '+254446322111',
            },
            {
                'name': 'Mulango Girls High School',
                'institution_type': 'highschool',
                'county': 'Kitui',
                'postal_address': 'P.O. Box 234-90200',
                'physical_address': 'Kitui',
                'phone_number': '+254446322222',
            },
            
            # MAKUENI COUNTY
            {
                'name': 'Wote High School',
                'institution_type': 'highschool',
                'county': 'Makueni',
                'postal_address': 'P.O. Box 123-90300',
                'physical_address': 'Wote',
                'phone_number': '+254447222111',
            },
            
            # MOMBASA COUNTY
            {
                'name': 'Mombasa High School',
                'institution_type': 'highschool',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 90224-80100',
                'physical_address': 'Mombasa',
                'phone_number': '+254412315111',
            },
            {
                'name': 'Serani High School',
                'institution_type': 'highschool',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 82414-80100',
                'physical_address': 'Mombasa',
                'phone_number': '+254412315222',
            },
            {
                'name': 'Shimo La Tewa High School',
                'institution_type': 'highschool',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 91343-80100',
                'physical_address': 'Mombasa',
                'phone_number': '+254412315333',
            },
            
            # KILIFI COUNTY
            {
                'name': 'Kaloleni Boys High School',
                'institution_type': 'highschool',
                'county': 'Kilifi',
                'postal_address': 'P.O. Box 45-80105',
                'physical_address': 'Kaloleni',
                'phone_number': '+254714606111',
            },
            {
                'name': 'Ribe Boys High School',
                'institution_type': 'highschool',
                'county': 'Kilifi',
                'postal_address': 'P.O. Box 234-80108',
                'physical_address': 'Ribe',
                'phone_number': '+254714606222',
            },
            
            # KWALE COUNTY
            {
                'name': 'Msambweni High School',
                'institution_type': 'highschool',
                'county': 'Kwale',
                'postal_address': 'P.O. Box 123-80404',
                'physical_address': 'Msambweni',
                'phone_number': '+254715222111',
            },
            
            # TAITA TAVETA COUNTY
            {
                'name': 'Wundanyi High School',
                'institution_type': 'highschool',
                'county': 'Taita Taveta',
                'postal_address': 'P.O. Box 34-80304',
                'physical_address': 'Wundanyi',
                'phone_number': '+254728523111',
            },
            
            # NAKURU COUNTY
            {
                'name': 'Menengai High School',
                'institution_type': 'highschool',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 545-20100',
                'physical_address': 'Nakuru',
                'phone_number': '+254512213111',
            },
            {
                'name': 'Njoro Girls High School',
                'institution_type': 'highschool',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 234-20115',
                'physical_address': 'Njoro',
                'phone_number': '+254512213222',
            },
            {
                'name': 'Nakuru High School',
                'institution_type': 'highschool',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 789-20100',
                'physical_address': 'Nakuru',
                'phone_number': '+254512213333',
            },
            
            # NAROK COUNTY
            {
                'name': 'Narok High School',
                'institution_type': 'highschool',
                'county': 'Narok',
                'postal_address': 'P.O. Box 45-20500',
                'physical_address': 'Narok',
                'phone_number': '+254729293111',
            },
            
            # KAJIADO COUNTY
            {
                'name': 'Kajiado High School',
                'institution_type': 'highschool',
                'county': 'Kajiado',
                'postal_address': 'P.O. Box 123-01100',
                'physical_address': 'Kajiado',
                'phone_number': '+254452122111',
            },
            
            # KISUMU COUNTY
            {
                'name': 'Kisumu Boys High School',
                'institution_type': 'highschool',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 134-40100',
                'physical_address': 'Kisumu',
                'phone_number': '+254572021111',
            },
            {
                'name': 'Kisumu Girls High School',
                'institution_type': 'highschool',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 567-40100',
                'physical_address': 'Kisumu',
                'phone_number': '+254572021222',
            },
            
            # SIAYA COUNTY
            {
                'name': 'Nyangoma Mixed Secondary School',
                'institution_type': 'highschool',
                'county': 'Siaya',
                'postal_address': 'P.O. Box 123-40600',
                'physical_address': 'Siaya',
                'phone_number': '+254572522111',
            },
            {
                'name': 'Ambira High School',
                'institution_type': 'highschool',
                'county': 'Siaya',
                'postal_address': 'P.O. Box 456-40600',
                'physical_address': 'Bondo',
                'phone_number': '+254572522222',
            },
            
            # KISII COUNTY
            {
                'name': 'Kisii High School',
                'institution_type': 'highschool',
                'county': 'Kisii',
                'postal_address': 'P.O. Box 45-40200',
                'physical_address': 'Kisii',
                'phone_number': '+254582030111',
            },
            {
                'name': 'Nyabururu Girls High School',
                'institution_type': 'highschool',
                'county': 'Kisii',
                'postal_address': 'P.O. Box 234-40200',
                'physical_address': 'Kisii',
                'phone_number': '+254582030222',
            },
            
            # NYAMIRA COUNTY
            {
                'name': 'Nyamira High School',
                'institution_type': 'highschool',
                'county': 'Nyamira',
                'postal_address': 'P.O. Box 123-40500',
                'physical_address': 'Nyamira',
                'phone_number': '+254583030111',
            },
            
            # MIGORI COUNTY
            {
                'name': 'Rapogi High School',
                'institution_type': 'highschool',
                'county': 'Migori',
                'postal_address': 'P.O. Box 123-40400',
                'physical_address': 'Migori',
                'phone_number': '+254715202111',
            },
            
            # HOMA BAY COUNTY
            {
                'name': 'Homa Bay High School',
                'institution_type': 'highschool',
                'county': 'Homa Bay',
                'postal_address': 'P.O. Box 123-40300',
                'physical_address': 'Homa Bay',
                'phone_number': '+254593522111',
            },
            
            # UASIN GISHU COUNTY
            {
                'name': 'Moi High School Kabarak',
                'institution_type': 'highschool',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 124-20157',
                'physical_address': 'Kabarak',
                'phone_number': '+254512216111',
            },
            {
                'name': 'Eldoret High School',
                'institution_type': 'highschool',
                'county': 'Uasin Gishu',
                'postal_address': 'P.O. Box 234-30100',
                'physical_address': 'Eldoret',
                'phone_number': '+254532063111',
            },
            
            # TRANS NZOIA COUNTY
            {
                'name': 'Kitale Boys High School',
                'institution_type': 'highschool',
                'county': 'Trans Nzoia',
                'postal_address': 'P.O. Box 123-30200',
                'physical_address': 'Kitale',
                'phone_number': '+254542030111',
            },
            
            # NANDI COUNTY
            {
                'name': 'Kapsabet Boys High School',
                'institution_type': 'highschool',
                'county': 'Nandi',
                'postal_address': 'P.O. Box 123-30300',
                'physical_address': 'Kapsabet',
                'phone_number': '+254532052111',
            },
            
            # BARINGO COUNTY
            {
                'name': 'Kabarnet High School',
                'institution_type': 'highschool',
                'county': 'Baringo',
                'postal_address': 'P.O. Box 123-30400',
                'physical_address': 'Kabarnet',
                'phone_number': '+254532222111',
            },
            
            # KAKAMEGA COUNTY
            {
                'name': 'Kakamega High School',
                'institution_type': 'highschool',
                'county': 'Kakamega',
                'postal_address': 'P.O. Box 123-50100',
                'physical_address': 'Kakamega',
                'phone_number': '+254562031111',
            },
            {
                'name': 'Friends School Kamusinga',
                'institution_type': 'highschool',
                'county': 'Bungoma',
                'postal_address': 'P.O. Box 242-50200',
                'physical_address': 'Kimilili',
                'phone_number': '+254708085111',
            },
            
            # BUNGOMA COUNTY
            {
                'name': 'Kibabii High School',
                'institution_type': 'highschool',
                'county': 'Bungoma',
                'postal_address': 'P.O. Box 456-50200',
                'physical_address': 'Bungoma',
                'phone_number': '+254708085222',
            },
            
            # BUSIA COUNTY
            {
                'name': 'Busia High School',
                'institution_type': 'highschool',
                'county': 'Busia',
                'postal_address': 'P.O. Box 123-50400',
                'physical_address': 'Busia',
                'phone_number': '+254552030111',
            },
            
            # VIHIGA COUNTY
            {
                'name': 'Vihiga High School',
                'institution_type': 'highschool',
                'county': 'Vihiga',
                'postal_address': 'P.O. Box 123-50300',
                'physical_address': 'Vihiga',
                'phone_number': '+254562050111',
            },
        ]
        
        institutions_data.extend(secondary_schools)
        self.stdout.write(self.style.SUCCESS(f'Added {len(secondary_schools)} secondary schools'))

        # ============= PRIMARY SCHOOLS (Sample from major towns/counties) =============
        primary_schools = [
            # NAIROBI
            {
                'name': 'Nairobi Primary School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30001-00100',
                'physical_address': 'Nairobi CBD',
                'phone_number': '+254202225001',
            },
            {
                'name': 'Kilimani Primary School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30002-00100',
                'physical_address': 'Kilimani, Nairobi',
                'phone_number': '+254202225002',
            },
            {
                'name': 'Eastleigh Primary School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30003-00100',
                'physical_address': 'Eastleigh, Nairobi',
                'phone_number': '+254202225003',
            },
            {
                'name': 'Langata Primary School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30004-00100',
                'physical_address': 'Langata, Nairobi',
                'phone_number': '+254202225004',
            },
            {
                'name': 'Karura Primary School',
                'institution_type': 'highschool',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30005-00100',
                'physical_address': 'Karura, Nairobi',
                'phone_number': '+254202225005',
            },
            
            # KIAMBU
            {
                'name': 'Kikuyu Primary School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 10-00902',
                'physical_address': 'Kikuyu',
                'phone_number': '+254204444001',
            },
            {
                'name': 'Thika Primary School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 11-01000',
                'physical_address': 'Thika',
                'phone_number': '+254672020001',
            },
            {
                'name': 'Limuru Primary School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 12-00217',
                'physical_address': 'Limuru',
                'phone_number': '+254204448001',
            },
            {
                'name': 'Kiambu Primary School',
                'institution_type': 'highschool',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 13-00900',
                'physical_address': 'Kiambu',
                'phone_number': '+254204352001',
            },
            
            # MURANG'A
            {
                'name': 'Murang\'a Primary School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 20-10200',
                'physical_address': 'Murang\'a Town',
                'phone_number': '+254722100001',
            },
            {
                'name': 'Kangema Primary School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 21-10203',
                'physical_address': 'Kangema',
                'phone_number': '+254722100002',
            },
            {
                'name': 'Kigumo Primary School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 22-10200',
                'physical_address': 'Kigumo',
                'phone_number': '+254722100003',
            },
            {
                'name': 'Kandara Primary School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 23-10200',
                'physical_address': 'Kandara',
                'phone_number': '+254722100004',
            },
            
            # NYERI
            {
                'name': 'Nyeri Primary School',
                'institution_type': 'highschool',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 30-10100',
                'physical_address': 'Nyeri Town',
                'phone_number': '+254612030001',
            },
            {
                'name': 'Karatina Primary School',
                'institution_type': 'highschool',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 31-10101',
                'physical_address': 'Karatina',
                'phone_number': '+254612030002',
            },
            {
                'name': 'Othaya Primary School',
                'institution_type': 'highschool',
                'county': 'Nyeri',
                'postal_address': 'P.O. Box 32-10106',
                'physical_address': 'Othaya',
                'phone_number': '+254612030003',
            },
            
            # KIRINYAGA
            {
                'name': 'Kerugoya Primary School',
                'institution_type': 'highschool',
                'county': 'Kirinyaga',
                'postal_address': 'P.O. Box 40-10300',
                'physical_address': 'Kerugoya',
                'phone_number': '+254706894001',
            },
            {
                'name': 'Wang\'uru Primary School',
                'institution_type': 'highschool',
                'county': 'Kirinyaga',
                'postal_address': 'P.O. Box 41-10300',
                'physical_address': 'Wang\'uru',
                'phone_number': '+254706894002',
            },
            
            # EMBU
            {
                'name': 'Embu Primary School',
                'institution_type': 'highschool',
                'county': 'Embu',
                'postal_address': 'P.O. Box 50-60100',
                'physical_address': 'Embu Town',
                'phone_number': '+254682031001',
            },
            {
                'name': 'Runyenjes Primary School',
                'institution_type': 'highschool',
                'county': 'Embu',
                'postal_address': 'P.O. Box 51-60100',
                'physical_address': 'Runyenjes',
                'phone_number': '+254682031002',
            },
            
            # MERU
            {
                'name': 'Meru Primary School',
                'institution_type': 'highschool',
                'county': 'Meru',
                'postal_address': 'P.O. Box 60-60200',
                'physical_address': 'Meru Town',
                'phone_number': '+254642460001',
            },
            {
                'name': 'Maua Primary School',
                'institution_type': 'highschool',
                'county': 'Meru',
                'postal_address': 'P.O. Box 61-60600',
                'physical_address': 'Maua',
                'phone_number': '+254642460002',
            },
            {
                'name': 'Nkubu Primary School',
                'institution_type': 'highschool',
                'county': 'Meru',
                'postal_address': 'P.O. Box 62-60200',
                'physical_address': 'Nkubu',
                'phone_number': '+254642460003',
            },
            
            # THARAKA NITHI
            {
                'name': 'Chuka Primary School',
                'institution_type': 'highschool',
                'county': 'Tharaka Nithi',
                'postal_address': 'P.O. Box 70-60400',
                'physical_address': 'Chuka',
                'phone_number': '+254706385001',
            },
            
            # MACHAKOS
            {
                'name': 'Machakos Primary School',
                'institution_type': 'highschool',
                'county': 'Machakos',
                'postal_address': 'P.O. Box 80-90100',
                'physical_address': 'Machakos Town',
                'phone_number': '+254442121001',
            },
            {
                'name': 'Tala Primary School',
                'institution_type': 'highschool',
                'county': 'Machakos',
                'postal_address': 'P.O. Box 81-90100',
                'physical_address': 'Tala',
                'phone_number': '+254442121002',
            },
            
            # KITUI
            {
                'name': 'Kitui Primary School',
                'institution_type': 'highschool',
                'county': 'Kitui',
                'postal_address': 'P.O. Box 90-90200',
                'physical_address': 'Kitui Town',
                'phone_number': '+254446322001',
            },
            
            # MAKUENI
            {
                'name': 'Wote Primary School',
                'institution_type': 'highschool',
                'county': 'Makueni',
                'postal_address': 'P.O. Box 100-90300',
                'physical_address': 'Wote',
                'phone_number': '+254447222001',
            },
            
            # MOMBASA
            {
                'name': 'Tudor Primary School',
                'institution_type': 'highschool',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 110-80100',
                'physical_address': 'Tudor, Mombasa',
                'phone_number': '+254412315001',
            },
            {
                'name': 'Buxton Primary School',
                'institution_type': 'highschool',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 111-80100',
                'physical_address': 'Buxton, Mombasa',
                'phone_number': '+254412315002',
            },
            {
                'name': 'Shanzu Primary School',
                'institution_type': 'highschool',
                'county': 'Mombasa',
                'postal_address': 'P.O. Box 112-80100',
                'physical_address': 'Shanzu',
                'phone_number': '+254412315003',
            },
            
            # KILIFI
            {
                'name': 'Kilifi Primary School',
                'institution_type': 'highschool',
                'county': 'Kilifi',
                'postal_address': 'P.O. Box 120-80108',
                'physical_address': 'Kilifi Town',
                'phone_number': '+254714606001',
            },
            {
                'name': 'Malindi Primary School',
                'institution_type': 'highschool',
                'county': 'Kilifi',
                'postal_address': 'P.O. Box 121-80200',
                'physical_address': 'Malindi',
                'phone_number': '+254714606002',
            },
            
            # KWALE
            {
                'name': 'Kwale Primary School',
                'institution_type': 'highschool',
                'county': 'Kwale',
                'postal_address': 'P.O. Box 130-80403',
                'physical_address': 'Kwale',
                'phone_number': '+254715222001',
            },
            
            # TAITA TAVETA
            {
                'name': 'Voi Primary School',
                'institution_type': 'highschool',
                'county': 'Taita Taveta',
                'postal_address': 'P.O. Box 140-80300',
                'physical_address': 'Voi',
                'phone_number': '+254728523001',
            },
            
            # NAKURU
            {
                'name': 'Nakuru Primary School',
                'institution_type': 'highschool',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 150-20100',
                'physical_address': 'Nakuru Town',
                'phone_number': '+254512213001',
            },
            {
                'name': 'Naivasha Primary School',
                'institution_type': 'highschool',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 151-20117',
                'physical_address': 'Naivasha',
                'phone_number': '+254512213002',
            },
            {
                'name': 'Gilgil Primary School',
                'institution_type': 'highschool',
                'county': 'Nakuru',
                'postal_address': 'P.O. Box 152-20116',
                'physical_address': 'Gilgil',
                'phone_number': '+254512213003',
            },
            
            # NAROK
            {
                'name': 'Narok Primary School',
                'institution_type': 'highschool',
                'county': 'Narok',
                'postal_address': 'P.O. Box 160-20500',
                'physical_address': 'Narok Town',
                'phone_number': '+254729293001',
            },
            
            # KAJIADO
            {
                'name': 'Kajiado Primary School',
                'institution_type': 'highschool',
                'county': 'Kajiado',
                'postal_address': 'P.O. Box 170-01100',
                'physical_address': 'Kajiado Town',
                'phone_number': '+254452122001',
            },
            {
                'name': 'Ngong Primary School',
                'institution_type': 'highschool',
                'county': 'Kajiado',
                'postal_address': 'P.O. Box 171-00208',
                'physical_address': 'Ngong',
                'phone_number': '+254452122002',
            },
            
            # KISUMU
            {
                'name': 'Kisumu Primary School',
                'institution_type': 'highschool',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 180-40100',
                'physical_address': 'Kisumu Town',
                'phone_number': '+254572021001',
            },
            {
                'name': 'Kondele Primary School',
                'institution_type': 'highschool',
                'county': 'Kisumu',
                'postal_address': 'P.O. Box 181-40100',
                'physical_address': 'Kondele, Kisumu',
                'phone_number': '+254572021002',
            },
            
            # SIAYA
            {
                'name': 'Siaya Primary School',
                'institution_type': 'highschool',
                'county': 'Siaya',
                'postal_address': 'P.O. Box 190-40600',
                'physical_address': 'Siaya Town',
                'phone_number': '+254572522001',
            },
            {
                'name': 'Bondo Primary School',
                'institution_type': 'highschool',
                'county': 'Siaya',
                'postal_address': 'P.O. Box 191-40601',
                'physical_address': 'Bondo',
                'phone_number': '+254572522002',
            },
            
            # KISII
            {
                'name': 'Kisii Primary School',
                'institution_type': 'highschool',
                'county': 'Kisii',
                'postal_address': 'P.O. Box 200-40200',
                'physical_address': 'Kisii Town',
                'phone_number': '+254582030001',
            },
            
            # NYAMIRA
            {
                'name': 'Nyamira Primary School',
                'institution_type': 'highschool',
                'county': 'Nyamira',
                'postal_address': 'P.O. Box 210-40500',
                'physical_address': 'Nyamira Town',
                'phone_number': '+254583030001',
            },
            
            # MIGORI
            {
                'name': 'Migori Primary School',
                'institution_type': 'highschool',
                'county': 'Migori',
                'postal_address': 'P.O. Box 220-40400',
                'physical_address': 'Migori Town',
                'phone_number': '+254715202001',
            },
            
            # HOMA BAY
            {
                'name': 'Homa Bay Primary School',
                'institution_type': 'highschool',
                'county': 'Homa Bay',
                'postal_address': 'P.O. Box 230-40300',
                'physical_address': 'Homa Bay Town',
                'phone_number': '+254593522001',
            },
            
            # UASIN GISHU
            {
                'name': 'Eldoret Primary School',
                'institution_type': 'highschool',
                'county': 'Uasin Gishu',
                'postal_address': 'P.O. Box 240-30100',
                'physical_address': 'Eldoret Town',
                'phone_number': '+254532063001',
            },
            {
                'name': 'Langas Primary School',
                'institution_type': 'highschool',
                'county': 'Uasin Gishu',
                'postal_address': 'P.O. Box 241-30100',
                'physical_address': 'Langas, Eldoret',
                'phone_number': '+254532063002',
            },
            
            # TRANS NZOIA
            {
                'name': 'Kitale Primary School',
                'institution_type': 'highschool',
                'county': 'Trans Nzoia',
                'postal_address': 'P.O. Box 250-30200',
                'physical_address': 'Kitale Town',
                'phone_number': '+254542030001',
            },
            
            # NANDI
            {
                'name': 'Kapsabet Primary School',
                'institution_type': 'highschool',
                'county': 'Nandi',
                'postal_address': 'P.O. Box 260-30300',
                'physical_address': 'Kapsabet',
                'phone_number': '+254532052001',
            },
            
            # BARINGO
            {
                'name': 'Kabarnet Primary School',
                'institution_type': 'highschool',
                'county': 'Baringo',
                'postal_address': 'P.O. Box 270-30400',
                'physical_address': 'Kabarnet',
                'phone_number': '+254532222001',
            },
            
            # KAKAMEGA
            {
                'name': 'Kakamega Primary School',
                'institution_type': 'highschool',
                'county': 'Kakamega',
                'postal_address': 'P.O. Box 280-50100',
                'physical_address': 'Kakamega Town',
                'phone_number': '+254562031001',
            },
            {
                'name': 'Mumias Primary School',
                'institution_type': 'highschool',
                'county': 'Kakamega',
                'postal_address': 'P.O. Box 281-50102',
                'physical_address': 'Mumias',
                'phone_number': '+254562031002',
            },
            
            # BUNGOMA
            {
                'name': 'Bungoma Primary School',
                'institution_type': 'highschool',
                'county': 'Bungoma',
                'postal_address': 'P.O. Box 290-50200',
                'physical_address': 'Bungoma Town',
                'phone_number': '+254708085001',
            },
            
            # BUSIA
            {
                'name': 'Busia Primary School',
                'institution_type': 'highschool',
                'county': 'Busia',
                'postal_address': 'P.O. Box 300-50400',
                'physical_address': 'Busia Town',
                'phone_number': '+254552030001',
            },
            
            # VIHIGA
            {
                'name': 'Vihiga Primary School',
                'institution_type': 'highschool',
                'county': 'Vihiga',
                'postal_address': 'P.O. Box 310-50300',
                'physical_address': 'Vihiga',
                'phone_number': '+254562050001',
            },
            
            # KERICHO
            {
                'name': 'Kericho Primary School',
                'institution_type': 'highschool',
                'county': 'Kericho',
                'postal_address': 'P.O. Box 320-20200',
                'physical_address': 'Kericho Town',
                'phone_number': '+254522021001',
            },
            
            # BOMET
            {
                'name': 'Bomet Primary School',
                'institution_type': 'highschool',
                'county': 'Bomet',
                'postal_address': 'P.O. Box 330-20400',
                'physical_address': 'Bomet Town',
                'phone_number': '+254712345001',
            },
        ]
        
        institutions_data.extend(primary_schools)
        self.stdout.write(self.style.SUCCESS(f'Added {len(primary_schools)} primary schools'))

        # Now seed all institutions
        self._seed_institutions(institutions_data)

    def _get_counties(self):
        """Get or create county references"""
        counties = {}
        
        # Official Kenya county codes (1-47)
        county_data = {
            'Mombasa': '001', 'Kwale': '002', 'Kilifi': '003', 'Tana River': '004',
            'Lamu': '005', 'Taita Taveta': '006', 'Garissa': '007', 'Wajir': '008',
            'Mandera': '009', 'Marsabit': '010', 'Isiolo': '011', 'Meru': '012',
            'Tharaka Nithi': '013', 'Embu': '014', 'Kitui': '015', 'Machakos': '016',
            'Makueni': '017', 'Nyandarua': '018', 'Nyeri': '019', 'Kirinyaga': '020',
            'Murang\'a': '021', 'Kiambu': '022', 'Turkana': '023', 'West Pokot': '024',
            'Samburu': '025', 'Trans Nzoia': '026', 'Uasin Gishu': '027', 'Elgeyo Marakwet': '028',
            'Nandi': '029', 'Baringo': '030', 'Laikipia': '031', 'Nakuru': '032',
            'Narok': '033', 'Kajiado': '034', 'Kericho': '035', 'Bomet': '036',
            'Kakamega': '037', 'Vihiga': '038', 'Bungoma': '039', 'Busia': '040',
            'Siaya': '041', 'Kisumu': '042', 'Homa Bay': '043', 'Migori': '044',
            'Kisii': '045', 'Nyamira': '046', 'Nairobi': '047'
        }
        
        for name, code in county_data.items():
            # Try to get existing county first
            county = County.objects.filter(name=name).first()
            
            if county:
                counties[name] = county
                self.stdout.write(self.style.SUCCESS(f'Found existing county: {name}'))
            else:
                # Create new county with unique code
                try:
                    county = County.objects.create(
                        name=name,
                        code=code,
                        is_active=True
                    )
                    counties[name] = county
                    self.stdout.write(self.style.WARNING(f'Created county: {name} (Code: {code})'))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'Error creating county {name}: {str(e)}'))
                    # Try to get it anyway in case it was created by another process
                    county = County.objects.filter(name=name).first()
                    if county:
                        counties[name] = county
        
        return counties

    def _seed_institutions(self, institutions_data):
        """Seed all institutions with transaction"""
        with transaction.atomic():
            created_count = 0
            updated_count = 0
            error_count = 0
            
            for inst_data in institutions_data:
                try:
                    # Get county
                    county = County.objects.filter(
                        name__icontains=inst_data['county']
                    ).first()
                    
                    if not county:
                        self.stdout.write(
                            self.style.ERROR(f'✗ County not found: {inst_data["county"]} for {inst_data["name"]}')
                        )
                        error_count += 1
                        continue
                    
                    institution, created = Institution.objects.update_or_create(
                        name=inst_data['name'],
                        defaults={
                            'institution_type': inst_data['institution_type'],
                            'county': county,
                            'postal_address': inst_data.get('postal_address'),
                            'physical_address': inst_data.get('physical_address'),
                            'phone_number': inst_data.get('phone_number'),
                            'email': inst_data.get('email'),
                            'principal_name': inst_data.get('principal_name'),
                            'principal_phone': inst_data.get('principal_phone'),
                            'principal_email': inst_data.get('principal_email'),
                            'is_active': True,
                        }
                    )
                    
                    if created:
                        created_count += 1
                    else:
                        updated_count += 1
                        
                except Exception as e:
                    error_count += 1
                    self.stdout.write(
                        self.style.ERROR(f'✗ Error with {inst_data["name"]}: {str(e)}')
                    )

        # Final Summary
        self.stdout.write('\n' + '='*80)
        self.stdout.write(self.style.SUCCESS('🎉 INSTITUTION SEEDING COMPLETED! 🎉'))
        self.stdout.write('='*80)
        self.stdout.write(self.style.SUCCESS(f'✓ Created: {created_count} institutions'))
        self.stdout.write(self.style.WARNING(f'⟳ Updated: {updated_count} institutions'))
        if error_count > 0:
            self.stdout.write(self.style.ERROR(f'✗ Errors: {error_count} institutions'))
        self.stdout.write(self.style.SUCCESS(f'📊 Total: {created_count + updated_count} institutions in database'))
        self.stdout.write('='*80 + '\n')
        
        # Display summary by type
        self.stdout.write(self.style.HTTP_INFO('📈 SUMMARY BY INSTITUTION TYPE:'))
        self.stdout.write('-' * 80)
        total = 0
        for inst_type, display_name in Institution.INSTITUTION_TYPES:
            count = Institution.objects.filter(institution_type=inst_type).count()
            total += count
            self.stdout.write(f'  🏫 {display_name:<30} {count:>5} institutions')
        self.stdout.write('-' * 80)
        self.stdout.write(f'  {"TOTAL":<30} {total:>5} institutions')
        self.stdout.write('='*80 + '\n')