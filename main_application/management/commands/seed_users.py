from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import random

User = get_user_model()

class Command(BaseCommand):
    help = "Seed system users with Kenyan data (excluding admin)"

    def handle(self, *args, **kwargs):
        users_data = [
            # Applicants
            {
                "username": "brian.otieno",
                "first_name": "Brian",
                "last_name": "Otieno",
                "email": "brian.otieno@gmail.com",
                "user_type": "applicant",
                "id_number": "34567890",
                "phone_number": "+254712345678",
            },
            {
                "username": "faith.wanjiku",
                "first_name": "Faith",
                "last_name": "Wanjiku",
                "email": "faith.wanjiku@gmail.com",
                "user_type": "applicant",
                "id_number": "29876543",
                "phone_number": "+254701234567",
            },

            # Reviewers
            {
                "username": "samuel.kiptoo",
                "first_name": "Samuel",
                "last_name": "Kiptoo",
                "email": "samuel.kiptoo@county.go.ke",
                "user_type": "reviewer",
                "id_number": "25678901",
                "phone_number": "+254722111333",
            },

            # Finance Officers
            {
                "username": "grace.njeri",
                "first_name": "Grace",
                "last_name": "Njeri",
                "email": "grace.njeri@county.go.ke",
                "user_type": "finance",
                "id_number": "31245678",
                "phone_number": "+254733444555",
            },

            # County Admin
            {
                "username": "james.mutua",
                "first_name": "James",
                "last_name": "Mutua",
                "email": "james.mutua@county.go.ke",
                "user_type": "county_admin",
                "id_number": "22334455",
                "phone_number": "+254711999888",
            },

            # Constituency Admin
            {
                "username": "alice.mwikali",
                "first_name": "Alice",
                "last_name": "Mwikali",
                "email": "alice.mwikali@county.go.ke",
                "user_type": "constituency_admin",
                "id_number": "33445566",
                "phone_number": "+254740123456",
            },

            # Ward Admin
            {
                "username": "peter.ndungu",
                "first_name": "Peter",
                "last_name": "Ndungu",
                "email": "peter.ndungu@county.go.ke",
                "user_type": "ward_admin",
                "id_number": "44556677",
                "phone_number": "+254790654321",
            },
        ]

        created = 0

        for data in users_data:
            if User.objects.filter(username=data["username"]).exists():
                self.stdout.write(
                    self.style.WARNING(f"User {data['username']} already exists, skipping.")
                )
                continue

            user = User.objects.create_user(
                username=data["username"],
                email=data["email"],
                password="password123",
                first_name=data["first_name"],
                last_name=data["last_name"],
                user_type=data["user_type"],
                id_number=data["id_number"],
                phone_number=data["phone_number"],
                is_active=True,
            )

            created += 1
            self.stdout.write(
                self.style.SUCCESS(f"Created user: {user.username} ({user.user_type})")
            )

        self.stdout.write(self.style.SUCCESS(f"\n✅ Done. {created} users created successfully."))
