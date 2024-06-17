from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Create a superuser if it does not exist'

    def handle(self, *args, **kwargs):
        User = get_user_model()
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser('admin', 'admin@admin.com', 'admin')
            self.stdout.write(self.style.SUCCESS('Successfully created superuser'))
        else:
            self.stdout.write(self.style.WARNING('Superuser already exists'))
