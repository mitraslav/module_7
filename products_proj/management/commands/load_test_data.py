from django.core.management.base import BaseCommand
from django.core import management
from products_proj.models import Product, Category

class Command(BaseCommand):
    help = 'Load test data: clear DB and load fixtures'

    def handle(self, *args, **options):
        self.stdout.write('Deleting existing Products and Categories...')
        Product.objects.all().delete()
        Category.objects.all().delete()

        self.stdout.write('Loading categories fixture...')
        management.call_command('loaddata', 'products_proj.json', verbosity=1)

        self.stdout.write(self.style.SUCCESS('Test data loaded successfully.'))