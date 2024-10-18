from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator


CATEGORY_CHOICES = [
    ("ELC", "Electronics"),
    ("CLT", "Clothing"),
    ("TYS", "Toys"),
    ("HOM", "Home"),
    ("GRD", "Gardening"),
    ("MSI", "Musical instruments"),
    ("NON", "Other")
]


class Users(AbstractUser):
    id = models.AutoField(primary_key=True)

class Product(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=64, unique=True, blank=False, null=False)
    description = models.TextField()
    price = models.IntegerField(validators=[MinValueValidator(1)])
    image = models.URLField(blank=True)
    created_at = models.DateTimeField()
    stock_quantity = models.IntegerField(validators=[MinValueValidator(1)])
    category = models.CharField(max_length=64, choices=CATEGORY_CHOICES, default='NON')