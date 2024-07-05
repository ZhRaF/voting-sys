from django.db import models
from django.contrib.auth.models import AbstractUser, Group
from django.db import models

class NormalUser(AbstractUser):
    points = models.PositiveIntegerField(default=0)  
    groups = models.ManyToManyField(
        Group,
        related_name='normal_users',  # Custom related name
        blank=True,
        verbose_name='groups',
    )

    def __str__(self):
        return self.username