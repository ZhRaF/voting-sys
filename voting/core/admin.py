from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *

admin.site.register(Election)
admin.site.register(Vote)
admin.site.register(Candidate)