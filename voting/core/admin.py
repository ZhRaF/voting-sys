from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import NormalUser

class CustomUserAdmin(UserAdmin):
    model = NormalUser
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('points',)}),
    )
    list_display = ['username', 'email', 'first_name', 'last_name', 'is_staff', 'points']

admin.site.register(NormalUser, CustomUserAdmin)

