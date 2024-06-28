from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    model = CustomUser

    search_fields = ['email', 'username', 'first_name']
    ordering = ['date_joined']
    list_display = ['email', 'username', 'first_name', 'is_active', 'is_staff']

    fieldsets = [
        ['Info', {'fields': ['email', 'username', 'first_name', 'last_name', 'phone_number', 'date_joined', 'password']}],
        ['Permissions', {'fields': ['is_active', 'is_staff', 'is_superuser']}]
    ]

    add_fieldsets = [
        ['Info', {'fields': ['email', 'username', 'password1', 'password2', 'first_name', 'last_name', 'phone_number']}],
        ['Permissions', {'fields': ['is_active', 'is_staff', 'is_superuser']}]
    ]

admin.site.register(CustomUser, CustomUserAdmin)
