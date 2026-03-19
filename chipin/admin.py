from django.contrib import admin
from .models import Group, Invite

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ("name", "admin")