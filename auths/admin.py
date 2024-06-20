from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
from .forms import CustomUserCreationForm, CustomUserChangeForm
# Register your models here.


class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser
    # list_display = ["email", "username", 'is_user_verified', 'credit']
    list_display = ["id", "email", "name",'created', 'updated']
    # def user_credit(self, obj):
    #         return str(obj.user.profile_photo)
    # user_credit.short_description = 'Profile Photo'  # Customize the column header

class instagram_accountsAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'password', 'created', 'updated']

class LeadAdmin(admin.ModelAdmin):
    list_display = ['id', 'instagram_account', 'name', 'username', 'status', 'csv_file_number', 'updated']

class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'recipient', 'instagram_account', 'content', 'scheduled_time', 'sent', 'sent_time']

class MessageTemplateAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'template_name']


admin.site.register(Lead,LeadAdmin)
admin.site.register(Message,MessageAdmin)
admin.site.register(MessageTemplate,MessageTemplateAdmin)


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(instagram_accounts, instagram_accountsAdmin)