"""
URL configuration for theshoppingai project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from auths.views import *

urlpatterns = [
    path('admin/', admin.site.urls),

    path('api/register/', UserRegistrationView.as_view(), name='api-register'),              
    # path('api/verification/', UserEmailVerificationView.as_view(), name='api-verification'), 
    # path('api/resendotp/', ResendOTPView.as_view(), name='api-resendotp'),                   # From Keywordlit Project
    path('api/login/', UserLoginView.as_view(), name='api-login'),              
    path('api/admin/get-insta-accounts/', AdminGetInstaAccounts.as_view(), name='admin-AdminGetInstaAccounts'),            
    path('api/admin/delete-user/', AdminDeleteUser.as_view(), name='admin-AdminDeleteUser'),                    
    path('api/admin/modify-user/', AdminModifyUser.as_view(), name='admin-AdminModifyUser'),   


    path('api/get-insta-account/', GetInstagramAccounts.as_view(), name='api-GetInstagramAccounts'), 
    path('api/add-insta-account/', AddInstagramAccount.as_view(), name='api-AddInstagramAccount'), 
    path('api/edit-insta-account/', EditInstagramAccount.as_view(), name='api-EditInstagramAccount'), 
    path('api/delete-insta-account/', DeleteInstagramAccount.as_view(), name='api-DeleteInstagramAccount'), 


    path('api/modify-user/', UserModifyView.as_view(), name='api-UserModifyView'), 
]
