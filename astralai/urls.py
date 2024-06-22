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
    path('api/profile/', UserProfileView.as_view(), name='api-UserProfileView'),              
    
    path('api/admin/get-insta-accounts/', AdminGetInstaAccounts.as_view(), name='admin-AdminGetInstaAccounts'),     

    path('api/admin/edit-insta-accounts/', AdminEditInstaAccounts.as_view(), name='admin-AdminEditInstaAccounts'),  
    path('api/admin/delete-insta-accounts/', AdminDeleteInstaAccounts.as_view(), name='admin-AdminDeleteInstaAccounts'),  

    path('api/admin/delete-user/', AdminDeleteUser.as_view(), name='admin-AdminDeleteUser'),                    
    path('api/admin/modify-user/', AdminModifyUser.as_view(), name='admin-AdminModifyUser'),   
    path('api/admin/view-user/', AdminViewUsers.as_view(), name='admin-AdminViewUsers'),

    path('api/admin/view-all-users/', AdminViewAllUsers.as_view(), name='admin-AdminViewAllUsers'),

    path('api/admin/analytics/', AdminAnalytics.as_view(), name='admin-AdminAnalytics'),


    path('api/get-insta-account/', GetInstagramAccounts.as_view(), name='api-GetInstagramAccounts'), 
    path('api/add-insta-account/', AddInstagramAccount.as_view(), name='api-AddInstagramAccount'), 
    path('api/edit-insta-account/', EditInstagramAccount.as_view(), name='api-EditInstagramAccount'), 
    path('api/delete-insta-account/', DeleteInstagramAccount.as_view(), name='api-DeleteInstagramAccount'), 


    path('api/modify-user/', UserModifyView.as_view(), name='api-UserModifyView'), 

#---------------------------------------LEAD and CSV urls-----------------------------------------------------------------
    path('api/save-lead-data/', SaveLeadData.as_view(), name='api-SaveLeadData'), 

    path('api/delete-lead-data/', DeleteLeadCSV.as_view(), name='api-DeleteLeadCSV'), 

    path('api/delete-lead-id/', DeleteLeadViaId.as_view(), name='api-DeleteLeadViaId'), 

    path('api/edit-lead-id/', EditLeadViaId.as_view(), name='api-EditLeadViaId'), 

    path('api/get-lead-data/', GetLeaddata.as_view(), name='api-GetLeaddata'), 

#---------------------------------------LEAD and CSV urls-----------------------------------------------------------------

    path('api/add-message-template/', AddMessageTemplate.as_view(), name='api-AddMessageTemplate'),  

    path('api/get-message-template/', GetMessageTemplate.as_view(), name='api-GetMessageTemplate'),  


    path('api/get-message/', GetMessage.as_view(), name='api-GetMessage'), 

    path('api/get-message-time/', GetMessagewithtime.as_view(), name='api-GetMessagewithtime'),  

    path('api/insta_messages/', InstagramBotView.as_view(), name='api-InstagramBotView'),

    path('api/add-message/', AddMessage.as_view(), name='api-AddMessage'), 

    path('api/delete-message/', deleteMessage.as_view(), name='api-deleteMessage'), 

    path('api/single-insta-messages/', SingleInstaMessageView.as_view(), name='api-SingleInstaMessageView'),

    path('api/task_status/', TaskStatusView.as_view(), name='api-TaskStatusView'),

]
