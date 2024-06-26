from django.shortcuts import render
from .models import *
from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from rest_framework.response import Response
from .email import send_otp_via_email
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import generate_random_string, get_user_id_from_token
from .serializers import  UserChangePasswordSerializer, UserLoginSerializer, UserProfileSerializer, UserRegistrationSerializer, UserChangePasswordSerializer, UserModifyPasswordSerializer
from rest_framework.permissions import BasePermission, IsAuthenticated, AllowAny
from .renderers import UserRenderer
from django.views import View
from django.http import JsonResponse, HttpResponse
import os
from django.conf import settings
import pytz
import random
from datetime import datetime, timedelta
from django.utils import timezone
import json

# Create your views here.




def IsSuperUser(user_id):
    user = CustomUser.objects.filter(id=user_id)
    if not user : return False, False
    user = user.first()
    return user , user.is_superuser
    
def get_or_createToken(request):
    """ 
    Create a user access token for already logged in user
    """
    if request.user.is_authenticated  :
        user = CustomUser.objects.get(email = request.user.email)
        token = get_tokens_for_user(user)
        request.session['access_token'] = token['access']
        return request.session['access_token']
    else:
        return False

def get_tokens_for_user(user):
    """ 
    Get a token access for already logged in user.
    """
    refresh = RefreshToken.for_user(user)
    return {
        # 'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
      


class UserRegistrationView(APIView):
    """ 
    An API view for user registration and return error if there is any error or insufficient data provided
    """
    renderer_classes = [UserRenderer]
    
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user_Admin, is_superuser = IsSuperUser(user_id)
        if not user_Admin or not is_superuser:
            msg = 'could not found the Admin user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        if not 'username' in request.data:
            while True:
                generated_random_username = generate_random_string(15)
                if CustomUser.objects.filter(username=generated_random_username).count() == 0:
                    request.data['username'] = generated_random_username
                    break

        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not request.data.get('email'):
            return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not request.data.get('password'):
            return Response({'Message': 'password field is required'}, status=status.HTTP_400_BAD_REQUEST)

        is_superuser = request.data.get('isAdmin', False)
        if is_superuser:
            user = CustomUser.objects.create_superuser(**serializer.validated_data)
            # user.is_user_verified = True  # ALL superuser are verified
            user.save()
            return Response({"email": 'Email is verified', 'Message': 'Admin user Created'},
                        status=status.HTTP_201_CREATED)
        
        else:
            user = serializer.save()
            user.save()

            return Response({"email": f'{user.email}', 'Message': ' User Created Successfully'},
                            status=status.HTTP_201_CREATED)



class AdminDeleteUser(APIView):
    """ 
    Delete-user if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_deleted = False

        if 'email' not in request.data or not request.data.get('email'):
            return Response({'Message' : 'could not got the user, Please provide email'}, status=status.HTTP_204_NO_CONTENT)
        
        delete_user_email =request.data['email']
        delete_user = CustomUser.objects.filter(email=delete_user_email).first()  

        if not delete_user:
            msg = 'User not in record!!'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        # delete_user.delete()
        if delete_user.delete() :
            user_deleted = True
            return Response({'Message' : 'successfully got the user deleted', 'user_deleted' : user_deleted}, status=status.HTTP_200_OK) 
        
        return Response({'Message' : 'could not delete the user', 'user_deleted' : user_deleted}, status=status.HTTP_400_BAD_REQUEST)
 

class AdminModifyUser(APIView):
    """ 
    Modify user details if the token belongs to a superuser.
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        
        if not user or not is_superuser:
            return Response({"Message": "Superuser not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        if 'email' not in request.data or not request.data.get('email'):
            return Response({'Message': 'Email not provided. Please provide an email.'}, status=status.HTTP_400_BAD_REQUEST)

        user_modified_email = request.data['email']
        new_name = request.data.get('new_name')
        new_password = request.data.get('new_password')

        if not new_name and not new_password:
            return Response({'Message': 'No details to modify. Please provide a new name or new password.'}, status=status.HTTP_400_BAD_REQUEST)

        try: 

            user_modified = CustomUser.objects.filter(email=user_modified_email).first()

            if not user_modified:
                return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            if new_name:
                user_modified.name = new_name
            if new_password:
                user_modified.set_password(new_password)

            user_modified.save()
            return Response({'Message': 'User details successfully updated', 'user_modified_status': True}, status=status.HTTP_200_OK)
        except Exception as  e:
            return Response({'Message': f'User details update Failed: {str(e)}', 'user_modified_status': False}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class UserLoginView(APIView):
    """ 
    send an username and exist user's password to get user's accesstoken.
    """
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        #user = CustomUser.objects.get(email = email)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # If the email is not found in records, return a 404 NotFound response
            return Response({'Message': 'Email not in record. Register First!'}, status=status.HTTP_404_NOT_FOUND)
        
            # user.check_password(password) 
        if user.check_password(password)  :
            token = get_tokens_for_user(user)
            user, is_superuser = IsSuperUser(user.id)
            return Response({'token':token, "user name":user.name, 'admin' : is_superuser, 'Message':'Login Success'}, status=status.HTTP_200_OK)

        else:
            return Response({'Message':'Login Failed!!! Check email and password'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class RefreshTokenView(APIView):
    """
    Send a refresh token to get a new access token.
    """
    def post(self, request, format=None):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'Message': 'No refresh token provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh_token = RefreshToken(refresh_token)
            access_token = refresh_token.access_token
        except Exception as e:
            return Response({'Message': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'access_token': str(access_token)}, status=status.HTTP_200_OK)




class UserModifyView(APIView):
    """ 
    Change existing user name and password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserModifyPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        old_password = serializer.validated_data.get('old_password')
        new_password = serializer.validated_data.get('new_password')

        # Check if the old password matches the user's current password
        if not user.check_password(old_password):
            return Response({'Message': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the old and new passwords are the same
        if old_password == new_password:
            return Response({'Message': 'New password must be different from the old password.'}, status=status.HTTP_400_BAD_REQUEST)

        # Change the user's password
        user.set_password(new_password)

        if request.data.get('name'):
            name = request.data.get('name')
            # return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)4
            user.name = name
        user.save()

        return Response({'Message': 'User details changed successfully.'}, status=status.HTTP_200_OK)
    
# ---------------------------------------ADMIN SECTION-----------------------------------------------------------------------------
class AdminGetInstaAccounts(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        
        if not user or not is_superuser:
            return Response({"Message": "Superuser not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        accounts = instagram_accounts.objects.all()
        if accounts.exists():
            accounts_data = [{'id': account.id, 'Instagram username': account.username, "user":account.user.email} for account in accounts]
            # return Response(accounts_data)
            return Response({'Message': 'Fetch the insta account successfully.', "data":accounts_data}, status=status.HTTP_200_OK)
        else:
            return Response({'Message': 'No instagram account found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AdminEditInstaAccounts(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):

        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        
        if not user or not is_superuser:
            return Response({"Message": "Superuser not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # user_id = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=user_id).first()
        # if not user:
        #     return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "insta_id" in request.data or not request.data.get('insta_id'):
            return Response({"Message":"No Instagram Account Id Found"})

        insta_id = request.data.get('insta_id')

        try:
            account = instagram_accounts.objects.get(id=insta_id)
        except instagram_accounts.DoesNotExist:
            return Response({'Message': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)

        username = request.data.get('username')
        password = request.data.get('password')

        if username:
            account.username = username
        if password:
            account.password = password
        if not username and not password:
            return Response({'Message': 'Could not found Insta Account detail to update'}, status=status.HTTP_404_NOT_FOUND)

        account.save()
        return Response({'Message': 'Account Details updated'}, status=status.HTTP_200_OK)

class AdminDeleteInstaAccounts(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):

        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        
        if not user or not is_superuser:
            return Response({"Message": "Superuser not found"}, status=status.HTTP_401_UNAUTHORIZED)

        # user_id = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=user_id).first()
        # if not user:
        #     return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "insta_id" in request.data or not request.data.get('insta_id'):
            return Response({"Message":"No Instagram Account Id Found"})

        insta_ids = request.data.get('insta_id')
        
        if not insta_ids:
            return Response({"Message": "No Instagram Account IDs Found"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(insta_ids, list):
            return Response({"Message": "Invalid data format. insta_ids should be a list of integers"}, status=status.HTTP_400_BAD_REQUEST)

        deleted_count = 0
        not_found_ids = []

        for insta_id in insta_ids:
            try:
                account = instagram_accounts.objects.get(id=insta_id)
                account.delete()
                deleted_count += 1
            except instagram_accounts.DoesNotExist:
                not_found_ids.append(insta_id)

        if not_found_ids:
            return Response({
                'Message': f'{deleted_count} account(s) deleted successfully. The following account IDs were not found: {not_found_ids}'
            }, status=status.HTTP_207_MULTI_STATUS)
        
        return Response({'Message': f'All {deleted_count} account(s) deleted successfully'}, status=status.HTTP_200_OK)
    


class AdminViewUsers(APIView):
    """ 
    Get a user profile data with email and password
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        

        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)

        if not user or not is_superuser:
            return Response({"Message": "Superuser not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        main_user_id = request.data.get("user_id")

        if not "user_id" in request.data or not request.data.get('user_id'):
            return Response({"Message":"User Id not Found!!!!"})

        
        user = CustomUser.objects.filter(id=main_user_id).first()

        if user:
            serializer = UserProfileSerializer(user)


            Insta_history = []

            insta_count=0
            for insta in instagram_accounts.objects.filter(user=user) :
            
                tmp = {
                    'user' : insta.user,
                    'id' : insta.id,
                    'username' : insta.username,
                    # 'password' : insta.password,#created.strftime("%d/%m/%Y"),
                    'created': insta.created.strftime("%d/%m/%Y %H:%M:%S"),
                    'updated': insta.updated.strftime("%d/%m/%Y %H:%M:%S"),
                }
                Insta_history.append(tmp)
            insta_count=len(Insta_history)
            
            Led_history = []
            lead_count = 0
            for LeadHistory in Lead.objects.filter(instagram_account__user=user):
                tmp = {
                    'id' : LeadHistory.id,
                    'amount' : LeadHistory.username,
                    'transection_id' : LeadHistory.name,
                    'status' : LeadHistory.status,
                    'created' : LeadHistory.created.strftime("%d/%m/%Y %H:%M:%S"),
                    'updated' : LeadHistory.updated.strftime("%d/%m/%Y %H:%M:%S"),
                }
                Led_history.append(tmp)
            lead_count = len(Led_history)

            Mess_history = []
            message_count= 0
            for MessageHistory in Message.objects.filter(instagram_account__user=user):
                tmp = {
                    'id' : MessageHistory.id,
                    'content' : MessageHistory.content,
                    'scheduled_time' : MessageHistory.scheduled_time,
                    'sent_status' : MessageHistory.sent,
                    'sent_time' : MessageHistory.sent_time,
                    'created' : MessageHistory.created.strftime("%d/%m/%Y %H:%M:%S"),
                    'update' : MessageHistory.updated.strftime("%d/%m/%Y %H:%M:%S"),
                }
                Mess_history.append(tmp)
            message_count = len(Mess_history)
                    
            jsonn_response = {
                'user_data' : serializer.data,
                'Total_Insta_account': insta_count,
                'Total_Message_count' : message_count,
                'Total_lead_count' : lead_count,
            }
            response = Response(jsonn_response, status=status.HTTP_200_OK)
            
            # Set the Referrer Policy header
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

            return response
        else:
            return Response({"Message": 'Unable to find user detail'})


class AdminViewAllUsers(APIView):
    """ 
    Get user profile data with email and password
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)

        if not user or not is_superuser:
            return Response({"Message": "Superuser not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        users = CustomUser.objects.all()
        user_data_list = []

        for user in users:

            user_main_id=user.id
            _, is_superuser = IsSuperUser(user_main_id)

            serializer = UserProfileSerializer(user)
            insta_history = []
            lead_history = []
            message_history = []

            for insta in instagram_accounts.objects.filter(user=user):
                insta_data = {
                    'user': insta.user,
                    'id': insta.id,
                    'username': insta.username,
                    'created': insta.created.strftime("%d/%m/%Y %H:%M:%S"),
                    'updated': insta.updated.strftime("%d/%m/%Y %H:%M:%S"),
                }
                insta_history.append(insta_data)
                
            insta_count = len(insta_history)

            for lead_history_obj in Lead.objects.filter(instagram_account__user=user):
                lead_data = {
                    'id': lead_history_obj.id,
                    'amount': lead_history_obj.username,
                    'transection_id': lead_history_obj.name,
                    'status': lead_history_obj.status,
                    'created': lead_history_obj.created.strftime("%d/%m/%Y %H:%M:%S"),
                    'updated': lead_history_obj.updated.strftime("%d/%m/%Y %H:%M:%S"),
                }
                lead_history.append(lead_data)
                
            lead_count = len(lead_history)

            for message_history_obj in Message.objects.filter(instagram_account__user=user):
                message_data = {
                    'id': message_history_obj.id,
                    'content': message_history_obj.content,
                    'scheduled_time': message_history_obj.scheduled_time,
                    'sent_status': message_history_obj.sent,
                    'sent_time': message_history_obj.sent_time,
                    'created': message_history_obj.created.strftime("%d/%m/%Y %H:%M:%S"),
                    'update': message_history_obj.updated.strftime("%d/%m/%Y %H:%M:%S"),
                }
                message_history.append(message_data)
                
            message_count = len(message_history)

            user_data = {
                'user_data': serializer.data,
                'IsAdmin': is_superuser,
                'Total_Insta_account': insta_count,
                'Total_Message_count': message_count,
                'Total_lead_count': lead_count,
            }

            user_data_list.append(user_data)

        response_data = {
            "Message": "Analytics data Fetched Successfully",
            "Data": user_data_list
        }

        response = Response(response_data, status=status.HTTP_200_OK)
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response





class AdminAnalytics(APIView):
    """ 
    Get-Analytics if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not find the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not "date_filter" in request.data or not request.data.get("date_filter"):
            return Response({"Message":"Please specify the date_filter eg: day, week, month"}, status=status.HTTP_400_BAD_REQUEST)

        date_filter = request.data.get("date_filter")
        now = timezone.now()
        analytics_data = []

        if date_filter == 'day':
            for i in range(1, 13):
                start_date = now - timedelta(days=i)
                end_date = now - timedelta(days=i-1)
                data = self.get_analytics_data(start_date, end_date)
                analytics_data.append(data)
        elif date_filter == 'week':
            for i in range(1, 13):
                start_date = now - timedelta(weeks=i)
                end_date = now - timedelta(weeks=i-1)
                data = self.get_analytics_data(start_date, end_date)
                analytics_data.append(data)
        elif date_filter == 'month':
            for i in range(1, 13):
                start_date = now - timedelta(days=30*i)
                end_date = now - timedelta(days=30*(i-1))
                data = self.get_analytics_data(start_date, end_date)
                analytics_data.append(data)
        else:
            return Response({"Message":"Invalid date_filter"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(analytics_data, status=status.HTTP_200_OK)

    def get_analytics_data(self, start_date, end_date):

        total_user= 0
        # User Table
        user_ = CustomUser.objects.filter(created__gte=start_date,  created__lte=end_date)
        total_user = len(user_)

        # Payment Table
        insta = instagram_accounts.objects.filter(updated__gte=start_date,  updated__lte=end_date)
        total_insta_account = len(insta)        

        # Credit Table
        total_leads_records = 0
        leads = Lead.objects.filter(updated__gte=start_date,  updated__lte=end_date)
        total_leads_records = len(leads)

        # Original Image Table
        messg = Message.objects.filter(updated__gte=start_date,  updated__lte=end_date)
        total_messages_count = len(messg)

        jsonn_response = {
            'Total user' : total_user,
            'Total Insta Accounts' : total_insta_account,
            'Total Message Records': total_messages_count,
            'Total Leads Count': total_leads_records,
        }
        # return JsonResponse(jsonn_response, status=status.HTTP_200_OK)
        

        return jsonn_response


# ---------------------------------------ADMIN SECTION-----------------------------------------------------------------------------

class AddInstagramAccount(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({'Message': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        if instagram_accounts.objects.filter(username=username, user=user).exists():
            return Response({'Message': 'Account already exists'}, status=status.HTTP_400_BAD_REQUEST)

        account = instagram_accounts(username=username, password=password, user=request.user)
        account.save()

        return Response({'Message': 'Account created Successfully', 'id': account.id}, status=status.HTTP_201_CREATED)

class GetInstagramAccounts(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        accounts = instagram_accounts.objects.filter(user=user)
        if accounts.exists():
            accounts_data = [{'id': account.id, 'Instagram username': account.username,  'Instagram password': account.password} for account in accounts]
            # return Response(accounts_data)
            return Response({'Message': 'Fetch the insta account successfully.', "data":accounts_data}, status=status.HTTP_200_OK)
        else:
            return Response({'Message': 'No instagram account found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class EditInstagramAccount(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "insta_id" in request.data or not request.data.get('insta_id'):
            return Response({"Message":"No Instagram Account Id Found"})

        insta_id = request.data.get('insta_id')

        try:
            account = instagram_accounts.objects.get(id=insta_id, user=user)
        except instagram_accounts.DoesNotExist:
            return Response({'Message': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)

        username = request.data.get('username')
        password = request.data.get('password')

        if username:
            account.username = username
        if password:
            account.password = password
        if not username and not password:
            return Response({'Message': 'Could not found Insta Account detail to update'}, status=status.HTTP_404_NOT_FOUND)

        account.save()
        return Response({'Message': 'Account Details updated'}, status=status.HTTP_200_OK)

class DeleteInstagramAccount(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "insta_id" in request.data or not request.data.get('insta_id'):
            return Response({"Message":"No Instagram Account Id Found"})

        insta_ids = request.data.get('insta_id')

        # if insta_id:
        #     try:
        #         account = instagram_accounts.objects.get(id=insta_id, user=user)
        #         account.delete()
        #         return Response({'Message': 'Account deleted Successfully'}, status=status.HTTP_200_OK)
        #     except instagram_accounts.DoesNotExist:
        #         return Response({'Message': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)
        

        if not insta_ids:
            return Response({"Message": "No Instagram Account IDs Found"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(insta_ids, list):
            return Response({"Message": "Invalid data format. insta_ids should be a list of integers"}, status=status.HTTP_400_BAD_REQUEST)

        deleted_count = 0
        not_found_ids = []

        for insta_id in insta_ids:
            try:
                account = instagram_accounts.objects.get(id=insta_id, user=user)
                account.delete()
                deleted_count += 1
            except instagram_accounts.DoesNotExist:
                not_found_ids.append(insta_id)

        if not_found_ids:
            return Response({
                'Message': f'{deleted_count} account(s) deleted successfully. The following account IDs were not found: {not_found_ids}'
            }, status=status.HTTP_207_MULTI_STATUS)
        
        return Response({'Message': f'All {deleted_count} account(s) deleted successfully'}, status=status.HTTP_200_OK)



class UserProfileView(APIView):
    """ 
    Get a user profile data with email and password
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


        Insta_history = []

        insta_count=0
        for insta in instagram_accounts.objects.filter(user=user) :
          
            tmp = {
                'user' : insta.user,
                'id' : insta.id,
                'username' : insta.username,
                # 'password' : insta.password,#created.strftime("%d/%m/%Y"),
                'created': insta.created.strftime("%d/%m/%Y %H:%M:%S"),
                'updated': insta.updated.strftime("%d/%m/%Y %H:%M:%S"),
            }
            Insta_history.append(tmp)
        insta_count=len(Insta_history)
        
        Led_history = []
        lead_count = 0
        for LeadHistory in Lead.objects.filter(instagram_account__user=user):
            tmp = {
                'id' : LeadHistory.id,
                'amount' : LeadHistory.username,
                'transection_id' : LeadHistory.name,
                'status' : LeadHistory.status,
                'created' : LeadHistory.created.strftime("%d/%m/%Y %H:%M:%S"),
                'updated' : LeadHistory.updated.strftime("%d/%m/%Y %H:%M:%S"),
            }
            Led_history.append(tmp)
        lead_count = len(Led_history)

        Mess_history = []
        message_count= 0
        for MessageHistory in Message.objects.filter(instagram_account__user=user):
            tmp = {
                'id' : MessageHistory.id,
                'content' : MessageHistory.content,
                'scheduled_time' : MessageHistory.scheduled_time,
                'sent_status' : MessageHistory.sent,
                'sent_time' : MessageHistory.sent_time,
                'created' : MessageHistory.created.strftime("%d/%m/%Y %H:%M:%S"),
                'update' : MessageHistory.updated.strftime("%d/%m/%Y %H:%M:%S"),
            }
            Mess_history.append(tmp)
        message_count = len(Mess_history)
                
        jsonn_response = {
            'user_data' : serializer.data,
            'Total_Insta_account': insta_count,
            'Total_Message_count' : message_count,
            'Total_lead_count' : lead_count,
        }
        response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # Set the Referrer Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response


#----------------------------------------------------------------CSV file and Leads-------------------------------------------------
from django.db import transaction
import uuid

class SaveLeadData(APIView):
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        instagram_account_id = request.data.get('instagram_id')
        if not instagram_account_id:
            return Response({"Message": "No Instagram Account found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            instagram_account = instagram_accounts.objects.get(id=instagram_account_id,user = user)
        except:
            return Response({"Message":"No Instagram Account Found!!!!!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        instagram_account.user = user

        data = request.data  # Assuming data is sent as JSON

        # Generate a new unique CSV file number
        csv_file_number = str(uuid.uuid4())

        for lead_data in data['leads']:
            name = lead_data.get('name')
            # email = lead_data.get('email')
            # phone_number = lead_data.get('phone_number')
            username = lead_data.get('username')
            statuss = lead_data.get('status')

            # Assuming instagram_account is passed as a parameter
            # instagram_account_id = lead_data.get('instagram_account_id')

            # Create Lead object and save
            lead = Lead.objects.create(
                csv_file_number=csv_file_number,
                instagram_account=instagram_account,
                name=name,
                # email=email,
                # phone_number=phone_number,
                username=username,
                status=statuss
            )
            lead.save()

        return Response({'message': 'Lead data saved successfully'}, status=status.HTTP_201_CREATED)


class GetLeaddata(APIView):
    def get(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        insta_id = request.data.get("insta_id")  

        try:
            # Find all Lead objects associated with the specified csv_file_number and delete them
            if insta_id:
                inns = instagram_accounts.objects.get(id=insta_id)
                lead_obj= Lead.objects.filter(instagram_account__user=user,instagram_account = inns)
            else:
                lead_obj= Lead.objects.filter(instagram_account__user=user)

            if not lead_obj:
                return Response({'Message': 'No Lead objects found'}, status=status.HTTP_404_NOT_FOUND)

            lead_data = []

            for leads in lead_obj:
                tmp={

                    "instagram_account":leads.instagram_account.username,
                    "Lead ID" : leads.id,
                    "name":leads.name,
                    "username":leads.username,
                    "leads_status":leads.status,
                    "csv_file_number":leads.csv_file_number
                }
                lead_data.append(tmp)



            return Response({'Message': 'Lead objects fetched successfully', "Lead_data":lead_data}, status=status.HTTP_200_OK)

        except Lead.DoesNotExist:
            return Response({'Message': 'No Lead objects found for deletion'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"Message":f"Error Occured while fetching Lead Object: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class DeleteLeadCSV(APIView):
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "csv_file_number" in request.data or not request.data.get('csv_file_number'):
            return Response({"Message":"No csv_file_number Found"}, status=status.HTTP_404_NOT_FOUND)
        
        csv_file_number = request.data.get('csv_file_number')

        try:

            with transaction.atomic():
                # Find all Lead objects associated with the specified csv_file_number and delete them
                deleted_count, _ = Lead.objects.filter(csv_file_number=csv_file_number,instagram_account__user=user).delete()

            if deleted_count == 0:
                return Response({'Message': 'No Lead objects found for deletion'}, status=status.HTTP_404_NOT_FOUND)

            return Response({'Message': f'{deleted_count} Lead objects deleted successfully'}, status=status.HTTP_200_OK)

        except Lead.DoesNotExist:
            return Response({'Message': 'No Lead objects found for deletion'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"Message":f"Error Occured: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DeleteLeadViaId(APIView):
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "lead_id" in request.data or not request.data.get('lead_id'):
            return Response({"Message":"No lead_id Found"}, status=status.HTTP_404_NOT_FOUND)
        

        lead_ids = request.data.get('lead_id')

        if not lead_ids:
            return Response({"Message": "No lead_id(s) found"}, status=status.HTTP_404_NOT_FOUND)

        if not isinstance(lead_ids, list):
            return Response({"Message": "Invalid data format. lead_id(s) should be a list of integers"}, status=status.HTTP_400_BAD_REQUEST)

        deleted_count = 0
        not_found_ids = []

        try:
            with transaction.atomic():
                for lead_id in lead_ids:
                    try:
                        delete_lead = Lead.objects.get(id=lead_id, instagram_account__user=user)
                        delete_lead.delete()
                        deleted_count += 1
                    except Lead.DoesNotExist:
                        not_found_ids.append(lead_id)

            if not_found_ids:
                return Response({'Message': f'{deleted_count} Lead object(s) deleted successfully. The following Lead IDs were not found: {not_found_ids}'},
                                status=status.HTTP_207_MULTI_STATUS)
            else:
                return Response({'Message': f'All {deleted_count} Lead object(s) deleted successfully'},
                                status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"Message": f"Error Occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class EditLeadViaId(APIView):
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if "leads" not in request.data or not request.data.get('leads'):
            return Response({"Message": "No leads Found"}, status=status.HTTP_404_NOT_FOUND)

        leads_data = request.data.get('leads')

        if not isinstance(leads_data, list):
            return Response({"Message": "Invalid data format. Leads should be a list of dictionaries"}, status=status.HTTP_400_BAD_REQUEST)

        updated_count = 0
        not_found_ids = []

        try:
            with transaction.atomic():
                for lead_data in leads_data:
                    lead_id = lead_data.get('lead_id')

                    if not lead_id:
                        return Response({"Message": "lead_id not found in one or more leads"}, status=status.HTTP_400_BAD_REQUEST)

                    try:
                        lead = Lead.objects.get(id=lead_id, instagram_account__user=user)

                        if 'name' in lead_data:
                            lead.name = lead_data.get('name', lead.name)
                        if 'username' in lead_data:
                            lead.username = lead_data.get('username', lead.username)
                        if 'status' in lead_data:
                            lead.status = lead_data.get('status', lead.status)


                        lead.save()
                        updated_count += 1
                    except Lead.DoesNotExist:
                        not_found_ids.append(lead_id)

            if not_found_ids:
                return Response({'Message': f'{updated_count} Lead object(s) updated successfully. The following Lead IDs were not found: {not_found_ids}'},
                                status=status.HTTP_207_MULTI_STATUS)
            else:
                return Response({'Message': f'All {updated_count} Lead object(s) updated successfully'},
                                status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"Message": f"Error Occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#----------------------------------------------------------------CSV file and Leads-------------------------------------------------




#----------------------------------------------------------------Message Template-------------------------------------------------

class AddMessageTemplate(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        template_name = request.data.get('template_name')
        template_content = request.data.get('template_content')

        if not template_name or not template_content:
            return Response({'Message': 'template_name and template_content are required'}, status=status.HTTP_400_BAD_REQUEST)

        if MessageTemplate.objects.filter(template_name=template_name, template_content=template_content, user=user).exists():
            return Response({'Message': 'Message Template already exists'}, status=status.HTTP_400_BAD_REQUEST)

        mess_temp = MessageTemplate(template_name=template_name, template_content=template_content, user=user)
        mess_temp.save()

        return Response({'Message': 'Message Template created Successfully', 'id': mess_temp.id}, status=status.HTTP_201_CREATED)



class GetMessageTemplate(APIView):
    def get(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        temp_id = request.data.get('temp_id')

        # if not temp_id:
        #     return Response({'Message': 'Template id not found'}, status=status.HTTP_400_BAD_REQUEST)


        try:
            if temp_id:
                Mess_obj= MessageTemplate.objects.filter(user=user, id= temp_id)
            else:
                Mess_obj= MessageTemplate.objects.filter(user=user)


            if not Mess_obj:
                return Response({'Message': 'No Message Template found'}, status=status.HTTP_404_NOT_FOUND)
            
            tmp = []
            for mess_obj in Mess_obj:
                tmp.append({
                    "Message Template id": mess_obj.id,
                    "User Email": mess_obj.user.email,
                    "Template Name": mess_obj.template_name,
                    "Template Content": mess_obj.template_content
                })

            return Response({'Message': 'Message Template fetched successfully', "Message_template_data":tmp}, status=status.HTTP_200_OK)

        except MessageTemplate.DoesNotExist:
            return Response({'Message': 'No Message Template found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"Message":f"Error Occured while fetching Message Template: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class deleteMessageTemplate(APIView):
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "template_id" in request.data or not request.data.get('template_id'):
            return Response({"Message":"No template_id Found"}, status=status.HTTP_404_NOT_FOUND)
        
        template_id = request.data.get('template_id')

        try:
            temp = MessageTemplate.objects.get(id=template_id,user=user)
            temp.delete()
            return Response({'Message': 'Template deleted successfully'},
                                status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"Message": f"Error Occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



#----------------------------------------------------------------Message Template-------------------------------------------------


#----------------------------------------------------------------Instagram Message View--------------------------------------------------------



# # instabot/views.py
# import time
# import logging
# import threading
# from django.http import JsonResponse
# from django.views import View
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.common.keys import Keys
# # import undetected_chromedriver as uc
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from webdriver_manager.chrome import ChromeDriverManager

# class InstagramBot:
#     # def __init__(self, username, password, recipients, message):
#     def __init__(self, username, password, recipients, message, instagram_account, task):
#         self.username = username
#         self.password = password
#         self.recipients = recipients
#         self.message = message
#         self.instagram_account = instagram_account
#         self.task = task
#         self.base_url = 'https://www.instagram.com/'

#         # options = uc.ChromeOptions()
#         options = webdriver.ChromeOptions()
#         # options.headless = True
#         options.add_argument('--no-sandbox')
#         options.add_argument('--disable-dev-shm-usage')
#         options.add_argument('--disable-gpu')
#         options.add_argument('--disable-extensions')
#         options.add_argument('--window-size=1200x600')
#         options.add_argument('--disable-client-side-phishing-detection')

#         # options.binary_location = '/usr/bin/chromedriver' 
#         # self.bot = uc.Chrome(options=options)
#         # self.bot = webdriver.Chrome(options=options)


#         options.add_argument('--headless')
#         options.add_argument('--disable-setuid-sandbox')
#         options.add_argument('--user-data-dir=/tmp/chromium')
#         options.add_argument('--remote-debugging-port=9222')
#         logging.basicConfig(level=logging.DEBUG)
#         print("Options set SUCCESSFULLY")


#         CHROMEDRIVER_PATH = '/usr/bin/chromedriver'
#         # Check if ChromeDriver exists at the specified path
#         if not os.path.exists(CHROMEDRIVER_PATH):
#             from webdriver_manager.chrome import ChromeDriverManager
#             CHROMEDRIVER_PATH = ChromeDriverManager().install()

        

#         # driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

#         # Ensure that the ChromeDriver path is correct
#         # try: self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options) 

#         #     print("BOT CREATED SUCCESSFULLY") 
#         # except Exception as e: 
#         #     print(f"The Error in bot creation is: {str(e)}")


#         try:
        
#             chromedriver_path = '/usr/bin/chromedriver'
#             service = Service(CHROMEDRIVER_PATH)
#             self.bot = webdriver.Chrome(service=service, options=options)

#             # self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
#             # self.bot = webdriver.Chrome(options=options)
#             # self.bot = webdriver.Chrome(chromedriver_path, options=options)

#             print("BOT CREATED SUCCESSFULLY")

#         except Exception as e:
#             print(f"The Error in bot is: {str(e)}")


#         # self.bot = uc.Chrome()
#         self.popup_thread = threading.Thread(target=self.handle_popup, daemon=True)
#         self.popup_thread.start()

#         print("Thread started SUCCESSFULLY")
#         try:
#             self.login()
#             print("Login SUCCESSFULLY")
#         except Exception as e:
#             print(f"The error is is --->: {e}")
#             logging.error(f"Error during login for {self.username}: {e}")
#             self.bot.quit()

#     def handle_popup(self):
#         while True:
#             try:
#                 not_now_button = WebDriverWait(self.bot, 5).until(
#                     EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Not Now')]"))
#                 )
#                 not_now_button.click()
#                 logging.info(f"Popup closed for {self.username}")
#             except Exception as e:
#                 time.sleep(1)

#     def login(self):
#         self.bot.get(self.base_url)
#         try:
#             enter_username = WebDriverWait(self.bot, 20).until(
#                 EC.presence_of_element_located((By.NAME, 'username')))
#             enter_username.send_keys(self.username)

#             enter_password = WebDriverWait(self.bot, 20).until(
#                 EC.presence_of_element_located((By.NAME, 'password')))
#             enter_password.send_keys(self.password)
#             enter_password.send_keys(Keys.RETURN)
#             time.sleep(5)
#         except Exception as e:
#             print(f"The error2222222222222222 --->: {e}")
#             logging.error(f"Error entering login credentials: {e}")
#             # mess=Message.objects.create(
#             #             instagram_account =self.instagram_account,
#             #             recipient=self.recipients,
#             #             content = self.message,
#             #             scheduled_time = timezone.now(),
#             #             sent = False,
#             #             sent_time = timezone.now(),
#             #             error = f"Error entering login credentials: {e}"
#             #             )
#             # self.task.message.add(mess)
#             # self.task.failed_messages += 1
#             self.task.error_message = "Failed"
#             self.task.save()
#             self.bot.quit()
#             return #############################################Break

#         time.sleep(3)
#         try:
#             # self.bot.find_element(By.XPATH,
#             #                       '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[5]/div/div/span/div/a/div/div[1]/div/div[1]').click()
            
#             self.bot.get("https://www.instagram.com/direct/inbox/")


#             time.sleep(2)
#         except Exception as e:
#             logging.error(f"Error navigating to message section: {e}")
#             return

#         self.task.status = 'in_progress'
#         self.task.save()

#         print("self.message 11111111111111111111111111111111111111111111111",self.message)
#         print("self.recipient222222222222222222222222222222222222222222222",self.recipients)

#         # for recipient in self.recipients:
#         for recipient, message in zip(self.recipients,self.message[0]):
#             print("The size of message are:================================================== ",len(self.message))
#             print(message)

#             print("The size of recipient are: ==================================================",len(self.recipients))
#             print(recipient)
#         # for message in messages:

#             try:
#                 time.sleep(3)
#                 try:
#                     new_message_button = WebDriverWait(self.bot, 5).until(
#                         EC.visibility_of_element_located((By.XPATH,
#                                                             '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[1]/div/div[1]/div[2]/div/div/div'))
#                     )
#                     new_message_button.click()
#                     time.sleep(2)
#                     recipient_input = WebDriverWait(self.bot, 5).until(
#                         EC.visibility_of_element_located((By.XPATH,
#                                                             '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[2]/div/div[2]/input'))
#                     )
#                     recipient_input.send_keys(recipient)
#                     time.sleep(2)

#                     recipient_suggestion = WebDriverWait(self.bot, 5).until(
#                         EC.visibility_of_element_located((By.XPATH,
#                                                             '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[3]/div/div/div[1]/div[1]'))
#                     )
#                     recipient_suggestion.click()
#                     time.sleep(2)

#                     next_button = WebDriverWait(self.bot, 5).until(
#                         EC.visibility_of_element_located((By.XPATH, '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[4]'))
#                     )
#                     next_button.click()
#                     time.sleep(2)
#                 except Exception as e:
#                     mess=Message.objects.create(
#                         instagram_account =self.instagram_account,
#                         recipient=recipient, 
#                         content = message,
#                         scheduled_time = timezone.now(),
#                         sent = False,
#                         sent_time = timezone.now(),
#                         error = f"Error adding recipient {recipient}: {e}"
#                         )
#                     self.task.message.add(mess)
#                     # self.task.failed_messages += 1
#                     self.task.save()
#                     logging.error(f"Error adding recipient {recipient}: {e}")
#                     continue

#                 try:
#                     # message_area = WebDriverWait(self.bot, 5).until(
#                     #     EC.visibility_of_element_located((By.XPATH,
#                     #                                       #'/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[2]/div/div/div/div/div/div/div[2]/div/div/div[2]/div/div/div[2]/div/div[1]/p'))
#                     #                                       '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[2]/div/div/div/div/div/div/div[2]/div/div/div[3]/div/div/div[2]/div/div'))
#                     # )

#                     # message_area = WebDriverWait(self.bot, 5).until(
#                     #     EC.visibility_of_element_located((By.CSS_SELECTOR, 'x1n2onr6'))
#                     # )
#                     time.sleep(2)
#                     message_area = WebDriverWait(self.bot, 10).until(
#                         EC.visibility_of_element_located((By.XPATH, '//div[@contenteditable="true" and @aria-label="Message"]'))
#                     )

                    
#                     message_area.click()
                        

#                     # message_area.send_keys(f"{message}")



#                     time.sleep(1)
#                     # message_area.send_keys(Keys.ENTER)
#                     # time.sleep(2)


#                     print("The message is prior send message: ",message)


#                     message_area.send_keys(message)
#                     print("The message is AFTER send message: ",message)
#                     time.sleep(1)
#                     message_area.send_keys(Keys.RETURN)
#                     print("The message is AFTER ENTER: ",message)
#                     time.sleep(2)
#                     mess=Message.objects.create(
#                         instagram_account =self.instagram_account, 
#                         recipient=recipient,
#                         content = message,
#                         scheduled_time = timezone.now(),
#                         sent = True,
#                         sent_time = timezone.now()
#                         )
                    
#                     mess.sent =True
#                     mess.save()
#                     self.task.sent_messages += 1
#                     self.task.message.add(mess)
#                     self.task.save()
#                     time.sleep(1)
#                 except Exception as e:
#                     logging.error(f"Error sending message to {recipient}: {e}")
#                     mess=Message.objects.create(
#                         instagram_account =self.instagram_account, 
#                         recipient=recipient,
#                         content = message,
#                         scheduled_time = timezone.now(),
#                         sent = False,
#                         sent_time = timezone.now(),
#                         error = f"Error sending message to {recipient}: {e}"
#                         )
#                     self.task.message.add(mess)
#                     self.task.failed_messages += 1
#                     self.task.save()
#                     continue
#                 finally:
#                     self.bot.refresh()
#                     time.sleep(2)

#             except Exception as e:
#                 mess=Message.objects.create(
#                         instagram_account =self.instagram_account, 
#                         recipient=recipient,
#                         content = message,
#                         scheduled_time = timezone.now(),
#                         sent = False,
#                         sent_time = timezone.now(),
#                         error = f"Error handling message for {recipient}: {e}")
#                 logging.error(f"Error handling message for {recipient}: {e}")

#                 self.task.message.add(mess)
#                 self.task.save()

#             minute_ = random.randint(1, 4)
#             print(f"Sleeping for {minute_} minutes...")
#             time.sleep(minute_ * 60)
#             print("Awake now!")
#         self.task.status = 'completed'
#         self.task.save()

#     def logout(self):
#         try:
#             profile_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[8]/div/span/div/a/div/div/div/div/span"
#             self.bot.find_element(By.XPATH, profile_xpath).click()
#             time.sleep(1)

#             setting_icon_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[2]/div/div[2]/section/main/div/header/section[2]/div/div/div[3]/div/div"
#             self.bot.find_element(By.XPATH, setting_icon_xpath).click()
#             time.sleep(1)

#             logout_xpath = "/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/button[7]"
#             self.bot.find_element(By.XPATH, logout_xpath).click()
#             time.sleep(2)
#         except Exception as e:
#             logging.error(f"An error occurred during logout: {e}")

#     def close_browser(self):
#         self.logout()
#         time.sleep(3)
#         self.bot.quit()

# def send_messages(account):
#     print("Before Getting all variable")
#     username = account['username']
#     password = account['password']
#     recipients = account['recipients']
#     message = account['message']
#     instagram_account = account['instagram_account']
#     task = account['task']
#     print("After Getting all variable")
#     try:
#         # instagram_bot = InstagramBot(username, password, recipients, message)

#         # instagram_bot = InstagramBot(username, password, recipients, message, instagram_account)
#         print("Before instagram_bot")
#         instagram_bot = InstagramBot(username, password, recipients, message, instagram_account, task)
#         print("after instagram_bot")

#         instagram_bot.close_browser()
#         return f"Messages sent from {username} to {recipients}"
#     except Exception as e:
#         logging.error(f"An error occurred with account {username}: {e}")
#         task.status = 'failed'
#         task.error_message = str(e)
#         task.save()
#         return f"Failed to send messages from {username}"

# from django.views.decorators.csrf import csrf_exempt

# class InstagramBotView(APIView):

#     @csrf_exempt
#     def dispatch(self, *args, **kwargs):
#         return super().dispatch(*args, **kwargs)

#     def post(self, request):
#         logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


#         instagram_account_id=request.data.get('instagram_account_id')

#         if not instagram_account_id:
#             return Response({"Message":"Please Provide instagram_account_id"})
        
#         recipient_list=request.data.get('recipient_list')

#         if not isinstance(recipient_list, list):
#             return Response({"Message": "Recipient_list must be a list. ex- ['recipient1', 'recipient2', 'recipient3']"})

#         if not recipient_list:
#             return Response({"Message":"Recipient_list not found!!!!"})
        
#         custom_message = request.data.get("custom_message")
#         message_list=request.data.get('message_list')

#         # if not isinstance(message_list, list):
#         #     return Response({"Message": "message_list must be a list. ex- if you have 3 recipient then [[Template_id1, Template_id2],[Template_id3, Template_id1], [Template_id4]]"})

#         # if not message_list:
#         #     return Response({"Message":"message_list not found!!!!"})
        

#         ins=instagram_accounts.objects.filter(id=instagram_account_id).first()

#         # total_messages = sum(len(messages) for messages in message_list)

#         total_messages = len(recipient_list)

#         task = Task.objects.create(instagram_account=ins, total_messages=total_messages)


#         response_data = {'task_id': task.id}
#         print("Towards thread")
#         # Process messages in background
#         executor = ThreadPoolExecutor(max_workers=1)
#         executor.submit(self.process_messages, request.data, ins, task)
#         print("Afterwards thread")

#         return JsonResponse(response_data)


#     def process_messages(self, data, instagram_account, task):
#         print("HIiiiiiiiiiiiiiiii")
        
#         message_list=data.get('message_list')
#         recipient_list=data.get('recipient_list')
#         custom_message = data.get("custom_message")
#         print("Byeeeeeeeeeeeeeeeeeeeeeeee")
#         print("recipient_list :",recipient_list)
#         print("custom_message :",custom_message)
#         if not custom_message:

#             messages = []

#             date = data.get('date', 'Date')  # Default date if not provided
#             name = data.get('name', 'Instagram User')  # Default name if not provided
#             # company_service = data.get('company_service', 'Services')  # Default service if not provided
#             username = data.get('username', 'username_not_provided')
#             # for templates in message_list:
#             #     if not isinstance(templates, list) or len(templates) == 0:
#             #         return Response({"Message": "Each item in message_list must be a non-empty list of template IDs"}, status=400)
#             print("1111111111111111111111111111111")
#             template_messages = []  # Initialize a list to store messages for current set of templates
#             for i in range(len(name)):
#                 try:
#                     # Fetch message_template object from the database
#                     message_template = MessageTemplate.objects.get(id=message_list)
#                     print("The message template is as fllows: ",message_template)

#                     # Retrieve dynamic data from request or provide defaults
#                     # date = data.get('date', 'Date')  # Default date if not provided
#                     # name = data.get('name', 'Instagram User')  # Default name if not provided
#                     # # company_service = data.get('company_service', 'Services')  # Default service if not provided
#                     # username = data.get('username', 'username_not_provided')  # Default company name if not provided
#                     # # address = data.get('address', '')  # Default address if not provided
#                     print("222222222222222222222222222")
#                     # Replace placeholders in message template with dynamic data
#                     message_content = message_template.template_content.format(
#                         name=name[i],
#                         username=username[i],
#                         # company_service=company_service,
#                         date=date,
#                         # address=address
#                     )

#                     print("The message content :",message_content)


#                     # Add formatted message content to the template_messages list
#                     template_messages.append(message_content)

#                 except MessageTemplate.DoesNotExist:
#                     return Response({"Message": f"Message template with ID {message_list} does not exist"}, status=404)

#             # Append the messages for current templates set to the main messages list
#             messages.append(template_messages)
        
#         else:
#             print("333333333333333333333333333333")
#             date = data.get('date', 'Date')  # Default date if not provided
#             name = data.get('name', 'Instagram User')  # Default name if not provided
#             # company_service = data.get('company_service', 'Services')  # Default service if not provided
#             username = data.get('username', 'username_not_provided')
#             print(name)
#             messages=[]
#             for i in range(len(name)):
#                 print("44444444444444444444444444")
#                 try:
#                     messages_ = str(custom_message).format(
#                         name=name[i],
#                         username=username[i],
#                         # company_service=company_service,
#                         date=date,
#                         # address=address
#                     )
#                     print("555555555555555555555555555555")
#                     messages.append([messages_])
#                 except:
#                     print("6666666666666666666666666666666")
#                     messages.append(custom_message)
#             messages = [messages]
                    





#         # ins=instagram_accounts.objects.filter(id=instagram_account_id).first()

#         # total_messages = sum(len(messages) for messages in message_list)

#         # task = Task.objects.create(instagram_account=ins, total_messages=total_messages)
#         print("77777777777777777777777777")
#         username=instagram_account.username
#         password=instagram_account.password

#         # print("The messages detail arre as folows: ",messages)

#         # accounts = [
#         #     {'username': username, 'password': password, 'recipients': recipient_list,
#         #      'message': messages},
#         #     # {'username': username, 'password': password, 'recipients': ['adilalpha1', 'adilwebsite01', 'adilalpha1'],
#         #     #  'message': [["This is the 1 Successfully test", "This is the 2 Successfully test"],
#         #     #              ["This is the 3 Successfully test", "This is the 4 Successfully test"],
#         #     #              ["This is the third Successfully test"]]}
#         # ]

#         accounts = [
#             {'username': username, 'password': password, 'recipients': recipient_list, 'message': messages, 'instagram_account': instagram_account, 'task': task},
#             # {'username': username, 'password': password, 'recipients': ['adilalpha1', 'adilwebsite01', 'adilalpha1'],
#             #  'message': [["This is the 1 Successfully test", "This is the 2 Successfully test"],
#             #              ["This is the 3 Successfully test", "This is the 4 Successfully test"],
#             #              ["This is the third Successfully test"]]}
#         ]


#         # print("The account detail is: ",accounts)
#         print("8888888888888888888888888888888888")
#         max_simultaneous_logins = 5  # Set this to the number of simultaneous logins you want
#         print("Before thread")
#         results = []
#         with ThreadPoolExecutor(max_workers=max_simultaneous_logins) as executor:
#             futures = [executor.submit(send_messages, account) for account in accounts]
#             # print("The futures are as follows :",futures)
#             for future in as_completed(futures):
#                 results.append(future.result())

#         task.status = 'completed'
#         task.save()
#         print("After thread")
#         # return JsonResponse({'results': results})
#         # return JsonResponse({'results': results, 'task_id': task.id})






import time
import logging
import threading
from django.http import JsonResponse
from django.views import View
from concurrent.futures import ThreadPoolExecutor, as_completed
from instagrapi import Client
from instagrapi.exceptions import ClientError, ClientLoginRequired
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import instagram_accounts, Message, Task, MessageTemplate
from django.utils import timezone
import os

class InstagramBot:
    def __init__(self, username, password, recipients, message, instagram_account, task):
        self.username = username
        self.password = password
        self.recipients = recipients
        self.message = message
        self.instagram_account = instagram_account
        self.task = task
        self.client = Client()

        logging.basicConfig(level=logging.DEBUG)
        try:
            self.client.login(username, password)
            print("Login SUCCESSFUL")
        except ClientLoginRequired as e:
            print(f"Login required: {e}")
            logging.error(f"Login required for {self.username}: {e}")
            self.task.error_message = "Login required"
            self.task.save()
            return
        except ClientError as e:
            print(f"Client error: {e}")
            logging.error(f"Client error for {self.username}: {e}")
            self.task.error_message = "Client error"
            self.task.save()
            return
        
        self.task.status = 'in_progress'
        self.task.save()
        self.send_messages()

    def send_messages(self):
        for recipient, message in zip(self.recipients, self.message[0]):
            try:
                user_id = self.client.user_id_from_username(recipient)
                self.client.direct_send(message, [user_id])
                print(f"Message sent to {recipient}")
                mess = Message.objects.create(
                    instagram_account=self.instagram_account,
                    recipient=recipient,
                    content=message,
                    scheduled_time=timezone.now(),
                    sent=True,
                    sent_time=timezone.now()
                )
                self.task.sent_messages += 1
                self.task.message.add(mess)
                self.task.save()
                time.sleep(2)  # Add delay to avoid rate limits
            except ClientError as e:
                print(f"Error sending message to {recipient}: {e}")
                logging.error(f"Error sending message to {recipient}: {e}")
                mess = Message.objects.create(
                    instagram_account=self.instagram_account,
                    recipient=recipient,
                    content=message,
                    scheduled_time=timezone.now(),
                    sent=False,
                    sent_time=timezone.now(),
                    error=f"Error sending message to {recipient}: {e}"
                )
                self.task.message.add(mess)
                self.task.failed_messages += 1
                self.task.save()
                continue
            finally:
                minute_ = random.randint(1, 4)
                print(f"Sleeping for {minute_} minutes...")
                time.sleep(minute_ * 60)
                print("Awake now!")

        self.task.status = 'completed'
        self.task.save()
        self.logout()

    def logout(self):
        try:
            self.client.logout()
            print("Logged out successfully!")
        except ClientError as e:
            logging.error(f"An error occurred during logout: {e}")

def send_messages(account):
    print("Before Getting all variable")
    username = account['username']
    password = account['password']
    recipients = account['recipients']
    message = account['message']
    instagram_account = account['instagram_account']
    task = account['task']
    print("After Getting all variable")
    try:
        instagram_bot = InstagramBot(username, password, recipients, message, instagram_account, task)
        return f"Messages sent from {username} to {recipients}"
    except Exception as e:
        logging.error(f"An error occurred with account {username}: {e}")
        task.status = 'failed'
        task.error_message = str(e)
        task.save()
        return f"Failed to send messages from {username}"

class InstagramBotView(APIView):

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

        instagram_account_id = request.data.get('instagram_account_id')

        if not instagram_account_id:
            return Response({"Message": "Please Provide instagram_account_id"})
        
        recipient_list = request.data.get('recipient_list')

        if not isinstance(recipient_list, list):
            return Response({"Message": "Recipient_list must be a list. ex- ['recipient1', 'recipient2', 'recipient3']"})

        if not recipient_list:
            return Response({"Message": "Recipient_list not found!!!!"})
        
        custom_message = request.data.get("custom_message")
        message_list = request.data.get('message_list')

        ins = instagram_accounts.objects.filter(id=instagram_account_id).first()
        total_messages = len(recipient_list)
        task = Task.objects.create(instagram_account=ins, total_messages=total_messages)
        response_data = {'task_id': task.id}

        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(self.process_messages, request.data, ins, task)

        return JsonResponse(response_data)

    def process_messages(self, data, instagram_account, task):
        message_list = data.get('message_list')
        recipient_list = data.get('recipient_list')
        custom_message = data.get("custom_message")

        if not custom_message:
            messages = []
            date = data.get('date', 'Date')
            name = data.get('name', 'Instagram User')
            username = data.get('username', 'username_not_provided')
            template_messages = []
            for i in range(len(name)):
                try:
                    message_template = MessageTemplate.objects.get(id=message_list)
                    message_content = message_template.template_content.format(
                        name=name[i],
                        username=username[i],
                        date=date,
                    )
                    template_messages.append(message_content)
                except MessageTemplate.DoesNotExist:
                    return Response({"Message": f"Message template with ID {message_list} does not exist"}, status=404)
            messages.append(template_messages)
        else:
            date = data.get('date', 'Date')
            name = data.get('name', 'Instagram User')
            username = data.get('username', 'username_not_provided')
            messages = []
            for i in range(len(name)):
                try:
                    messages_ = str(custom_message).format(
                        name=name[i],
                        username=username[i],
                        date=date,
                    )
                    messages.append([messages_])
                except:
                    messages.append(custom_message)
            messages = [messages]

        username = instagram_account.username
        password = instagram_account.password

        accounts = [
            {'username': username, 'password': password, 'recipients': recipient_list, 'message': messages, 'instagram_account': instagram_account, 'task': task},
        ]

        max_simultaneous_logins = 5
        results = []
        with ThreadPoolExecutor(max_workers=max_simultaneous_logins) as executor:
            futures = [executor.submit(send_messages, account) for account in accounts]
            for future in as_completed(futures):
                results.append(future.result())

        task.status = 'completed'
        task.save()







#----------------------------------------------------------------Instagram Message View--------------------------------------------------------




class GetMessage(APIView):
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # temp_id = request.data.get('temp_id')

        # if not temp_id:
        #     return Response({'Message': 'Template id not found'}, status=status.HTTP_400_BAD_REQUEST)
        instagram_account_id=request.data.get('instagram_account_id')

        try:
            if instagram_account_id:
                Mess_obj= Message.objects.filter(instagram_account__user=user,instagram_account__id= instagram_account_id)
            else:
                Mess_obj= Message.objects.filter(instagram_account__user=user)

            if not Mess_obj:
                return Response({'Message': 'No Message found'}, status=status.HTTP_404_NOT_FOUND)
            mess_lst=[]
            for mess in Mess_obj:
            
                tmp={
                "Message id" : mess.id,
                "Message instagram account id" : mess.instagram_account.id,
                "user email" : mess.instagram_account.user.email,
                "Message content" : mess.content,
                "Message scheduled_time" : mess.scheduled_time,
                "Message sent status" : mess.sent,
                "Message sent_time" : mess.sent_time}

                mess_lst.append(tmp)            

            return Response({'Message': 'Message Data fetched successfully', "Message_data":mess_lst}, status=status.HTTP_200_OK)

        except Message.DoesNotExist:
            return Response({'Message': 'No Message Record found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"Message":f"Error Occured while fetching Message Data: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



from django.utils.dateparse import parse_datetime

class AddMessage(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        instagram_account_id = request.data.get('instagram_account_id')
        
        recipient = request.data.get('recipient')
        content = request.data.get('custom_message')
        scheduled_time_str = request.data.get('scheduled_time')
        # print(scheduled_time_str)
        # print(type(scheduled_time_str))
        
        try:
            scheduled_time = parse_datetime(scheduled_time_str)
            if scheduled_time is None:
                return Response({'Message': 'Invalid scheduled_time format'}, status=status.HTTP_400_BAD_REQUEST)
            # Ensure the parsed datetime is timezone-aware
            if timezone.is_naive(scheduled_time):
                scheduled_time = timezone.make_aware(scheduled_time, timezone.utc)
        except ValueError:
            return Response({'Message': 'Invalid scheduled_time format'}, status=status.HTTP_400_BAD_REQUEST)
        
        instagram_account = instagram_accounts.objects.get(id=instagram_account_id)
        sent = False

        if not recipient or not instagram_account:
            return Response({'Message': 'recipient and instagram_account_id are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not scheduled_time:
            return Response({'Message': 'scheduled_time are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        message_list = request.data.get("message_list")
        
        if not content:
            # template_id for templates:
            try:
                # Fetch message_template object from the database
                message_template = MessageTemplate.objects.get(id=message_list)
                print("The message template is as fllows: ",message_template)

                # Retrieve dynamic data from request or provide defaults
                date = request.data.get('date', 'Date')  # Default date if not provided
                name = request.data.get('name', 'Instagram User')  # Default name if not provided
                username = request.data.get('username', 'username_not_found')
                # company_service = request.data.get('company_service', 'Services')  # Default service if not provided
                # company_name = request.data.get('company_name', 'Company')  # Default company name if not provided
                # address = request.data.get('address', '')  # Default address if not provided

                # Replace placeholders in message template with dynamic data
                message_content = message_template.template_content.format(
                    name=name[0],
                    username=username[0],
                    # company_name=company_name,
                    # company_service=company_service,
                    date=date,
                    # address=address
                )

                print("The message content :",message_content)

                content = message_content


                # Add formatted message content to the template_messages list
                # message_content

            except MessageTemplate.DoesNotExist:
                return Response({"Message": f"Message template with ID {message_list} does not exist"}, status=404)
        else:
            try:
                date = request.data.get('date', 'Date')  # Default date if not provided
                name = request.data.get('name', 'Instagram User')  # Default name if not provided
                username = request.data.get('username', 'username_not_provided')
                message_contents = content.format(
                        name=name[0],
                        username=username[0],
                        date=date
                    )
                content = message_contents
            except:    

                content = content


        print("The COntent is :",content)


        

        try:
            if Message.objects.filter(instagram_account =instagram_account, recipient=recipient[0], content=content, scheduled_time=scheduled_time, sent=sent).exists():
                return Response({'Message': 'Message already exists'}, status=status.HTTP_400_BAD_REQUEST)

            else:
                total_messages = len(recipient)
                mess = Message.objects.create(instagram_account =instagram_account, recipient=recipient[0], content=content, scheduled_time=scheduled_time, sent=sent)
                task = Task.objects.create(instagram_account=instagram_account, total_messages=total_messages)
                task.message.add(mess)
                task.save()
                print(task)
                print(mess)
                return Response({'Message': 'Message Added Successfully',"Task_id":task.id}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'Message': f'Message creation Failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class deleteMessage(APIView):
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if not "message_id" in request.data or not request.data.get('message_id'):
            return Response({"Message":"No message_id Found"}, status=status.HTTP_404_NOT_FOUND)
        
        message_id = request.data.get('message_id')

        try:
            mess = Message.objects.get(id=message_id,instagram_account__user=user)
            mess.delete()
            return Response({'Message': 'Message Record deleted successfully'},
                                status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"Message": f"Error Occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class GetMessagewithtime(APIView):
    def post(self, request, format=None):
        # Get user ID from token
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Retrieve time_before and time_after from request data
        # time_before_str = request.data.get("time_before")
        # time_after_str = request.data.get("time_after")

        # if not time_before_str or not time_after_str:
        #     return Response({"Message": "time_before and time_after are required"}, status=status.HTTP_400_BAD_REQUEST)

        now = timezone.now()
        time_before_str = str(now - timedelta(hours=1))
        time_after_str = str(now + timedelta(hours=1))

        # print(now)
        # print(ttime_after)
        # print(ttime_before)

        try:
            # Parse ISO 8601 strings to datetime objects
            time_before = datetime.fromisoformat(time_before_str)
            time_after = datetime.fromisoformat(time_after_str)

            # Ensure time_before and time_after are in UTC
            if time_before.tzinfo is None or time_before.tzinfo.utcoffset(time_before) is None:
                time_before = timezone.make_aware(time_before, timezone.utc)
            if time_after.tzinfo is None or time_after.tzinfo.utcoffset(time_after) is None:
                time_after = timezone.make_aware(time_after, timezone.utc)

            # Query messages within the specified time range
            messages = Message.objects.filter(
                instagram_account__user=user,
                sent=False,
                scheduled_time__gte=time_before,
                scheduled_time__lte=time_after
            )

            if not messages:
                return Response({'Message': 'No Message Templates found within the specified time range'}, status=status.HTTP_404_NOT_FOUND)

            message_data = []
            for message in messages:
                message_info = {
                    "Message id": message.id,
                    "Message instagram account id": message.instagram_account.id,
                    "user email": message.instagram_account.user.email,
                    "Message content": message.content,
                    "Message scheduled_time": message.scheduled_time.isoformat() if message.scheduled_time else None,
                    "Message sent status": message.sent,
                    "Message sent_time": message.sent_time.isoformat() if message.sent_time else None
                }
                message_data.append(message_info)

            return Response({
                "Message": "Message Data fetched successfully",
                "Message_data": message_data
            }, status=status.HTTP_200_OK)

        except ValueError:
            return Response({"Message": "Invalid datetime format"}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"Message": f"Error Occurred while fetching Message Data: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        




# class SingleInstaMessageView(APIView):

#     @csrf_exempt
#     def dispatch(self, *args, **kwargs):
#         return super().dispatch(*args, **kwargs)

#     def post(self, request):
#         # self.logger.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


#         instagram_account_id=request.data.get('instagram_account_id')

#         if not instagram_account_id:
#             return Response({"Message":"Please Provide instagram_account_id"})
        
#         recipient_list=request.data.get('recipient_list')

#         # if not isinstance(recipient_list, list):
#         #     return Response({"Message": "Recipient must be a list. ex- ['recipient1', 'recipient2', 'recipient3']"})

#         if not recipient_list:
#             return Response({"Message":"Recipient not found!!!!"})
        

#         message_list=request.data.get('message_list')

#         custom_message=request.data.get('custom_message')

#         # if not isinstance(message_list, list):
#         #     return Response({"Message": "message_list must be a list. ex- if you have 3 recipient then [[Template_id1, Template_id2],[Template_id3, Template_id1], [Template_id4]]"})

#         if not message_list and not custom_message:
#             return Response({"Message":"message not found!!!!"})
        
#         if not custom_message:
#             # template_id for templates:
#             try:
#                 # Fetch message_template object from the database
#                 message_template = MessageTemplate.objects.get(id=message_list)
#                 print("The message template is as fllows: ",message_template)

#                 # Retrieve dynamic data from request or provide defaults
#                 date = request.data.get('date', 'Date')  # Default date if not provided
#                 name = request.data.get('name', 'Instagram User')  # Default name if not provided
#                 # company_service = request.data.get('company_service', 'Services')  # Default service if not provided
#                 username = request.data.get('username', 'username_not_provided')  # Default company name if not provided
#                 # address = request.data.get('address', '')  # Default address if not provided

#                 # Replace placeholders in message template with dynamic data
#                 message_content = message_template.template_content.format(
#                     name=name[0],
#                     username=username[0],
#                     date=date,
#                 )

#                 print("The message content :",message_content)


#                 # Add formatted message content to the template_messages list
#                 # message_content

#             except MessageTemplate.DoesNotExist:
#                 return Response({"Message": f"Message template with ID {message_list} does not exist"}, status=404)
#         else:

#             try:
#                 date = request.data.get('date', 'Date')  # Default date if not provided
#                 name = request.data.get('name', 'Instagram User')  # Default name if not provided
#                 username = request.data.get('username', 'username_not_provided')
#                 message_contents = custom_message.format(
#                         name=name[0],
#                         username=username[0],
#                         date=date
#                     )
#                 message_content = message_contents
#             except:    

#                 message_content = custom_message

#             # message_content = custom_message

#         ins=instagram_accounts.objects.filter(id=instagram_account_id).first()
#         if not ins:
#             return Response({"Message": "Instagram account not found"}, status=404)

#         username=ins.username
#         password=ins.password

      
#         accounts = [
#             {'username': username, 'password': password, 'recipients': recipient_list[0], 'message': message_content, 'instagram_account': ins}
#         ]


#         # print("The account detail is: ",accounts)

#         max_simultaneous_logins = 10  # Set this to the number of simultaneous logins you want

#         results = []
#         with ThreadPoolExecutor(max_workers=max_simultaneous_logins) as executor:
#             futures = [executor.submit(single_send_messages, account) for account in accounts]
#             # print("The futures are as follows :",futures)
#             for future in as_completed(futures):
#                 results.append(future.result())
#         return JsonResponse({'results': results})

# from selenium.webdriver.common.action_chains import ActionChains
# import undetected_chromedriver as uc  # Import undetected_chromedriver
# from selenium.common.exceptions import TimeoutException, NoSuchElementException
# import requests

# class SingleInstagramBot:
#     # def __init__(self, username, password, recipients, message):
#     def __init__(self, username, password, recipients, message, instagram_account):
#         self.username = username
#         self.password = password
#         self.recipients = recipients
#         self.message = message
#         self.instagram_account = instagram_account
#         self.base_url = 'https://www.instagram.com/'

#         # options = uc.ChromeOptions()
#         # options = webdriver.ChromeOptions()
#         options = uc.ChromeOptions()
#         # options.headless = True
#         options.add_argument('--no-sandbox')
#         options.add_argument('--disable-dev-shm-usage')
#         options.add_argument('--disable-gpu')
#         options.add_argument('--disable-extensions')
#         # options.add_argument('--window-size=1366×768')
#         options.add_argument("--window-size=1920,1080")
#         options.add_argument('--disable-client-side-phishing-detection')

#         # options.binary_location = '/usr/bin/chromedriver' 
#         # self.bot = uc.Chrome(options=options)
#         # self.bot = webdriver.Chrome(options=options)


#         options.add_argument('--headless')
#         options.add_argument('--disable-setuid-sandbox')
#         # options.add_argument('--user-data-dir=/tmp/chromium')
#         options.add_argument('--remote-debugging-port=9222')
#         # logging.basicConfig(level=logging.DEBUG)

#          # Initialize custom logger
#         self.logger = logging.getLogger(f"SingleInstagramBot-{username}")
#         self.logger.setLevel(logging.INFO)
#         formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
#         stream_handler = logging.StreamHandler()
#         stream_handler.setFormatter(formatter)

#         class FilterOutSpecificWarnings(logging.Filter):
#             def filter(self, record):
#                 # Filter out the warnings you want to suppress
#                 message = record.getMessage()
#                 if "Permissions-Policy header: Unrecognized feature: 'battery'" in message \
#                    or "Permissions-Policy header: Unrecognized feature: 'usb-unrestricted'" in message:
#                     return False  # Return False to suppress these log records
#                 return True

#         stream_handler.addFilter(FilterOutSpecificWarnings())
#         self.logger.addHandler(stream_handler)
#         print("Options set SUCCESSFULLY")


#         CHROMEDRIVER_PATH = '/usr/bin/chromedriver'
#         # Check if ChromeDriver exists at the specified path
#         if not os.path.exists(CHROMEDRIVER_PATH):
#             from webdriver_manager.chrome import ChromeDriverManager
#             CHROMEDRIVER_PATH = ChromeDriverManager().install()

        

#         # driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

#         # Ensure that the ChromeDriver path is correct
#         # try: self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options) 

#         #     print("BOT CREATED SUCCESSFULLY") 
#         # except Exception as e: 
#         #     print(f"The Error in bot creation is: {str(e)}")


#         try:

#             chromedriver_path = '/usr/bin/chromedriver'
#             service = Service(CHROMEDRIVER_PATH)
#             # self.bot = webdriver.Chrome(service=service, options=options)
#             self.bot = uc.Chrome(options=options)

#             # self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
#             # self.bot = webdriver.Chrome(options=options)
#             # self.bot = webdriver.Chrome(chromedriver_path, options=options)

#             print("BOT CREATED SUCCESSFULLY")

#         except Exception as e:
#             print(f"The Error in bot is: {str(e)}")


#         # self.bot = uc.Chrome()
#         self.popup_thread = threading.Thread(target=self.handle_popup, daemon=True)
#         self.popup_thread.start()

#         print("Thread started SUCCESSFULLY")
#         try:
#             self.login()
#             print("Login SUCCESSFULLY")
#         except Exception as e:
#             print(f"The error is is --->: {e}")
#             self.logger.error(f"Error during login for {self.username}: {e}")
#             self.bot.quit()

#     def handle_popup(self):
#         while True:
#             try:
#                 not_now_button = WebDriverWait(self.bot, 5).until(
#                     EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Not Now')]"))
#                 )
#                 not_now_button.click()
#                 self.logger.info(f"Popup closed for {self.username}")
#             except Exception as e:
#                 time.sleep(1)

#     # def get_user_id(self,username):
#     #     url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"

#     #     headers = {
#     #         "accept": "*/*",
#     #         "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
#     #         "x-ig-app-id": "936619743392459",
#     #         "x-requested-with": "XMLHttpRequest"
#     #     }

#     #     response = requests.get(url, headers=headers)
#     #     time.sleep(2)
#     #     # print("respnse text :",response.text)

#     #     if response.status_code == 200:
#     # #         print(response.json())  # or response.text if the content is not JSON
#     #         return response.json()['data']['user']['eimu_id']
#     #     else:
#     #         return None
#     #         print(f"Failed to retrieve data: {response.status_code}")

#     def get_user_id(self,username):
#         try:
#             # Navigate to the search API endpoint
#             self.bot.get(f'https://www.instagram.com/web/search/topsearch/?query={username}')

#             # Wait for the page to load
#             time.sleep(5)

#             # Extract JSON response from the page source
#             json_response = self.bot.page_source

#             # Find the JSON data within the page source
#             start_index = json_response.find('{"users":')
#             end_index = json_response.find('</pre>')
#             json_data = json_response[start_index:end_index]

#             # Parse the JSON data
#             data = json.loads(json_data)

#             # Extract pk_id values
#             pk_ids = [user['user']['pk_id'] for user in data['users']]
#             print("The pk ids are as :",pk_ids)
#             print(int(pk_ids[0]))
#             return int(pk_ids[0])


#         # import json
#         # self.bot.get(f'https://www.instagram.com/web/search/topsearch/?query={username}')
#         # json_response = self.bot.page_source


#         # json_response = requests.get(f'https://www.instagram.com/web/search/topsearch/?query={username}')

#         # try:

#         #     data = json.loads(str(json_response))

#         #     # Extract the pk_id values
#         #     pk_ids = [user['user']['pk_id'] for user in data['users']]
#         #     print(pk_ids)
#         #     return pk_ids
#         except:
#             print("Error Occured during the fetching of user id")
#             return "Error Occured"



#     def ad(self,user_id):
#         import requests

#         url = 'https://www.instagram.com/api/graphql'

#         headers = {
#             'accept': '*/*',
#             'accept-language': 'en-US,en;q=0.9',
#             'content-type': 'application/x-www-form-urlencoded',
#             'origin': 'https://www.instagram.com',
#             'sec-fetch-mode': 'cors',
#             'sec-fetch-site': 'same-origin',
#             'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
#             'x-fb-friendly-name': 'PolarisProfilePageContentQuery',
#             'x-fb-lsd': 'AVr41ZWd_UE',
#         }
#         data = {
#                 'lsd': 'AVr41ZWd_UE',
#                 'variables': f'{{"id":"{user_id}","render_surface":"PROFILE"}}',
#                 'server_timestamps': 'true',
#                 'doc_id': '25618261841150840',
#             }
        
#         try:

            
#             response = requests.post(url, headers=headers, data=data)
#             print(response.status_code)
#         #     print(response.text)
#             print(response.json()['data']['user']['interop_messaging_user_fbid'])

#             return response.json()['data']['user']['interop_messaging_user_fbid']
#         except:
#             print("Error Occured During Process")
#             return None
        
#     def get_all_user(self,username, cookies):
#         # Define the URL and updated cookies
#         url = f'https://www.instagram.com/web/search/topsearch/?query={username}'

#         # cookies = {'rur': '"CCO\\05464736011245\\0541751121068:01f7fc95e3ff14d77771115195eb34e8741fe6ee5e852032dad50bef6b4e299fd42ce06f"', 'ds_user_id': '64736011245', 'csrftoken': 'Me5udPTxg64s9YLHImsFZy6L18NbwlY3', 'datr': 'JMl-Zjbdap2Ifo2R5pc_PPnn', 'ig_did': '6A6C31B1-DF71-4DCD-A428-00B9D24C4BB4', 'sessionid': '64736011245%3ArtfRByw809pNAl%3A10%3AAYdRcUIh5PGuz67IgY3669NMIFQzw_hfKvQ3zuucXQ', 'ps_n': '1', 'dpr': '1.25', 'ps_l': '1', 'mid': 'Zn7JJAALAAEOLRonIIhzpY333usr', 'wd': '1036x651'}

#         cookies = cookies

#         headers = {
#             'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
#             'Referer': 'https://www.instagram.com/',
#             'X-Requested-With': 'XMLHttpRequest',
#         }

#         # Send a GET request to the Instagram API with cookies and headers
#         response = requests.get(url, cookies=cookies, headers=headers)

#         # Check if request was successful (status code 200)
#         if response.status_code == 200:
#         #     print(response.json())  # Print the JSON response
#             json_response = response.json()
#             pk_ids = [user['user']['pk_id'] for user in json_response['users']]
#             print(pk_ids)
#             return int(pk_ids[0])
#             print(pk_ids[0])

#         else:
#             print(f"Request failed with status code {response.status_code}")
#             print(response.text)  # Print the response content for further inspection
#             return None

#     def login(self):
#         self.bot.get(self.base_url)
#         try:
#             enter_username = WebDriverWait(self.bot, 10).until(
#                 EC.presence_of_element_located((By.NAME, 'username')))
#             enter_username.send_keys(self.username)

#             enter_password = WebDriverWait(self.bot, 10).until(
#                 EC.presence_of_element_located((By.NAME, 'password')))
#             enter_password.send_keys(self.password)
#             enter_password.send_keys(Keys.RETURN)
#             time.sleep(5)
#         except Exception as e:
#             print(f"The error2222222222222222 --->: {e}")
#             self.logger.error(f"Error entering login credentials: {e}")

#         time.sleep(3)

#         recipient = self.recipients
#         message = self.message


#         try:
#             # self.bot.find_element(By.XPATH,
#             #                       '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[5]/div/div/span/div/a/div/div[1]/div/div[1]').click()
            
#             cook = self.bot.get_cookies()
#             # Convert to the desired format
#             cookies_list=cook

#             cookies = {}
#             for cookie in cookies_list:
#                 cookies[cookie['name']] = cookie['value']

#             client_user_unique_code = self.get_all_user(recipient, cookies)



#             # user_id = self.get_user_id(recipient)
#             # user_unique_code = self.ad(user_id)
#             print("user_unique_code:   ",client_user_unique_code)
#             # user_unique_code = self.get_user_id(recipient)
#             user_unique_code = self.ad(client_user_unique_code)
#             time.sleep(2)
#             self.bot.get(f"https://www.instagram.com/direct/t/{user_unique_code}/")



#             time.sleep(2)
            
#         except Exception as e:
#             self.logger.error(f"Error navigating to User Message section: {e}")
#             return

#         # for recipient, messages in zip(self.recipients, self.message):
#         #     for message in messages:
#         try:
#             time.sleep(3)
#             try:
#             #     # new_message_button = WebDriverWait(self.bot, 5).until(
#             #     #     # EC.visibility_of_element_located(
#             #     #         EC.element_to_be_clickable(
#             #     #         # (By.CLASS_NAME, 'x78zum5')
#             #     #         (By.CSS_SELECTOR, 'div.x78zum5[role="button"]')
#             #     #         # (By.XPATH,'/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[1]/div/div[1]/div[2]/div/div/div')
#             #     # ))
#             #     # new_message_button.click()
#             #     try:
#             #         # wait = WebDriverWait(self.bot, 5)
#             #         # svg_element = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, 'svg[aria-label="New message"]')))

#             #         # # Use JavaScript to click the SVG element
#             #         # # self.bot.execute_script("arguments[0].click();", svg_element)

#             #         # # Use JavaScript to create and dispatch a click event
#             #         # self.bot.execute_script("""
#             #         # var event = new MouseEvent('click', {
#             #         #     bubbles: true,
#             #         #     cancelable: true,
#             #         #     view: window
#             #         # });
#             #         # arguments[0].dispatchEvent(event);
#             #         # """, svg_element)

#             #         # wait = WebDriverWait(self.bot, 5)
#             #         # svg_element = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'svg[aria-label="New message"]')))
                    
#             #         # # Click the SVG element directly
#             #         # svg_element.click()
#             #         try:
#             #             wait = WebDriverWait(self.bot, 5)
#             #             svg_element = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'svg[aria-label="New message"]')))
                        
#             #             # Use ActionChains to click the SVG element
#             #             action = ActionChains(self.bot)
#             #             action.move_to_element(svg_element).click().perform()
#             #         except:
#             #             element = WebDriverWait(self.bot, 10).until( EC.element_to_be_clickable((By.CSS_SELECTOR, "div[role='button'][tabindex='0']")) ) 
#             #             # element.click()

#             #             self.bot.execute_script("arguments[0].click();", element)

#             #     except Exception as e:
#             #         self.logger.error(f"Error recipient 111111111111111111111111 {recipient}: {e}")

#             #     time.sleep(2)
#             #     try:
#             #         # recipient_input = WebDriverWait(self.bot, 5).until(
#             #         #     # EC.visibility_of_element_located(
#             #         #     EC.element_to_be_clickable(
                            
#             #         #         # (By.XPATH,'/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[2]/div/div[2]/input')
#             #         #         # (By.CLASS_NAME, 'x5ur3kl')
#             #         #         # (By.CSS_SELECTOR, 'input[name="queryBox"]')
#             #         #         (By.NAME, "queryBox")
#             #         #         ))
#             #         # recipient_input.send_keys(recipient)

#             #         # time.sleep(2)



#             #         try:
#             #             # Method 1: By name
#             #             search_box = self.bot.find_element(By.NAME, "queryBox")
#             #         except Exception as e:
#             #             try:
#             #                 # Method 4: By CSS selector with attribute placeholder
#             #                 search_box = self.bot.find_element(By.CSS_SELECTOR, 'input[placeholder="Search..."]')
#             #             except Exception as e:
#             #                 try:
#             #                     # Method 6: By XPATH with attribute placeholder
#             #                     search_box = self.bot.find_element(By.XPATH, '//input[@placeholder="Search..."]')
#             #                 except Exception as e:
#             #                     try:
#             #                         # Method 7: By XPATH with multiple class names
#             #                         search_box = self.bot.find_element(By.XPATH, '//input[contains(@class, "x5ur3kl") and contains(@class, "xopu45v")]')
#             #                     except Exception as e:
#             #                         try:
#             #                             # Method 8: By XPATH with type attribute
#             #                             search_box = self.bot.find_element(By.XPATH, '//input[@type="text"]')
#             #                         except Exception as e:
#             #                             try:
#             #                                 # Method 9: By XPATH with name attribute
#             #                                 search_box = self.bot.find_element(By.XPATH, '//input[@name="queryBox"]')
#             #                             except Exception as e:
#             #                                 try:
#             #                                     # Method 10: By partial link text (not recommended for input but shown as an example)
#             #                                     search_box = self.bot.find_element(By.PARTIAL_LINK_TEXT, "Search")
#             #                                 except Exception as e:
#             #                                     print("Element not found with any method")
#             #         search_box.send_keys(recipient)

#             #         time.sleep(2)





#             #     except Exception as e:
#             #         self.logger.error(f"Error recipient 222222222222222222222222222 {recipient}: {e}")
#             #         self.close_browser()

#             #     # Recipient Suggestion

#             #     # recipient_suggestion = WebDriverWait(self.bot, 5).until(
#             #     #     EC.visibility_of_element_located(
#             #     #         (By.XPATH,'/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[3]/div/div/div[1]/div[1]')
#             #     #     ))
#             #     # recipient_suggestion.click()
                
#             #     try:
#             #         # Ensure the element is visible and clickable
#             #         suggestion_element = WebDriverWait(self.bot, 10).until(
#             #             EC.element_to_be_clickable((By.XPATH, '//div[@role="button" and @tabindex="0"]'))
#             #             # EC.element_to_be_clickable((By.CSS_SELECTOR, '.x9f619.xjbqb8w.x78zum5.x168nmei.x13lgxp2.x5pf9jr.xo71vjh.x1uhb9sk.x1plvlek.xryxfnj.x1c4vz4f.x2lah0s.x1q0g3np.xqjyukv.x6s0dn4.x1oa3qoh.x1nhvcw1'))
#             #         )


#             #         suggestion_element.click()

#             #         # Scroll to the element
#             #         # self.bot.execute_script("arguments[0].scrollIntoView(true);", suggestion_element)

#             #         # # Pause to allow any potential overlays to load
#             #         # time.sleep(2)

#             #         # # Remove any potentially overlapping elements
#             #         # self.bot.execute_script("""
#             #         #     var elements = document.getElementsByClassName('x1qjc9v5 x9f619 x78zum5 xdt5ytf x1iyjqo2 xl56j7k');
#             #         #     for(var i = 0; i < elements.length; i++) {
#             #         #         elements[i].style.display = 'none';
#             #         #     }
#             #         # """)

#             #         # Pause to ensure the DOM is updated
#             #         time.sleep(2)

#             #         # # Use Action Chains to move to the element before clicking
#             #         # actions = ActionChains(self.bot)
#             #         # actions.move_to_element(suggestion_element).click().perform()

                    
#             #         time.sleep(2)
#             #         print("SUGGESTION CODE PASSED")

#             #     except Exception as e:
#             #         self.logger.error(f"Error recipient 33333333333333333333333333333 {recipient}: {e}")
#             #         self.close_browser()
                
                
                
                
#             #     # chat Button


#             #     # next_button = WebDriverWait(self.bot, 5).until(
#             #     #     # EC.visibility_of_element_located(
#             #     #         EC.element_to_be_clickable(
#             #     #         # (By.XPATH, '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[4]')
#             #     #         # (By.CLASS_NAME, 'x1i10hfl')
#             #     #         (By.CSS_SELECTOR, 'div.x9f619.xjbqb8w.x78zum5.x168nmei.x13lgxp2.x5pf9jr.xo71vjh.x1uhb9sk.x1plvlek.xryxfnj.x1iyjqo2.x2lwn1j.xeuugli.xdt5ytf.xqjyukv.x1cy8zhl.x1oa3qoh.x1nhvcw1')
#             #     #         ))
#             #     # next_button.click()


#             #     try:
#             #         # Wait until the Chat Button is present in the DOM
#             #         Chat_button = WebDriverWait(self.bot, 5)
#             #         # element = Chat_button.until(EC.presence_of_element_located((By.CSS_SELECTOR, 'div[role="button"][tabindex="0"]')))
#             #         # chat_element = Chat_button.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'div[role="button"]:contains("Chat")')))
#             #         chat_element = Chat_button.until(EC.element_to_be_clickable((By.XPATH, '//div[text()="Chat" and @role="button"]')))
#             #         # Use JavaScript to create and dispatch a click event
#             #         self.bot.execute_script("""
#             #         var event = new MouseEvent('click', {
#             #             bubbles: true,
#             #             cancelable: true,
#             #             view: window
#             #         });
#             #         arguments[0].dispatchEvent(event);
#             #         """, chat_element)

#             #     except Exception as e:
#             #         self.logger.error(f"Error recipient 44444444444444444444444444444444 {recipient}: {e}")
#             #         self.close_browser()


#             #     time.sleep(2)
#             # except Exception as e:
#             #     Message.objects.create(
#             #         instagram_account =self.instagram_account,
#             #         recipient=recipient, 
#             #         content = message,
#             #         scheduled_time = timezone.now(),
#             #         sent = False,
#             #         sent_time = timezone.now(),
#             #         error = f"Error adding recipient {recipient}: {e}"
#             #         )
#             #     self.logger.error(f"Error adding recipient {recipient}: {e}")
                

#             # try:
#             #     # message_area = WebDriverWait(self.bot, 5).until(
#             #     #     EC.visibility_of_element_located((By.XPATH,
#             #     #                                       #'/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[2]/div/div/div/div/div/div/div[2]/div/div/div[2]/div/div/div[2]/div/div[1]/p'))
#             #     #                                       '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[2]/div/div/div/div/div/div/div[2]/div/div/div[3]/div/div/div[2]/div/div'))
#             #     # )

#             #     # message_area = WebDriverWait(self.bot, 5).until(
#             #     #     EC.visibility_of_element_located((By.CSS_SELECTOR, 'x1n2onr6'))
#             #     # )
#             #     time.sleep(2)
#             #     # message_area = WebDriverWait(self.bot, 10).until(
#             #     #     EC.visibility_of_element_located((By.XPATH, '//div[@contenteditable="true" and @aria-label="Message"]'))
#             #     # )

                
#             #     # message_area.click()





# #================================================WE WANT FROM HERE++++=========================+++++++++++++++++++++++++++++++                    

#                 message_area = WebDriverWait(self.bot, 5)
#                 # message_area_element = message_area.until(EC.presence_of_element_located((By.CSS_SELECTOR, 'div[aria-describedby="Message"][role="textbox"][contenteditable="true"]')))
#                 message_area_element = message_area.until(EC.presence_of_element_located((By.XPATH, '//div[@aria-describedby="Message" and @role="textbox" and @contenteditable="true"]')))
#                 # Use JavaScript to focus and interact with the contenteditable div
#                 self.bot.execute_script("""
#                 arguments[0].focus();
#                 arguments[0].innerHTML = '<p class="xat24cr xdj266r">Your message here</p>';
#                 var event = new Event('input', {
#                     bubbles: true,
#                     cancelable: true,
#                 });
#                 arguments[0].dispatchEvent(event);
#                 """, message_area_element)

#                 # message_area.send_keys(f"{message}")



#                 time.sleep(1)
#                 # message_area.send_keys(Keys.ENTER)
#                 # time.sleep(2)


#                 print("The message is prior send message: ",message)


#                 message_area_element.send_keys(message)
#                 print("The message is AFTER send message: ",message)
#                 time.sleep(1)
#                 message_area_element.send_keys(Keys.RETURN)
#                 print("The message is AFTER ENTER: ",message)
#                 time.sleep(2)
#                 mess=Message.objects.create(
#                     instagram_account =self.instagram_account, 
#                     recipient=recipient,
#                     content = message,
#                     scheduled_time = timezone.now(),
#                     sent = True,
#                     sent_time = timezone.now()
#                     )
                
#                 mess.sent =True
#                 mess.save()
#                 time.sleep(1)
#             except Exception as e:
#                 self.logger.error(f"Error sending message to {recipient}: {e}")
#                 Message.objects.create(
#                     instagram_account =self.instagram_account, 
#                     recipient=recipient,
#                     content = message,
#                     scheduled_time = timezone.now(),
#                     sent = False,
#                     sent_time = timezone.now(),
#                     error = f"Error sending message to {recipient}: {e}"
#                     )
                
#             finally:
#                 self.close_browser()
#                 time.sleep(2)

#         except Exception as e:
#             Message.objects.create(
#                     instagram_account =self.instagram_account, 
#                     recipient=recipient,
#                     content = message,
#                     scheduled_time = timezone.now(),
#                     sent = False,
#                     sent_time = timezone.now(),
#                     error = f"Error handling message for {recipient}: {e}")
#             self.logger.error(f"Error handling message for {recipient}: {e}")

#     def logout(self):
#         try:
#             # profile_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[8]/div/span/div/a/div/div/div/div/span"
#             # self.bot.find_element(By.XPATH, profile_xpath).click()
            
#             profile_ = WebDriverWait(self.bot, 3).until(
#             EC.element_to_be_clickable((By.CSS_SELECTOR, "span[role='link'][tabindex='-1']"))
#             # EC.element_to_be_clickable((By.XPATH, '//svg[@aria-label="Settings"]'))
#             )
#             print("first DONE nfjksdjf")
#             profile_.click()

#             time.sleep(1)
#             print("inside Logout 11111111111111111111111")
#             # setting_icon_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[2]/div/div[2]/section/main/div/header/section[2]/div/div/div[3]/div/div"
#             # self.bot.find_element(By.XPATH, setting_icon_xpath).click()

#             try:
#                 setting_ = WebDriverWait(self.bot, 3).until(
#                     EC.element_to_be_clickable((By.CSS_SELECTOR, "div[role='button'][tabindex='0']"))
#                 )
#                 setting_.click()
#                 print("Second DONE nfjksdjf")

#             except Exception as e:
#                 print(f"An error occurred 11111111111111111: {e}")

#             time.sleep(1)
#             print("inside Logout 22222222222222222222222")
#             # logout_xpath = "/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/button[7]"
#             # self.bot.find_element(By.XPATH, logout_xpath).click()

#             try:
#                 # logout_ = WebDriverWait(self.bot, 10).until(
#                 #     # EC.element_to_be_clickable((By.CSS_SELECTOR, "button[tabindex='0']"))
#                 #     EC.element_to_be_clickable((By.XPATH, '//button[text()="Log Out"]')),
#                 # )
#                 # logout_.click()


#                 try:
#                     # Try to click the button using CSS Selector
#                     log_out_button = WebDriverWait(self.bot, 10).until(
#                         EC.element_to_be_clickable((By.CSS_SELECTOR, 'button.xjbqb8w.x1qhh985.xcfux6l.xm0m39n.x1yvgwvq.x13fuv20.x178xt8z.x1ypdohk.xvs91rp.x1evy7pa.xdj266r.x11i5rnm.xat24cr.x1mh8g0r.x1wxaq2x.x1iorvi4.x1sxyh0.xjkvuk6.xurb0ha.x2b8uid.x87ps6o.xxymvpz.xh8yej3.x52vrxo.x4gyw5p.x5n08af'))
#                     )
#                     log_out_button.click()
#                     print("Clicked on the element using CSS Selector")
#                 except Exception as e_css:
#                     print(f"CSS Selector failed: {e_css}")
                    
#                     try:
#                         # Try to click the button using XPath
#                         log_out_button = WebDriverWait(self.bot, 10).until(
#                             EC.element_to_be_clickable((By.XPATH, '//button[text()="Log Out"]'))
#                         )
#                         log_out_button.click()
#                         print("Clicked on the element using XPath")
#                     except Exception as e_xpath:
#                         print(f"XPath failed: {e_xpath}")
                        
#                         try:
#                             # Try to click the button using Class Name
#                             log_out_button = WebDriverWait(self.bot, 10).until(
#                                 EC.element_to_be_clickable((By.CLASS_NAME, 'xjbqb8w'))
#                             )
#                             log_out_button.click()
#                             print("Clicked on the element using Class Name")
#                         except Exception as e_class:
#                             print(f"Class Name failed: {e_class}")
                            
#                             try:
#                                 # Try to click the button using Partial Link Text
#                                 log_out_button = WebDriverWait(self.bot, 10).until(
#                                     EC.element_to_be_clickable((By.PARTIAL_LINK_TEXT, 'Log Out'))
#                                 )
#                                 log_out_button.click()
#                                 print("Clicked on the element using Partial Link Text")
#                             except Exception as e_partial_link:
#                                 print(f"Partial Link Text failed: {e_partial_link}")
#                                 print("All methods failed to click the element")
#                 print("Third DONE nfjksdjf")
#             except Exception as e:
#                 print(f"An error occurred 22222222222222222: {e}")


#             print("inside Logout 33333333333333333333333")
#             time.sleep(2)
#         except Exception as e:
#             self.logger.error(f"An error occurred during logout: {e}")

#     def close_browser(self):
#         self.logout()
#         print("Logout DONE")
#         time.sleep(3)
#         print("Closing Browser")
#         self.bot.quit()

# def single_send_messages(account):
#     username = account['username']
#     password = account['password']
#     recipients = account['recipients']
#     message = account['message']
#     instagram_account = account['instagram_account']
#     try:
#         # instagram_bot = InstagramBot(username, password, recipients, message)

#         instagram_bot = SingleInstagramBot(username, password, recipients, message, instagram_account)

#         # instagram_bot.close_browser()
#         return f"Messages sent from {username} to {recipients}"
#     except Exception as e:
#         # self.logger.error(f"An error occurred with account {username}: {e}")
#         return f"Failed to send messages from {username}: {str(e)}"
   


from instagrapi import Client
from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils import timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class SingleInstaMessageView(APIView):

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        instagram_account_id = request.data.get('instagram_account_id')

        if not instagram_account_id:
            return Response({"Message": "Please Provide instagram_account_id"})
        
        recipient_list = request.data.get('recipient_list')

        if not recipient_list:
            return Response({"Message": "Recipient not found!!!!"})
        
        message_list = request.data.get('message_list')
        custom_message = request.data.get('custom_message')

        if not message_list and not custom_message:
            return Response({"Message": "message not found!!!!"})
        
        if not custom_message:
            try:
                message_template = MessageTemplate.objects.get(id=message_list)
                date = request.data.get('date', 'Date')
                name = request.data.get('name', 'Instagram User')
                username = request.data.get('username', 'username_not_provided')

                message_content = message_template.template_content.format(
                    name=name[0],
                    username=username[0],
                    date=date,
                )

            except MessageTemplate.DoesNotExist:
                return Response({"Message": f"Message template with ID {message_list} does not exist"}, status=404)
        else:
            try:
                date = request.data.get('date', 'Date')
                name = request.data.get('name', 'Instagram User')
                username = request.data.get('username', 'username_not_provided')

                message_content = custom_message.format(
                    name=name[0],
                    username=username[0],
                    date=date
                )
            except:    
                message_content = custom_message

        ins = instagram_accounts.objects.filter(id=instagram_account_id).first()
        if not ins:
            return Response({"Message": "Instagram account not found"}, status=404)

        username = ins.username
        password = ins.password

        accounts = [
            {'username': username, 'password': password, 'recipients': recipient_list[0], 'message': message_content, 'instagram_account': ins}
        ]

        max_simultaneous_logins = 10

        results = []
        with ThreadPoolExecutor(max_workers=max_simultaneous_logins) as executor:
            futures = [executor.submit(single_send_messages, account) for account in accounts]
            for future in as_completed(futures):
                results.append(future.result())
        return JsonResponse({'results': results})

class SingleInstagramBot:
    def __init__(self, username, password, recipients, message, instagram_account):
        self.username = username
        self.password = password
        self.recipients = recipients
        self.message = message
        self.instagram_account = instagram_account

        self.client = Client()
        self.logger = logging.getLogger(f"SingleInstagramBot-{username}")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)

        try:
            self.client.login(username, password)
            self.logger.info(f"Logged in successfully as {username}")
        except Exception as e:
            self.logger.error(f"Error during login for {self.username}: {e}")
            raise e

    def send_message(self):
        try:
            user_id = self.client.user_id_from_username(self.recipients)
            self.client.direct_send(self.message, [user_id])
            self.logger.info(f"Message sent to {self.recipients}")
            Message.objects.create(
                instagram_account=self.instagram_account,
                recipient=self.recipients,
                content=self.message,
                scheduled_time=timezone.now(),
                sent=True,
                sent_time=timezone.now()
            )
            return f"Message sent to {self.recipients}"
        except Exception as e:
            self.logger.error(f"Error sending message to {self.recipients}: {e}")
            Message.objects.create(
                instagram_account=self.instagram_account,
                recipient=self.recipients,
                content=self.message,
                scheduled_time=timezone.now(),
                sent=False,
                sent_time=timezone.now(),
                error=str(e)
            )
            return f"Failed to send message to {self.recipients}: {str(e)}"

    def logout(self):
        self.client.logout()
        self.logger.info(f"Logged out {self.username}")

def single_send_messages(account):
    username = account['username']
    password = account['password']
    recipients = account['recipients']
    message = account['message']
    instagram_account = account['instagram_account']

    # try:
    #     instagram_bot = SingleInstagramBot(username, password, recipients, message, instagram_account)
    #     result = instagram_bot.send_message()
    #     instagram_bot.logout()
    #     # return f"Messages sent from {username} to {recipients}"
    #     if result:
    #         # return result
    #         return f"Messages sent from {username} to {recipients}"
    # except Exception as e:
    #     return f"Failed to send messages from {username}: {str(e)}"

    try:
        instagram_bot = SingleInstagramBot(username, password, recipients, message, instagram_account)
        result = instagram_bot.send_message()
        instagram_bot.logout()
        return result  # Return the result directly
    except Exception as e:
        error_message = f"Failed to send messages from {username} to {recipients}: {str(e)}"
        logging.error(error_message)
        return error_message  # Return the error message













   


class TaskStatusView(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        task_id = request.data.get("task_id")
        if not task_id:
            return Response({"Message":"No Task Id Received"})

        try:

            task = Task.objects.get(id=task_id,instagram_account__user=user)
            
            task_tmp={
                'task_id': task.id,
                'total_messages': task.total_messages,
                'sent_messages': task.sent_messages,
                'failed_messages': task.failed_messages,
                'status': task.status
            }
        

            message_data = []
            for message in Message.objects.filter(tasks=task):
                tmp = {
                    "Sender Username":message.instagram_account.username,
                    "Recipient": message.recipient,
                    "Content": message.content,
                    'scheduled_time': message.scheduled_time,
                    "sent_status": message.sent,
                    "sent_time": message.sent_time,
                    'error_message': message.error,
                }
                message_data.append(tmp)


            return Response({"Message":"Task Data Fetched Successuly","task":task_tmp,"Message_data":message_data}, status=status.HTTP_200_OK)
        except Task.DoesNotExist:
            return Response({"Message": "Task not found"}, status=status.HTTP_404_NOT_FOUND)
        
class TaskStatusbyUsername(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        username_ = request.data.get("username")
        if not username_:
            return Response({"Message":"No username Received"})

        try:
            instagram_account = instagram_accounts.objects.filter(user=user, username=username_).first()
            if not instagram_account:
                return Response({"Message": "Instagram account not found for this user"}, status=status.HTTP_404_NOT_FOUND)

            task_all = Task.objects.filter(instagram_account=instagram_account)

            # task_all = Task.objects.filter(instagram_account__user=user,instagram_account__username=username_)
            # print("TASKALL :",task_all)
            if task_all.exists():
                all_data = []
                for task in task_all:

                    task_tmp={
                        'task_id': task.id,
                        'total_messages': task.total_messages,
                        'sent_messages': task.sent_messages,
                        'failed_messages': task.failed_messages,
                        'status': task.status
                    }
                

                    message_data = []
                    for message in task.message.all():
                        tmp = {
                            "Sender Username":message.instagram_account.username,
                            "Recipient": message.recipient,
                            "Content": message.content,
                            'scheduled_time': message.scheduled_time,
                            "sent_status": message.sent,
                            "sent_time": message.sent_time,
                            'error_message': message.error,
                        }
                        message_data.append(tmp)

                    all_data.append({"task":task_tmp, 'Message_data':message_data})

                return Response({"Message":"Task Data Fetched Successuly","task_data":all_data}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "Task not found"}, status=status.HTTP_404_NOT_FOUND)
        except Task.DoesNotExist:
            return Response({"Message": "Task not found"}, status=status.HTTP_404_NOT_FOUND)


        

class AdminTaskStatusView(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=user_id).first()

        user_Admin, is_superuser = IsSuperUser(user_id)
        if not user_Admin or not is_superuser:
            msg = 'could not found the Admin user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        # if not user:
        #     return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # task_id = request.data.get("task_id")
        # if not task_id:
        #     return Response({"Message":"No Task Id Received"})

        try:

            task_all = Task.objects.all()
            all_data = []
            for task in task_all:
            
                task_tmp={
                    'task_id': task.id,
                    'total_messages': task.total_messages,
                    'sent_messages': task.sent_messages,
                    'failed_messages': task.failed_messages,
                    'status': task.status
                }
            

                message_data = []
                for message in Message.objects.filter(tasks=task):
                    tmp = {
                        "Sender Username":message.instagram_account.username,
                        "Recipient": message.recipient,
                        "Content": message.content,
                        'scheduled_time': message.scheduled_time,
                        "sent_status": message.sent,
                        "sent_time": message.sent_time,
                        'error_message': message.error,
                    }
                    message_data.append(tmp)

                all_data.append({"task":task_tmp, 'Message_data':message_data})


            return Response({"Message":"Task Data Fetched Successuly","all_task_data":all_data}, status=status.HTTP_200_OK)
        except Task.DoesNotExist:
            return Response({"Message": "Task not found"}, status=status.HTTP_404_NOT_FOUND)
