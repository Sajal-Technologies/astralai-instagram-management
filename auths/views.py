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

    def get(self, request, format=None):
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
    def get(self, request, format=None):
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
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        

        try:
            # Find all Lead objects associated with the specified csv_file_number and delete them
            lead_obj= Lead.objects.filter(instagram_account__user=user)

            if not lead_obj:
                return Response({'Message': 'No Lead objects found'}, status=status.HTTP_404_NOT_FOUND)

            lead_data = []

            for leads in lead_obj:
                tmp={

                    "instagram_account":leads.instagram_account.username,
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
    def post(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        temp_id = request.data.get('temp_id')

        if not temp_id:
            return Response({'Message': 'Template id not found'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            Mess_obj= MessageTemplate.objects.filter(user=user, id= temp_id).first()

            if not Mess_obj:
                return Response({'Message': 'No Message Template found'}, status=status.HTTP_404_NOT_FOUND)
            
            tmp={
            "Message Template id" : Mess_obj.id,
            "Message Template id" : Mess_obj.user.email,
            "Message Template id" : Mess_obj.template_name,
            "Message Template id" : Mess_obj.template_content}

            return Response({'Message': 'Message Template fetched successfully', "Message_template_data":tmp}, status=status.HTTP_200_OK)

        except MessageTemplate.DoesNotExist:
            return Response({'Message': 'No Message Template found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"Message":f"Error Occured while fetching Message Template: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#----------------------------------------------------------------Message Template-------------------------------------------------


#----------------------------------------------------------------Instagram Message View--------------------------------------------------------



# instabot/views.py
import time
import logging
import threading
from django.http import JsonResponse
from django.views import View
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
# import undetected_chromedriver as uc
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

class InstagramBot:
    # def __init__(self, username, password, recipients, message):
    def __init__(self, username, password, recipients, message, instagram_account):
        self.username = username
        self.password = password
        self.recipients = recipients
        self.message = message
        self.instagram_account = instagram_account
        self.base_url = 'https://www.instagram.com/'

        # options = uc.ChromeOptions()
        options = webdriver.ChromeOptions()
        # options.headless = True
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-extensions')
        options.add_argument('--window-size=1200x600')
        options.add_argument('--disable-client-side-phishing-detection')

        # options.binary_location = '/usr/bin/chromedriver' 
        # self.bot = uc.Chrome(options=options)
        # self.bot = webdriver.Chrome(options=options)


        options.add_argument('--headless')
        options.add_argument('--disable-setuid-sandbox')
        options.add_argument('--user-data-dir=/tmp/chromium')
        options.add_argument('--remote-debugging-port=9222')
        print("Options set SUCCESSFULLY")


        CHROMEDRIVER_PATH = '/usr/bin/chromedriver'
        # Check if ChromeDriver exists at the specified path
        if not os.path.exists(CHROMEDRIVER_PATH):
            from webdriver_manager.chrome import ChromeDriverManager
            CHROMEDRIVER_PATH = ChromeDriverManager().install()

        

        # driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

        # Ensure that the ChromeDriver path is correct
        try:
        
            chromedriver_path = '/usr/bin/chromedriver'
            service = Service(CHROMEDRIVER_PATH)
            self.bot = webdriver.Chrome(service=service, options=options)

            # self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
            # self.bot = webdriver.Chrome(options=options)
            # self.bot = webdriver.Chrome(chromedriver_path, options=options)

            print("BOT CREATED SUCCESSFULLY")

        except Exception as e:
            print(f"The Error in bot is: {str(e)}")


        # self.bot = uc.Chrome()
        self.popup_thread = threading.Thread(target=self.handle_popup, daemon=True)
        self.popup_thread.start()

        print("Thread started SUCCESSFULLY")
        try:
            self.login()
            print("Login SUCCESSFULLY")
        except Exception as e:
            print(f"The error is is --->: {e}")
            logging.error(f"Error during login for {self.username}: {e}")
            self.bot.quit()

    def handle_popup(self):
        while True:
            try:
                not_now_button = WebDriverWait(self.bot, 5).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Not Now')]"))
                )
                not_now_button.click()
                logging.info(f"Popup closed for {self.username}")
            except Exception as e:
                time.sleep(1)

    def login(self):
        self.bot.get(self.base_url)
        try:
            enter_username = WebDriverWait(self.bot, 20).until(
                EC.presence_of_element_located((By.NAME, 'username')))
            enter_username.send_keys(self.username)

            enter_password = WebDriverWait(self.bot, 20).until(
                EC.presence_of_element_located((By.NAME, 'password')))
            enter_password.send_keys(self.password)
            enter_password.send_keys(Keys.RETURN)
            time.sleep(5)
        except Exception as e:
            print(f"The error2222222222222222 --->: {e}")
            logging.error(f"Error entering login credentials: {e}")
            return

        time.sleep(3)
        try:
            self.bot.find_element(By.XPATH,
                                  '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[5]/div/div/span/div/a/div/div[1]/div/div[1]').click()
            time.sleep(2)
        except Exception as e:
            logging.error(f"Error navigating to message section: {e}")
            return

        for recipient, messages in zip(self.recipients, self.message):
            for message in messages:
                try:
                    time.sleep(3)
                    try:
                        new_message_button = WebDriverWait(self.bot, 5).until(
                            EC.visibility_of_element_located((By.XPATH,
                                                              '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[1]/div/div[1]/div[2]/div/div/div'))
                        )
                        new_message_button.click()
                        time.sleep(2)
                        recipient_input = WebDriverWait(self.bot, 5).until(
                            EC.visibility_of_element_located((By.XPATH,
                                                              '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[2]/div/div[2]/input'))
                        )
                        recipient_input.send_keys(recipient)
                        time.sleep(2)

                        recipient_suggestion = WebDriverWait(self.bot, 5).until(
                            EC.visibility_of_element_located((By.XPATH,
                                                              '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[3]/div/div/div[1]/div[1]'))
                        )
                        recipient_suggestion.click()
                        time.sleep(2)

                        next_button = WebDriverWait(self.bot, 5).until(
                            EC.visibility_of_element_located((By.XPATH, '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[4]'))
                        )
                        next_button.click()
                        time.sleep(2)
                    except Exception as e:
                        Message.objects.create(
                            instagram_account =self.instagram_account,
                            recipient=recipient, 
                            content = message,
                            scheduled_time = timezone.now(),
                            sent = False,
                            sent_time = timezone.now()
                            )
                        logging.error(f"Error adding recipient {recipient}: {e}")
                        continue

                    try:
                        message_area = WebDriverWait(self.bot, 5).until(
                            EC.visibility_of_element_located((By.XPATH,
                                                              '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[2]/div/div/div/div/div/div/div[2]/div/div/div[2]/div/div/div[2]/div/div[1]/p'))
                        )
                        time.sleep(3)
                        message_area.send_keys(message)
                        time.sleep(1)
                        message_area.send_keys(Keys.RETURN)
                        time.sleep(2)
                        mess=Message.objects.create(
                            instagram_account =self.instagram_account, 
                            recipient=recipient,
                            content = message,
                            scheduled_time = timezone.now(),
                            sent = True,
                            sent_time = timezone.now()
                            )
                        
                        mess.sent =True
                        mess.save()
                        time.sleep(1)
                    except Exception as e:
                        logging.error(f"Error sending message to {recipient}: {e}")
                        Message.objects.create(
                            instagram_account =self.instagram_account, 
                            recipient=recipient,
                            content = message,
                            scheduled_time = timezone.now(),
                            sent = False,
                            sent_time = timezone.now()
                            )
                        continue
                    finally:
                        self.bot.refresh()
                        time.sleep(2)

                except Exception as e:
                    Message.objects.create(
                            instagram_account =self.instagram_account, 
                            recipient=recipient,
                            content = message,
                            scheduled_time = timezone.now(),
                            sent = False,
                            sent_time = timezone.now())
                    logging.error(f"Error handling message for {recipient}: {e}")

    def logout(self):
        try:
            profile_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[8]/div/span/div/a/div/div/div/div/span"
            self.bot.find_element(By.XPATH, profile_xpath).click()
            time.sleep(1)

            setting_icon_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[2]/div/div[2]/section/main/div/header/section[2]/div/div/div[3]/div/div"
            self.bot.find_element(By.XPATH, setting_icon_xpath).click()
            time.sleep(1)

            logout_xpath = "/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/button[7]"
            self.bot.find_element(By.XPATH, logout_xpath).click()
            time.sleep(2)
        except Exception as e:
            logging.error(f"An error occurred during logout: {e}")

    def close_browser(self):
        self.logout()
        time.sleep(3)
        self.bot.quit()

def send_messages(account):
    username = account['username']
    password = account['password']
    recipients = account['recipients']
    message = account['message']
    instagram_account = account['instagram_account']
    try:
        # instagram_bot = InstagramBot(username, password, recipients, message)

        instagram_bot = InstagramBot(username, password, recipients, message, instagram_account)

        instagram_bot.close_browser()
        return f"Messages sent from {username} to {recipients}"
    except Exception as e:
        logging.error(f"An error occurred with account {username}: {e}")
        return f"Failed to send messages from {username}"

from django.views.decorators.csrf import csrf_exempt

class InstagramBotView(APIView):

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


        instagram_account_id=request.data.get('instagram_account_id')

        if not instagram_account_id:
            return Response({"Message":"Please Provide instagram_account_id"})
        
        recipient_list=request.data.get('recipient_list')

        if not isinstance(recipient_list, list):
            return Response({"Message": "Recipient_list must be a list. ex- ['recipient1', 'recipient2', 'recipient3']"})

        if not recipient_list:
            return Response({"Message":"Recipient_list not found!!!!"})
        

        message_list=request.data.get('message_list')

        if not isinstance(message_list, list):
            return Response({"Message": "message_list must be a list. ex- if you have 3 recipient then [[Template_id1, Template_id2],[Template_id3, Template_id1], [Template_id4]]"})

        if not message_list:
            return Response({"Message":"message_list not found!!!!"})
        
        messages = []
        for templates in message_list:
            if not isinstance(templates, list) or len(templates) == 0:
                return Response({"Message": "Each item in message_list must be a non-empty list of template IDs"}, status=400)

            template_messages = []  # Initialize a list to store messages for current set of templates
            for template_id in templates:
                try:
                    # Fetch message_template object from the database
                    message_template = MessageTemplate.objects.get(id=template_id)

                    # Retrieve dynamic data from request or provide defaults
                    date = request.data.get('date', 'Date')  # Default date if not provided
                    name = request.data.get('name', 'Instagram User')  # Default name if not provided
                    company_service = request.data.get('company_service', 'Services')  # Default service if not provided
                    company_name = request.data.get('company_name', 'Company')  # Default company name if not provided
                    address = request.data.get('address', '')  # Default address if not provided

                    # Replace placeholders in message template with dynamic data
                    message_content = message_template.template_content.format(
                        name=name,
                        company_name=company_name,
                        company_service=company_service,
                        date=date,
                        address=address
                    )

                    # Add formatted message content to the template_messages list
                    template_messages.append(message_content)

                except MessageTemplate.DoesNotExist:
                    return Response({"Message": f"Message template with ID {template_id} does not exist"}, status=404)

            # Append the messages for current templates set to the main messages list
            messages.append(template_messages)





        ins=instagram_accounts.objects.filter(id=instagram_account_id).first()

        username=ins.username
        password=ins.password

        # print("The messages detail arre as folows: ",messages)

        # accounts = [
        #     {'username': username, 'password': password, 'recipients': recipient_list,
        #      'message': messages},
        #     # {'username': username, 'password': password, 'recipients': ['adilalpha1', 'adilwebsite01', 'adilalpha1'],
        #     #  'message': [["This is the 1 Successfully test", "This is the 2 Successfully test"],
        #     #              ["This is the 3 Successfully test", "This is the 4 Successfully test"],
        #     #              ["This is the third Successfully test"]]}
        # ]

        accounts = [
            {'username': username, 'password': password, 'recipients': recipient_list, 'message': messages, 'instagram_account': ins},
            # {'username': username, 'password': password, 'recipients': ['adilalpha1', 'adilwebsite01', 'adilalpha1'],
            #  'message': [["This is the 1 Successfully test", "This is the 2 Successfully test"],
            #              ["This is the 3 Successfully test", "This is the 4 Successfully test"],
            #              ["This is the third Successfully test"]]}
        ]


        # print("The account detail is: ",accounts)

        max_simultaneous_logins = 5  # Set this to the number of simultaneous logins you want

        results = []
        with ThreadPoolExecutor(max_workers=max_simultaneous_logins) as executor:
            futures = [executor.submit(send_messages, account) for account in accounts]
            # print("The futures are as follows :",futures)
            for future in as_completed(futures):
                results.append(future.result())
        return JsonResponse({'results': results})


#----------------------------------------------------------------Instagram Message View--------------------------------------------------------




class GetMessage(APIView):
    def get(self, request, format=None):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # temp_id = request.data.get('temp_id')

        # if not temp_id:
        #     return Response({'Message': 'Template id not found'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            Mess_obj= Message.objects.filter(instagram_account__user=user)

            if not Mess_obj:
                return Response({'Message': 'No Message Template found'}, status=status.HTTP_404_NOT_FOUND)
            mess_lst=[]
            for mess in Mess_obj:
            
                tmp={
                "Message Template id" : mess.id,
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