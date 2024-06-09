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
import datetime
# import requests
import random
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














#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
    
# class UserEmailVerificationView(APIView):
#     def post(self, request):
#         email = request.data.get('email')
#         verification_code = request.data.get('verification_code')
#         # Check if required fields are provided
#         if not email or not verification_code:
#             return Response({'Message': 'Please provide Email and Verification code'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             user = CustomUser.objects.get(email=email)

#             if user.is_user_verified == True:
#                 # If user is already verified, return a message indicating so
#                 return Response({'Message': 'User is already verified.'}, status=status.HTTP_400_BAD_REQUEST)
            
#              # Check if verification code is a valid number
#             if not verification_code.isdigit():
#                 return Response({'Message': 'Invalid Verification Code.'}, status=status.HTTP_400_BAD_REQUEST)

#             if str(user.verification_code) == verification_code:
#                 user.is_user_verified = True
#                 token = get_tokens_for_user(user)
#                 verification_code = random.randint(100000, 999999)# Extra Code added to change the code after Process because same code will be used multiple times ex- same code will be used to chnage password.
#                 user.verification_code = verification_code# Extra Code added to change the code after Process because same code will be used multiple times ex- same code will be used to chnage password.
#                 user.save()
#                 # if user.membership:
#                 #     Mem=Membership.objects.filter(name=user.membership.name).first()
#                 #     memebership_id=Mem.id
#                 #     return Response({'token':token,'verified' : user.is_user_verified, 'Message':'Email verified successfully.', "membership_id":memebership_id, "membership":user.membership.name, "membership_expiry_date":str(user.membership_expiry), "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
#                 # else:
#                 return Response({'token':token,'verified' : user.is_user_verified, 'Message':'Email verified successfully.', "membership_id":None, "membership":None, "membership_expiry_date":None, "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
#                 # return Response({'token':token,'Message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
#             else:
#                 return Response({'Message': 'Entered Verification code is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
#         except CustomUser.DoesNotExist:
#             # If email is not in records, prompt user to register first
#             return Response({'Message': 'Email not in records. Please register first.'}, status=status.HTTP_400_BAD_REQUEST)

#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
 
#---------------------------------------------------------Resend OTP API by ADIL----------------------------------------------------------------

# class ResendOTPView(APIView):
#     def post(self, request):
#         email = request.data.get('email')
#         if not email:
#             return Response({'Message': 'Please provide an email address.'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             user = CustomUser.objects.get(email=email)
#             verification_code = random.randint(100000, 999999)
#             user.verification_code = verification_code
#             user.save()
#             # Call the function to send OTP via email
#             send_otp_via_email(email)
#             return Response({'Message': 'New verification code sent successfully.'}, status=status.HTTP_200_OK)
#         except CustomUser.DoesNotExist:
#             return Response({'Message': 'Email not found in records. Register First'}, status=status.HTTP_404_NOT_FOUND)


#---------------------------------------------------------Resend OTP APY by ADIL---------------------------------------------------------------


#---------------------------------------------Change Password by Adil------------------------------------------------------------

# class UserChangePasswordView(APIView):
#     """ 
#     Reset user password
#     """
#     renderer_classes = [UserRenderer]
#     permission_classes = [AllowAny]  # Allow any user to access this endpoint

#     def post(self, request, format=None):
#         email = request.data.get('email')
#         verification_code = request.data.get('verification_code')
#         new_password = request.data.get('new_password')

#         # Check if required fields are provided
#         if not email or not verification_code or not new_password:
#             return Response({'Message': 'Please provide the Email, Verification code and New Password'}, status=status.HTTP_400_BAD_REQUEST)

#          # Check if verification code is a valid number
#         if not verification_code.isdigit():
#             return Response({'Message': 'Invalid Verification Code.'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             user = CustomUser.objects.get(email=email, verification_code=verification_code)
#             verification_code = random.randint(100000, 999999)# Extra Code added to change the code after Process because same code will be used multiple times.
#             user.verification_code = verification_code# Extra Code added to change the code after Process because same code will be used multiple times.
#             user.save()# Extra Code added to change the code after Process because same code will be used multiple times.
#         except CustomUser.DoesNotExist:
#             return Response({'Message': 'Invalid email or verification code.'}, status=status.HTTP_400_BAD_REQUEST)

#         serializer = UserChangePasswordSerializer(instance=user, data={'password': new_password, 'password2': new_password})
#         try:
#             serializer.is_valid(raise_exception=True)
#             serializer.save()
#             return Response({'Message': 'Password changed successfully'}, status=status.HTTP_200_OK)
#         except ValidationError as e:
#             # Handle validation errors
#             return Response({'Message': e.detail}, status=status.HTTP_400_BAD_REQUEST)


#---------------------------------------------Change Password by Adil------------------------------------------------------------



# class AdminModifyUser(APIView):
#     """ 
#     Delete-user if token is of super user
#     """
#     renderer_classes = [UserRenderer]
#     permission_classes = [IsAuthenticated]
#     def post(self, request, format=None):
#         user_id = get_user_id_from_token(request)
#         user, is_superuser = IsSuperUser(user_id)
#         if not user or not is_superuser:
#             msg = 'could not found the super user'
#             return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
#         user_modified_status = False

#         if 'email' not in request.data or not request.data.get('email'):
#             return Response({'Message' : 'could not got the user, Please provide email'}, status=status.HTTP_204_NO_CONTENT)

#         user_modified_email =request.data['email']

#         new_name =request.data['new_name']
#         new_password =request.data['new_password']

#         if not new_name and not new_password:
#             return Response({'Message' : 'could not got any user details to modify, Please provide name or new password'}, status=status.HTTP_204_NO_CONTENT)


#         user_modified = CustomUser.objects.filter(email=user_modified_email).first()  

#         if not user_modified:
#             msg = 'User not in record!!'
#             return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

#         if user_modified:
#             if new_name:
#                 user_modified.name = new_name
#             if new_password:
#                 user_modified.set_password(new_password)

#             user_modified.save()
#             user_modified_status = True
#             return Response({'Message' : 'successfully got the user deleted', 'user_modified_status' : user_modified_status}, status=status.HTTP_200_OK) 
        
#         return Response({'Message' : 'could not update the user', 'user_modified_status' : user_modified_status}, status=status.HTTP_400_BAD_REQUEST)
 






#---------------------------------Forgot Password by Adil--------------------------------------------------------------------

# class ForgotPasswordView(APIView):
#     def post(self, request):
#         email = request.data.get('email')
#         if not email:
#             return Response({'Message': 'Please provide the Email'}, status=status.HTTP_400_BAD_REQUEST)
#         try:
#             # Check if user exists in records
#             user = CustomUser.objects.get(email=email)
#         except CustomUser.DoesNotExist:
#             # If user is not in records, prompt user to register first
#             return Response({'Message': 'User not in records. Register first.'}, status=status.HTTP_400_BAD_REQUEST)

#         # Generate a verification code
#         verification_code = random.randint(100000, 999999)
#         user.verification_code = verification_code
#         user.save()

#         # Send verification code via email
#         send_otp_via_email(email)

#         return Response({'Message': 'Password Reset code sent successfully. Use it to reset your password.'}, status=status.HTTP_200_OK)

#------------------------------------Forgot Password by Adil---------------------------------------------------------------
    