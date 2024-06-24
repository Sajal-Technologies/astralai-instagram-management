from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import MinValueValidator

# ------------------------copied from keywordlit project------------------------------------------------------------------------------

class TimeStampModel(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# --------------------------------------------UserManager Code By Adil-------------------------------------------------------------
class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        """ 
        Create a normal user instead of super user with his/ her personal details.
        """
        if not email:
            raise ValueError('User must have an email address')
        if not username:
            raise ValueError('User must have a username')

        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Superuser must have an email address')

        email = self.normalize_email(email)
        #user = self.model(email=email, username=email, is_staff=True, is_superuser=True, **extra_fields)
        user = self.model(email=email, is_staff=True, is_superuser=True, **extra_fields)
        #user = self.model(email=email, is_admin = True, is_staff=True, is_superuser=True, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    


#-----------------------------------------------------Code BY Adil-------------------------------------------------------------
class CustomUser(AbstractUser,TimeStampModel):
    """ 
    This models is create to store and edit the New registered User's Data and edit Django defualt User authentication 
    """

    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=25)
    # verification_code = models.BigIntegerField(null=True, blank=True)
    # is_user_verified = models.BooleanField(default=False)
    # credit = models.BigIntegerField(default=100)
    #Mobile_number = models.IntegerField(default=0)
    #gender = models.CharField(max_length=25, choices=GENDER, null=True, blank=True)
    # profile_photo = models.ImageField(upload_to='profile_pic/', blank=True, null=True) #default='default-user-profile.jpg')
    # stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)  # Added for Stripe
    # is_subscribed = models.BooleanField(default=False)  # Added for Stripe
    #membership = models.ForeignKey(Membership, null=True, blank=True, on_delete=models.SET_NULL)  # Added for Stripe
    # membership_expiry = models.DateTimeField(null=True, blank=True)  
    REQUIRED_FIELDS = ["email"]

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_staff

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True 
#-----------------------------------------------------Code BY Adil-------------------------------------------------------------



class instagram_accounts(TimeStampModel):
    id = models.BigAutoField(primary_key=True)
    username = models.CharField(unique=True,max_length=250)
    password = models.CharField(max_length=250)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)




class Lead(TimeStampModel): # This will take up the .CSV FILE DATA
    instagram_account = models.ForeignKey(instagram_accounts, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    # email = models.EmailField(null=True, blank=True)
    csv_file_number = models.CharField(max_length=30)
    username = models.CharField(max_length=150)
    status = models.CharField(max_length=150)
    # Add other fields as necessary

class Message(TimeStampModel):
    instagram_account = models.ForeignKey(instagram_accounts, on_delete=models.CASCADE)
    recipient = models.CharField(max_length=250)
    content = models.TextField()
    scheduled_time = models.DateTimeField()
    sent = models.BooleanField()
    sent_time = models.DateTimeField(null=True, blank=True)
    error = models.TextField(null=True, blank=True)
    # opened = models.BooleanField(default=False)
    # Add other fields as necessary

class Task(TimeStampModel):
    instagram_account = models.ForeignKey(instagram_accounts, on_delete=models.CASCADE)
    message = models.ManyToManyField(Message, related_name='tasks')
    total_messages = models.IntegerField(default=0)
    sent_messages = models.IntegerField(default=0)
    failed_messages = models.IntegerField(default=0)
    status = models.CharField(max_length=50, default='pending')  # pending, in_progress, completed, failed
    # created_at = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now=True)
    error_message = models.TextField(null=True, blank=True)



class MessageTemplate(TimeStampModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    template_name = models.CharField(max_length=255)
    template_content = models.TextField()










# Specify unique related_name attributes for the reverse relationships
CustomUser._meta.get_field('groups').remote_field.related_name = 'customuser_groups'
CustomUser._meta.get_field('user_permissions').remote_field.related_name = 'customuser_user_permissions'