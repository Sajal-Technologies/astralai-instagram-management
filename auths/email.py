from django.core.mail import send_mail
import random
from django.conf import settings
from .models import CustomUser
from django.core.exceptions import ObjectDoesNotExist


# def send_otp_via_email(email):
#     try:
#         user_obj = CustomUser.objects.get(email=email)
#         # Now you can send the OTP email to the user
#         # Example code for sending email...

#         subject = 'Verification code is here'
#         message = f'Your verification code is: {user_obj.verification_code}'
#         from_email = settings.EMAIL_HOST_USER  # Use the email defined in settings.py
#         recipient_list = [email]

#         send_mail(subject, message, from_email, recipient_list)  # You can change fail_silently to True if you don't want to raise exceptions for any email sending failure
#     except ObjectDoesNotExist:
#         # Handle the case where the user does not exist
#         # For example, you can log the error or return a response indicating the error
#         print(f"User with email {email} does not exist")



def send_otp_via_email(email):
    try:
        user_obj = CustomUser.objects.get(email=email)
        # Now you can send the OTP email to the user

        subject = 'Verification code is here'
        message = f'''
            <!DOCTYPE html>
            <html lang="en">
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <meta http-equiv="X-UA-Compatible" content="ie=edge" />
                <title>Verification Code</title>

                <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet" />
              </head>
              <body style="margin: 0; font-family: 'Poppins', sans-serif; background: #ffffff; font-size: 14px;">
                <div style="max-width: 680px; margin: 0 auto; padding: 45px 30px 60px; background: #f4f7ff; background-image: url(https://archisketch-resources.s3.ap-northeast-2.amazonaws.com/vrstyler/1661497957196_595865/email-template-background-banner); background-repeat: no-repeat; background-size: 800px 452px; background-position: top center; font-size: 14px; color: #434343;">
                  <header>
                    <table style="width: 100%;">
                      <tbody>
                        <tr style="height: 0;">
                          <td>
                            <img alt="" src="https://livingimage-profile-bucket.s3.amazonaws.com/logo.png" height="45px" />
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </header>

                  <main>
                    <div style="margin: 0; margin-top: 70px; padding: 92px 30px 115px; background: #ffffff; border-radius: 30px; text-align: center;">
                      <div style="width: 100%; max-width: 489px; margin: 0 auto;">
                        <h1 style="margin: 0; font-size: 24px; font-weight: 500; color: #1f1f1f;">Hey User,</h1>
    
                        <p style="margin: 0; margin-top: 17px; font-weight: 500; letter-spacing: 0.56px;">Thank you for choosing LivingImage. Use the following OTP. OTP is valid for <span style="font-weight: 600; color: #1f1f1f;">5 minutes</span>. Do not share this code with others.</p>
                        <p style="margin: 0; margin-top: 30px; font-size: 36px; font-weight: 600; letter-spacing: 15px; color: #ba3d4f;"><span style="white-space: nowrap;">{user_obj.verification_code}</span></p>
                      </div>
                    </div>

                    <p style="max-width: 400px; margin: 0 auto; margin-top: 90px; text-align: center; font-weight: 500; color: #8c8c8c;">Need help? Ask at <a href="mailto:support@livingimage.io" style="color: #499fb6; text-decoration: none;">support@livingimage.io</a> or visit our <a href="https://livingimage.io/" target="_blank" style="color: #499fb6; text-decoration: none;">Website</a></p>
                  </main>

                  <footer style="width: 100%; max-width: 490px; margin: 20px auto 0; text-align: center; border-top: 1px solid #e6ebf1;">
                    <p style="margin: 0; margin-top: 40px; font-size: 16px; font-weight: 600; color: #434343;">Living Image</p>
                  </footer>
                </div>
              </body>
            </html>
        '''
        from_email = settings.EMAIL_HOST_USER  # Use the email defined in settings.py
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list, html_message=message)  # Send HTML email
    except ObjectDoesNotExist:
        print(f"User with email {email} does not exist")






def send_payment_status_email(email, payment_id=None, payment_status=None, payment_description=None):
    try:
        user_obj = CustomUser.objects.get(email=email)
        # Now you can send the OTP email to the user

        subject = 'Payment Status Update from  Living Image'
        message = f'''
            <!DOCTYPE html>
            <html lang="en">
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <meta http-equiv="X-UA-Compatible" content="ie=edge" />
                <title>Verification Code</title>

                <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet" />
              </head>
              <body style="margin: 0; font-family: 'Poppins', sans-serif; background: #ffffff; font-size: 14px;">
                <div style="max-width: 680px; margin: 0 auto; padding: 45px 30px 60px; background: #f4f7ff; background-image: url(https://archisketch-resources.s3.ap-northeast-2.amazonaws.com/vrstyler/1661497957196_595865/email-template-background-banner); background-repeat: no-repeat; background-size: 800px 452px; background-position: top center; font-size: 14px; color: #434343;">
                  <header>
                    <table style="width: 100%;">
                      <tbody>
                        <tr style="height: 0;">
                          <td>
                            <img alt="" src="https://livingimage-profile-bucket.s3.amazonaws.com/logo.png" height="45px" />
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </header>

                  <main>
                    <div style="margin: 0; margin-top: 70px; padding: 92px 30px 115px; background: #ffffff; border-radius: 30px; text-align: center;">
                      <div style="width: 100%; max-width: 489px; margin: 0 auto;">
                        <h1 style="margin: 0; font-size: 24px; font-weight: 500; color: #1f1f1f;">Hey User,</h1>
    
                        <p style="margin: 0; margin-top: 17px; font-weight: 500; letter-spacing: 0.56px;">Thank you for choosing Living Image. Please find the status for your latest payment below<br><span style="font-weight: 600; color: #1f1f1f;"><center style= "font-weight: 600; letter-spacing: 0.56px;">Payment Status: </center>{payment_status}<br></span> <center style= "font-weight: 600; letter-spacing: 0.56px;">Description:</center> <p style="font-weight: 600; color: #1f1f1f;">{payment_description}</p></p>
                        <p style="margin: 0; margin-top: 30px; font-size: 15px; font-weight: 600; letter-spacing: 1px; color: #ba3d4f;"><span style="white-space: nowrap;">{payment_id}</span></p>
                      </div>
                    </div>

                    <p style="max-width: 400px; margin: 0 auto; margin-top: 90px; text-align: center; font-weight: 500; color: #8c8c8c;">Need help? Ask at <a href="mailto:support@livingimage.io" style="color: #499fb6; text-decoration: none;">support@livingimage.io</a> or visit our <a href="https://livingimage.io/" target="_blank" style="color: #499fb6; text-decoration: none;">Website</a></p>
                  </main>

                  <footer style="width: 100%; max-width: 490px; margin: 20px auto 0; text-align: center; border-top: 1px solid #e6ebf1;">
                    <p style="margin: 0; margin-top: 40px; font-size: 16px; font-weight: 600; color: #434343;">Living Image</p>
                  </footer>
                </div>
              </body>
            </html>
        '''
        from_email = settings.EMAIL_HOST_USER  # Use the email defined in settings.py
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list, html_message=message)  # Send HTML email
    except ObjectDoesNotExist:
        print(f"User with email {email} does not exist")