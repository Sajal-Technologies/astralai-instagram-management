# tasks.py
from astralai.celery import Celery
from celery import shared_task
from django.conf import settings
# from datetime import datetime
from django.utils import timezone
import requests
from django.http import JsonResponse
import logging


from auths.models import Message, Task
import os
from django.utils import timezone
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.common.keys import Keys
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from webdriver_manager.chrome import ChromeDriverManager
import time
import threading
from celery_once import QueueOnce



from instagrapi import Client



app = Celery('tasks', broker='redis://127.0.0.1:6379/0')
# Configure logging to write to a file
logging.basicConfig(filename='celery.log', level=logging.INFO)

# Set the pool option to 'threads'
app.conf.update(
    task_default_queue='default',
    task_default_exchange='default',
    task_default_routing_key='default',
    worker_pool='threads',
)

# from celery import shared_task



# @shared_task(base=QueueOnce, once={'graceful': True})
# # @shared_task
# def send_message(message_id):
#     # Define the InstagramBot class here or import it if it's in a different file
#     class InstagramBot:
#         # def __init__(self, username, password, recipients, message):
#         def __init__(self, username, password, recipient, message, instagram_account,message_id):
#             self.username = username
#             self.password = password
#             self.recipient = recipient
#             self.message = message
#             self.message_id=message_id
#             self.instagram_account = instagram_account
#             self.base_url = 'https://www.instagram.com/'

#             # options = uc.ChromeOptions()
#             options = webdriver.ChromeOptions()
#             # options.headless = True
#             options.add_argument('--no-sandbox')
#             options.add_argument('--disable-dev-shm-usage')
#             options.add_argument('--disable-gpu')
#             options.add_argument('--disable-extensions')
#             options.add_argument('--window-size=1200x600')
#             options.add_argument('--disable-client-side-phishing-detection')

#             # options.binary_location = '/usr/bin/chromedriver' 
#             # self.bot = uc.Chrome(options=options)
#             # self.bot = webdriver.Chrome(options=options)


#             options.add_argument('--headless')
#             options.add_argument('--disable-setuid-sandbox')
#             options.add_argument('--user-data-dir=/tmp/chromium')
#             options.add_argument('--remote-debugging-port=9222')
#             logging.basicConfig(level=logging.DEBUG)
#             print("Options set SUCCESSFULLY")


#             CHROMEDRIVER_PATH = '/usr/bin/chromedriver'
#             # Check if ChromeDriver exists at the specified path
#             if not os.path.exists(CHROMEDRIVER_PATH):
#                 from webdriver_manager.chrome import ChromeDriverManager
#                 CHROMEDRIVER_PATH = ChromeDriverManager().install()

            

#             # driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

#             # Ensure that the ChromeDriver path is correct
#             # try: self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options) 

#             #     print("BOT CREATED SUCCESSFULLY") 
#             # except Exception as e: 
#             #     print(f"The Error in bot creation is: {str(e)}")


#             try:
            
#                 chromedriver_path = '/usr/bin/chromedriver'
#                 service = Service(CHROMEDRIVER_PATH)
#                 self.bot = webdriver.Chrome(service=service, options=options)

#                 # self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
#                 # self.bot = webdriver.Chrome(options=options)
#                 # self.bot = webdriver.Chrome(chromedriver_path, options=options)

#                 print("BOT CREATED SUCCESSFULLY")

#             except Exception as e:
#                 print(f"The Error in bot is: {str(e)}")


#             # self.bot = uc.Chrome()
#             self.popup_thread = threading.Thread(target=self.handle_popup, daemon=True)
#             self.popup_thread.start()

#             print("Thread started SUCCESSFULLY")
#             try:
#                 self.login()
#                 print("Login SUCCESSFULLY")
#             except Exception as e:
#                 print(f"The error is is --->: {e}")
#                 logging.error(f"Error during login for {self.username}: {e}")
#                 self.bot.quit()



#         def handle_popup(self):
#             while True:
#                 try:
#                     not_now_button = WebDriverWait(self.bot, 5).until(
#                         EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Not Now')]"))
#                     )
#                     not_now_button.click()
#                     logging.info(f"Popup closed for {self.username}")
#                 except Exception:
#                     time.sleep(1)

#         def login(self):
#             self.bot.get(self.base_url)
#             try:
#                 enter_username = WebDriverWait(self.bot, 20).until(
#                     EC.presence_of_element_located((By.NAME, 'username')))
#                 enter_username.send_keys(self.username)

#                 enter_password = WebDriverWait(self.bot, 20).until(
#                     EC.presence_of_element_located((By.NAME, 'password')))
#                 enter_password.send_keys(self.password)
#                 enter_password.send_keys(Keys.RETURN)
#                 time.sleep(5)

#                 print("Inside the Instagram")
#             except Exception as e:
#                 logging.error(f"Error entering login credentials: {e}")
#                 return

#             # time.sleep(3)
#             # print("Will go inside the send message")
#             # self.send_message()

#         # def send_message(self):
#             try:
#                 # Inbox Page
#                 try:
#                     # self.bot.find_element(By.XPATH,
#                     #                       '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[5]/div/div/span/div/a/div/div[1]/div/div[1]').click()
#                     print("Will now go to the inbox page")
#                     self.bot.get("https://www.instagram.com/direct/inbox/")
#                     print("INSIDE the inbox page")

#                     time.sleep(2)
#                 except Exception as e:
#                     logging.error(f"Error navigating to INBOX section: {e}")
#                     return


#                 # new Message Button
#                 new_message_button = WebDriverWait(self.bot, 5).until(
#                     EC.visibility_of_element_located((By.XPATH,
#                     '/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/section/div/div/div/div[1]/div/div[1]/div/div[1]/div[2]/div/div/div'))
#                                                     #   '//div[text()="Send Message"]/parent::button'))
#                 )
#                 new_message_button.click()
#                 print("Clicked NEW MASSAGE BUTTON")
#                 # recipient search input
#                 recipient_input = WebDriverWait(self.bot, 5).until(
#                     # EC.visibility_of_element_located((By.NAME, 'queryBox'))
#                     EC.visibility_of_element_located((By.XPATH,
#                                                               '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[2]/div/div[2]/input'))
#                 )
#                 recipient_input.send_keys(self.recipient)
#                 time.sleep(2)
#                 print("ENTERED RECIPIENT NAME")

#                 # recipient first suggestion click
#                 recipient_suggestion = WebDriverWait(self.bot, 7).until(
#                     # EC.visibility_of_element_located((By.XPATH, '//div[@role="dialog"]//div[text()="'+self.recipient+'"]'))
#                     EC.visibility_of_element_located((By.XPATH,
#                                                               '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[3]/div/div/div[1]/div[1]'))
#                 )
#                 recipient_suggestion.click()
#                 print("RECIPIENT Suggestion")
#                 next_button = WebDriverWait(self.bot, 5).until(
#                     # EC.visibility_of_element_located((By.XPATH, '//button[text()="Next"]'))
#                     EC.visibility_of_element_located((By.XPATH, '/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/div/div[1]/div/div[4]'))
#                 )
#                 next_button.click()

#                 message_area = WebDriverWait(self.bot, 5).until(
#                     # EC.visibility_of_element_located((By.TAG_NAME, 'textarea'))
#                     EC.visibility_of_element_located((By.XPATH, '//div[@contenteditable="true" and @aria-label="Message"]'))

#                 )
#                 message_area.send_keys(self.message)
#                 message_area.send_keys(Keys.RETURN)

#                 mess = Message.objects.get(id=self.message_id)
#                 mess.sent = True
#                 mess.sent_time = timezone.now()
#                 mess.save()
#                 tsk = Task.objects.get(message = mess)
#                 tsk.sent_messages+=1
#                 tsk.status = "completed"
#                 tsk.save()
#                 self.bot.refresh()
#                 logging.info(f"Message {self.message_id} sent successfully to {self.recipient}")
#                 self.close_browser()

#             except Exception as e:
#                 mess = Message.objects.get(id=self.message_id)
#                 mess.sent = False
#                 # mess.sent_time = None
#                 mess.save()
#                 tsk = Task.objects.get(message = mess)
#                 tsk.failed_messages+=1
#                 tsk.status = "failed"
#                 tsk.error_message = f"Error sending message to {self.recipient}: {e}"
#                 tsk.save()
#                 logging.error(f"Error sending message to {self.recipient}: {e}")
#                 self.close_browser()



#         def logout(self):
#             try:
#                 profile_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[1]/div[1]/div/div/div/div/div[2]/div[8]/div/span/div/a/div/div/div/div/span"
#                 self.bot.find_element(By.XPATH, profile_xpath).click()
#                 time.sleep(1)

#                 setting_icon_xpath = "/html/body/div[2]/div/div/div[2]/div/div/div[1]/div[2]/div/div[2]/section/main/div/header/section[2]/div/div/div[3]/div/div"
#                 self.bot.find_element(By.XPATH, setting_icon_xpath).click()
#                 time.sleep(1)

#                 logout_xpath = "/html/body/div[6]/div[1]/div/div[2]/div/div/div/div/div/button[7]"
#                 self.bot.find_element(By.XPATH, logout_xpath).click()
#                 time.sleep(2)
#             except Exception as e:
#                 logging.error(f"An error occurred during logout: {e}")

#         def close_browser(self):
#             self.logout()
#             time.sleep(3)
#             self.bot.quit()

#         # def close_browser(self):
#         #     self.bot.quit()

#     try:
#         mess = Message.objects.get(id=message_id)
#         if mess.sent:
#             tsk = Task.objects.get(message = mess)
#             tsk.sent_messages+=1
#             tsk.status = "completed"
#             tsk.save()
#             logger.info(f"Message {message_id} already sent, skipping.")
#             return {'Message': f'Message {message_id} already sent'}
#         username = mess.instagram_account.username
#         password = mess.instagram_account.password
#         recipient = mess.recipient
#         message = mess.content
#         instagram_account = mess.instagram_account

#         instagram_bot = InstagramBot(username, password, recipient, message, instagram_account,message_id)
#         instagram_bot.close_browser()

#         logger.info(f"Sending message to {recipient}")

#         # Mark the message as sent
#         mess.sent = True
#         # mess.sent_time = timezone.now()
#         mess.save()

#         logger.info(f"Message {message_id} sent successfully to {recipient}")
#         return {'Message': f'Message {message_id} sent successfully'}
#     except Message.DoesNotExist:
#         logger.error(f"Message {message_id} not found")
#         return {'Message': 'Message not found'}
#     except Exception as e:
#         logger.error(f"An error occurred while sending message {message_id}: {str(e)}")
#         return {'Message': f'An error occurred: {str(e)}'}








@shared_task(base=QueueOnce, once={'graceful': True})
def send_message(message_id):
    try:
        mess = Message.objects.get(id=message_id)
        if mess.sent:
            tsk = Task.objects.get(message=mess)
            tsk.sent_messages += 1
            tsk.status = "completed"
            tsk.save()
            logging.info(f"Message {message_id} already sent, skipping.")
            return {'Message': f'Message {message_id} already sent'}
        
        username = mess.instagram_account.username
        password = mess.instagram_account.password
        recipient = mess.recipient
        message_content = mess.content

        client = Client()
        try:
            client.login(username, password)
        except Exception as e:
            logging.error(f"Login failed for {username}: {e}")
            return {'Message': f'Login failed for {username}'}

        try:
            user_id = client.user_id_from_username(recipient)
            client.direct_send(message_content, [user_id])
            
            mess.sent = True
            mess.sent_time = timezone.now()
            mess.save()
            
            tsk = Task.objects.get(message=mess)
            tsk.sent_messages += 1
            tsk.status = "completed"
            tsk.save()
            
            logging.info(f"Message {message_id} sent successfully to {recipient}")
            return {'Message': f'Message {message_id} sent successfully'}
        except Exception as e:
            mess.sent = False
            mess.save()
            
            tsk = Task.objects.get(message=mess)
            tsk.failed_messages += 1
            tsk.status = "failed"
            tsk.error_message = f"Error sending message to {recipient}: {e}"
            tsk.save()
            
            logging.error(f"Error sending message to {recipient}: {e}")
            return {'Message': f'Error sending message to {recipient}: {e}'}
    except Message.DoesNotExist:
        logging.error(f"Message {message_id} not found")
        return {'Message': 'Message not found'}
    except Exception as e:
        logging.error(f"An error occurred while sending message {message_id}: {str(e)}")
        return {'Message': f'An error occurred: {str(e)}'}











# Get the logger
logger = logging.getLogger(__name__)



@shared_task
def find_next_regeneration_datetime():
    logger.info("Received task to find next Message sending senttime.")  
 
    try:
        from auths.models import Message 
        from datetime import timedelta, datetime
        # Calculate the datetime range for 30 minutes interval
        now = timezone.now()
        time_before_str = str(now - timedelta(seconds=10))
        time_after_str = str(now + timedelta(seconds=10))
        
        # Parse ISO 8601 strings to datetime objects
        time_before = datetime.fromisoformat(time_before_str)
        time_after = datetime.fromisoformat(time_after_str)

        # Ensure time_before and time_after are in UTC
        if time_before.tzinfo is None or time_before.tzinfo.utcoffset(time_before) is None:
            time_before = timezone.make_aware(time_before, timezone.utc)
        if time_after.tzinfo is None or time_after.tzinfo.utcoffset(time_after) is None:
            time_after = timezone.make_aware(time_after, timezone.utc)

        # Query messages within the specified time range
        messages_to_send = Message.objects.filter(
            sent=False,
            scheduled_time__gte=time_before,
            scheduled_time__lte=time_after
            # opened = False
        )



        logger.info("trying to find Messages")
    
        # Schedule regeneration tasks for each image
        for message in messages_to_send:
            logger.info(f"Scheduling send task for Message ID: {message.id}")
            # regenerate_image.apply_async(args=[message.id], countdown=0)  # Execute immediately
            send_message.apply_async(args=[message.id], countdown=0)
        return f'Scheduled sending for {len(messages_to_send)} Messages'
    
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return "An error occurred during sending Message scheduling."