# tasks.py
from astralai.celery import Celery
from celery import shared_task
# from auths.models import CreditHistory
# from home.views import calculate_regeneration_time
from django.conf import settings
# from datetime import datetime
# import boto3
# from botocore.exceptions import ClientError
# import pytz
from django.utils import timezone
# from openai import OpenAI
import requests
# from io import BytesIO
from django.http import JsonResponse
import logging


from auths.models import Message
import os
from django.utils import timezone
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
import threading




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




@shared_task
def send_message(message_id):
    # Define the InstagramBot class here or import it if it's in a different file

    class InstagramBot:
        def __init__(self, username, password, recipient, message, instagram_account):
            self.username = username
            self.password = password
            self.recipient = recipient
            self.message = message
            self.instagram_account = instagram_account
            self.base_url = 'https://www.instagram.com/'

            options = webdriver.ChromeOptions()
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            options.add_argument('--window-size=1200x600')
            options.add_argument('--disable-client-side-phishing-detection')

            if not os.path.exists('/usr/bin/chromedriver'):
                self.bot = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
            else:
                self.bot = webdriver.Chrome(executable_path='/usr/bin/chromedriver', options=options)

            self.popup_thread = threading.Thread(target=self.handle_popup, daemon=True)
            self.popup_thread.start()
            self.login()

        def handle_popup(self):
            while True:
                try:
                    not_now_button = WebDriverWait(self.bot, 5).until(
                        EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Not Now')]"))
                    )
                    not_now_button.click()
                    logging.info(f"Popup closed for {self.username}")
                except Exception:
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
                logging.error(f"Error entering login credentials: {e}")
                return

            time.sleep(3)
            self.send_message()

        def send_message(self):
            try:
                new_message_button = WebDriverWait(self.bot, 5).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//div[text()="Send Message"]/parent::button'))
                )
                new_message_button.click()
                recipient_input = WebDriverWait(self.bot, 5).until(
                    EC.visibility_of_element_located((By.NAME, 'queryBox'))
                )
                recipient_input.send_keys(self.recipient)
                time.sleep(2)

                recipient_suggestion = WebDriverWait(self.bot, 5).until(
                    EC.visibility_of_element_located((By.XPATH, '//div[@role="dialog"]//div[text()="'+self.recipient+'"]'))
                )
                recipient_suggestion.click()

                next_button = WebDriverWait(self.bot, 5).until(
                    EC.visibility_of_element_located((By.XPATH, '//button[text()="Next"]'))
                )
                next_button.click()

                message_area = WebDriverWait(self.bot, 5).until(
                    EC.visibility_of_element_located((By.TAG_NAME, 'textarea'))
                )
                message_area.send_keys(self.message)
                message_area.send_keys(Keys.RETURN)

                mess = Message.objects.get(id=self.message_id)
                mess.sent = True
                mess.sent_time = timezone.now()
                mess.save()
                logging.info(f"Message {self.message_id} sent successfully to {self.recipient}")
            except Exception as e:
                logging.error(f"Error sending message to {self.recipient}: {e}")

        def close_browser(self):
            self.bot.quit()

    try:
        mess = Message.objects.get(id=message_id)
        username = mess.instagram_account.username
        password = mess.instagram_account.password
        recipient = mess.recipient
        message = mess.content
        instagram_account = mess.instagram_account

        instagram_bot = InstagramBot(username, password, recipient, message, instagram_account)
        instagram_bot.close_browser()

        logger.info(f"Sending message to {recipient}")

        # Mark the message as sent
        mess.sent = True
        mess.sent_time = timezone.now()
        mess.save()

        logger.info(f"Message {message_id} sent successfully to {recipient}")
        return {'Message': f'Message {message_id} sent successfully'}
    except Message.DoesNotExist:
        logger.error(f"Message {message_id} not found")
        return {'Message': 'Message not found'}
    except Exception as e:
        logger.error(f"An error occurred while sending message {message_id}: {str(e)}")
        return {'Message': f'An error occurred: {str(e)}'}








# Get the logger
logger = logging.getLogger(__name__)



@shared_task
def find_next_regeneration_datetime():
    logger.info("Received task to find next Message sending senttime.")  
 
    try:
        from auths.models import Message 
        from datetime import timedelta
        # Calculate the datetime range for 30 minutes interval      #  IMAGE MODEL OBJECT .ALL RETURN 
        now = timezone.now()
        time_before = now - timedelta(seconds=10)
        time_after = now + timedelta(seconds=10)
        
        # Query the database for images within the 30 minutes interval
        messages_to_send = Message.objects.filter(
            sent_time__gte=time_before,
            sent_time__lte=time_after,
            sent=False
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