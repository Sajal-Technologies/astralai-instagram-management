# celery.py
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set the Celery app
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'astralai.settings')
app = Celery('astralai')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()



# @app.task
# def hello():
#     print("Hello World!")


# @app.task(bind=True)
# def debug_task(self):
#     print('Request: {0!r}'.format(self.request))

# Set Celery to use UTC timezone
# app.conf.timezone = 'UTC'

# app.conf.timezone = 'Asia/Kolkata'
