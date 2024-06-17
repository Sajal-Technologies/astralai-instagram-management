#!/bin/bash

# Run Django migrations
python manage.py makemigrations auths
python manage.py migrate

# Create a superuser if it does not exist
python manage.py shell <<EOF
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@admin.com', 'admin')
EOF

# Run the Django development server
exec "$@"
