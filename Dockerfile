# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Install system dependencies
RUN apt-get update \
    && apt-get install -y \
    gnupg2 \
    unzip \
    curl \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Chromium for arm64 architecture
RUN apt-get update \
    && apt-get install -y chromium-driver

# Install ChromeDriver
RUN CHROME_DRIVER_VERSION=$(curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE) \
    && curl -sS -o /tmp/chromedriver_linux64.zip http://chromedriver.storage.googleapis.com/${CHROME_DRIVER_VERSION}/chromedriver_linux64.zip \
    && unzip /tmp/chromedriver_linux64.zip -d /usr/local/bin/ \
    && rm /tmp/chromedriver_linux64.zip

# Set up the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run Django migrations
RUN python manage.py makemigrations auths && python manage.py migrate

# Create a superuser if it doesn't already exist
RUN echo "from django.contrib.auth import get_user_model; User = get_user_model(); \
if not User.objects.filter(username='admin').exists(): \
    User.objects.create_superuser(username='admin', email='admin@admin.com', password='admin')" | python manage.py shell

# Expose port 8001 for the Django app
EXPOSE 8001

# Define the default command to run the Django app
CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
