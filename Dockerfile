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
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entrypoint script
# COPY entrypoint.sh /
# COPY entrypoint.sh /entrypoint.sh

# Make the entrypoint script executable
# RUN chmod +x /entrypoint.sh

# Expose port 8001 for the Django app
EXPOSE 8001

# Use the entrypoint script to start the Django app
# ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
