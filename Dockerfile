FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY templates templates/

# Create necessary directories
RUN mkdir -p instance

# Run as non-root user for better security
RUN useradd -m ctfuser
RUN chown -R ctfuser:ctfuser /app
USER ctfuser

# Command to run the application
CMD ["python", "app.py"]

