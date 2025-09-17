# Midnight CTF Platform

A CTF platform designed for the TryHackMe Midnight room, featuring personalized flags for each participant.

## Features

- User registration and authentication
- Serial challenge progression
- Personalized flags based on user email
- Flag validation system
- Real-time scoreboard

## Deployment Instructions

### Prerequisites

- Docker and Docker Compose
- Git

### Quick Start

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/midnight-ctf.git
   cd midnight-ctf
   ```

2. Create your `admin_mapping.txt` file based on the provided `sample_mapping.txt`:
   ```
   cp sample_mapping.txt admin_mapping.txt
   # Edit admin_mapping.txt with your actual flags
   nano admin_mapping.txt
   ```

3. Start the application:
   ```
   docker-compose up -d
   ```

4. Access the platform at `http://your-server-ip:5000`


## Configuration

The platform uses a mapping file to validate flags. Each line follows this format:
```
filepath|original_secret|secret_type|optional_user
```

- `filepath`: Path to the file containing the secret (for reference only)
- `original_secret`: The base flag or secret before personalization
- `secret_type`: Either "flag", "plain text", or "base64"
- `optional_user`: Username associated with the secret (optional)

## Security Considerations

- Always use HTTPS in production
- Change the SECRET_KEY in docker-compose.yml
- Never commit your real admin_mapping.txt file

