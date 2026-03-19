# Agent Keychain PoC - Simulated Developer Environment
# This container mimics a real developer's local machine with
# credentials stored in common locations that AI coding agents can access.

FROM python:3.12-slim

# Install common dev tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    openssh-client \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create a fake developer home environment
WORKDIR /home/developer

# --- Simulate credential files that exist on a real developer's machine ---

# 1. AWS credentials
RUN mkdir -p .aws
COPY poc/fake_credentials/.aws/credentials .aws/credentials
COPY poc/fake_credentials/.aws/config .aws/config

# 2. SSH keys
RUN mkdir -p .ssh && chmod 700 .ssh
COPY poc/fake_credentials/.ssh/id_rsa .ssh/id_rsa
COPY poc/fake_credentials/.ssh/id_rsa.pub .ssh/id_rsa.pub
RUN chmod 600 .ssh/id_rsa

# 3. Git config with token
COPY poc/fake_credentials/.gitconfig .gitconfig

# 4. NPM token
COPY poc/fake_credentials/.npmrc .npmrc

# 5. Docker config with registry auth
RUN mkdir -p .docker
COPY poc/fake_credentials/.docker/config.json .docker/config.json

# 6. Environment variables (simulating .env and shell exports)
COPY poc/fake_credentials/.env .env
COPY poc/fake_credentials/.bashrc .bashrc

# 7. Kubernetes config
RUN mkdir -p .kube
COPY poc/fake_credentials/.kube/config .kube/config

# 8. A project directory with .env file
RUN mkdir -p projects/my-webapp
COPY poc/fake_credentials/projects/my-webapp/.env projects/my-webapp/.env

# Install Python dependencies for PoC scripts
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy PoC scripts
COPY poc/ poc/

ENV HOME=/home/developer
WORKDIR /home/developer

CMD ["/bin/bash"]
