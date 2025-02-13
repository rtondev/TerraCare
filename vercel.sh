#!/bin/bash

# Instalar dependências do sistema
apt-get update
apt-get install -y python3-dev default-libmysqlclient-dev build-essential pkg-config

# Instalar dependências Python
pip install -r requirements.txt 