#!/bin/bash

# Install package dependencies
 pip3 install -r requirements.txt --target ./package

# Zip up the package dependencies 
 zip -r aws-account-monitor.zip ./package

# Add config and the main lambda code to the Zip file
 zip aws-account-monitor.zip main.py config.yaml