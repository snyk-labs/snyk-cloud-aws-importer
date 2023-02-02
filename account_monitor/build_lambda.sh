#!/bin/bash

# Make a temporary folder for the package
mkdir _package

# Install package dependencies
pip3 install -r lambda/requirements.txt --target ./_package

# Copy the lambda function itself to the package
cp lambda/main.py ./_package

# Zip up the package dependencies
cd _package; zip -r ../aws-account-monitor.zip *; cd ..

# Delete the temporary package folder
rm -rf ./_package