#
# © 2023 Snyk Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#!/bin/bash

# Make a temporary folder for the package
mkdir _package

# Install package dependencies
pip3 install -r lambda/requirements.txt --target ./_package

# Copy the lambda function itself to the package
cp lambda/main.py ./_package

# Zip up the package dependencies
cd _package; zip -r ../lambda-account-monitor-package.zip *; cd ..

# Delete the temporary package folder
rm -rf ./_package