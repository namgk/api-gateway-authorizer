#!/bin/bash

set -e

FUNCTION_NAME=functionName
REGION=us-west-2

rm -rf *.zip
zip -r $FUNCTION_NAME.zip index.js dist

aws lambda update-function-code --region $REGION --function-name $FUNCTION_NAME --zip-file fileb://$FUNCTION_NAME.zip
