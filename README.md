## Function
This function works in conjunction with https://github.com/namgk/cognito-lambda-authflow to authenticate an api gateway API with a cognito user pool. It looks at the cookie in the request and verify the information with cognito iss.


## Usage

Environment variables:

* COGNITO_REGION
* AWS_ACCOUNT_ID
* APIS_USERPOOL (e.g. { "api ID": "pool ID" })