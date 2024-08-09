**Prerequisites**

- AWS Account.
- Well verse with AWS IAM & AWS STS.
- JDK 17.

** **

**AWS IAM role**
- Create an AWS user, allow it to assume role, and read iam roles
- Create an IAM Role needed for the STS assume role via SDK, it's trusted entities may look like below, do needed customizations accordingly:-
- root user should never be used
- for the IAM user, sts:AssumeRole is required, bind it to specific roles as part of the inline policy.
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::AWS_ACCOUNT_NUMBER:user/USER_NAME"
            },
            "Action": "sts:AssumeRole",
            "Condition": {}
        }
    ]
}
```
** **
**Configuration related to the AWS access, etc**
- replace these properties accordingly
  ```properties
  # access key id of the IAM user.
  aws.access-key-id=${AWS_ACCESS_KEY_ID}
  # secret access  of the IAM user.
  aws.secret-access-key=${AWS_SECRET_ACCESS_KEY}
  # region scoped for the flow.
  aws.default-region=ap-south-1
  # role that we need to assume.
  aws.assumed-role-arn=${AWS_ROLE_ARN_TO_BE_ASSUMED}
  ```

**Signup on Duo for an account & create an application of WEB SDK type**

- get the client id, secret & API host name for the DUO app.
- **replace these fields in the application.properties accordingly**
  ```properties
  duo.client-id=DUO_CLIENT_ID
  duo.client-secret=DUO_CLIENT_SECRET
  duo.apiHostName=DUO_API_HOST
  ```
- create duo user & group, assign the user to the group
- **replace the fields below, based on the user & group name**
  ```properties
  duo.username=something
  duo.allowed-group-name=aws-admins
  ```
** **

Start the server, try to access the / endpoint and click on sign in with AWS link. 

-> It will redirect you to DUO Authorize endpoint

-> DUO will trigger MFA prompts

-> DUO will redirect back to /duo/mfa/callback endpoint

-> DUO id token, etc. is validated.

-> AWS STS generates the signIn url

-> redirected to AWS console with assumed role