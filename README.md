
# AWS Workbench

This is a AWS CDK project to deploy a dockerized applications behind
a Application Load Balancer (ALB) with Cognito authentication.
The Cognito authentication uses the Cognito Hosted UI for signup and login.

## AWS Region

The ALB + Cognito authentication is easiest setup using a `authenticate-cognito` action, which is not available in all AWS Regions.
At least in `eu-north-1` it does not work.
[See here for more details](https://stackoverflow.com/questions/65718635/cannot-add-cognito-authentification-to-aws-load-balancer-elb).
Easiest solution is to use, e.g. `eu-west-1` as the AWS Region.
Currently this is hard-coded in [`app.py`](./app.py)

## Setup

Before running `cdk deploy --all`,
you need to setup a SSL Certificate for the ALB and create a `cdk.context.json` file.

### SSL Certificate for the ALB

You need a SSL certificate for the load balancer in order to use Cognito authentication.
If you do not have your own domain and a certifcate for it,
[here is a great and very concise gist on how to create a self-signed SSL certificate](https://gist.github.com/riandyrn/049eaab390f604eae4bf2dfcc50fbab7).
I did not get the AWS CLI command to work, but it is easy to
[do it via the Console](https://docs.aws.amazon.com/acm/latest/userguide/import-certificate-api-cli.html).
Make sure to import the certificate in the `AWS_REGION` you intend to use for deployment.

Once the certificate is in ACM, create a `cdk.context.json` file with the certifcate ARN:

```json
{
  "certificate_arn": "arn:aws:acm:<AWS_REGION>:<AWS_ACCOUNT_ID>:certificate/<CERTIFICATE_ID>",
}
```

### Deploy stacks 

```
cdk deploy --all
```

## `AWS CDK` boilerplate

To manually create a virtualenv on MacOS and Linux:

```
$ python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
$ pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

```
$ cdk synth
```

To add additional dependencies, for example other CDK libraries, just add
them to your `setup.py` file and rerun the `pip install -r requirements.txt`
command.

## Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation
