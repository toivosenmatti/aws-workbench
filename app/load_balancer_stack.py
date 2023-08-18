import aws_cdk as core
from constructs import Construct

from aws_cdk import (
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_actions as actions,
    aws_certificatemanager as acm,
    aws_lambda as _lambda,
    aws_iam as iam,
    custom_resources,
)
import datetime
import json


def snake_case_to_camel_case(s):
    return " ".join(s.split("_")).title()

# TODO:
# * Support for multiple targest & services
# * Autoscaling
# * "Landing page"
# * More automated, but still restricted, sign-up process


class LoadBalancerStack(core.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        vpc: ec2.Vpc,
        container_image: ecs.ContainerImage = ecs.ContainerImage.from_registry(
            "amazon/amazon-ecs-sample"
        ),
        testing=True,
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)

        ### APPLICATION LOAD BALANCER ###

        load_balancer = elbv2.ApplicationLoadBalancer(
            self, "LoadBalancer", vpc=vpc, internet_facing=True
        )
        # If you get error message "Client is not enabled for OAuth2.0 flows."
        # in the Hosted Signin UI, this is caused by redirect_uri not matching
        # the allowed callback URL.
        # The problem is most likely not having the callback URLs in lowercase.
        # We should lowercase the load_balancer_dns_name, but cannot
        # This can be done with a CustomResource:
        # https://github.com/aws/aws-cdk/issues/11171#issuecomment-1056836149
        load_balancer_url = f"https://{load_balancer.load_balancer_dns_name}"
        core.CfnOutput(self, "LoadBalancerURL", value=load_balancer_url)

        certificate_arn = self.node.try_get_context("certificate_arn")
        if certificate_arn is not None:
            certificate = acm.Certificate.from_certificate_arn(
                self, "Certificate", certificate_arn
            )
            lb_listener_kwargs = dict(certificates=[certificate])
        else:
            lb_listener_kwargs = {}

        listener = load_balancer.add_listener(
            "Listener", port=443, **lb_listener_kwargs
        )
        # To test the load balancer
        listener.add_action(
            "Fixed",
            priority=10,
            conditions=[elbv2.ListenerCondition.path_patterns(["/ok"])],
            action=elbv2.ListenerAction.fixed_response(
                200, content_type="text/plain", message_body="OK"
            ),
        )
        load_balancer.add_redirect(
            source_protocol=elbv2.ApplicationProtocol.HTTP,
            source_port=80,
            target_protocol=elbv2.ApplicationProtocol.HTTPS,
            target_port=443,
        )

        ### COGNITO

        # Create a Cognito User Pool
        user_pool = cognito.UserPool(
            self,
            "UserPool",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            removal_policy=core.RemovalPolicy.DESTROY,
        )
        self.user_pool = user_pool

        callback_url = f"{load_balancer_url}/oauth2/idpresponse"
        callback_urls = [load_balancer_url, callback_url]

        user_pool_client = user_pool.add_client(
            "app-client",
            generate_secret=True,
            auth_flows=cognito.AuthFlow(user_password=True),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True,
                ),
                scopes=[cognito.OAuthScope.EMAIL],
                callback_urls=callback_urls,
            ),
            supported_identity_providers=[
                cognito.UserPoolClientIdentityProvider.COGNITO,
            ],
        )
        self.user_pool_client = user_pool_client

        domain_prefix = "my-awesome-app3"
        user_pool_domain = user_pool.add_domain(
            "CognitoDomain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=domain_prefix),
        )

        redirect_uri = load_balancer_url
        assert redirect_uri in callback_urls
        login_url = user_pool_domain.sign_in_url(
            user_pool_client, redirect_uri=redirect_uri
        )
        login_str = "/login?"
        logout_url = login_url.replace(login_str, "/logout?")
        authorization_endpoint = login_url.split(login_str)[0] + "/oauth2/authorize"
        core.CfnOutput(self, "RedirectUri", value=redirect_uri)
        core.CfnOutput(self, "CognitoSignInURL", value=login_url)
        core.CfnOutput(self, "CognitoSignOutURL", value=logout_url)
        core.CfnOutput(
            self, "CogntioUserPoolDomainURL", value=user_pool.user_pool_provider_url
        )

        ### SERVICE ###

        cluster = ecs.Cluster(self, "Cluster", vpc=vpc)

        # # Get available instance types with AWS CLI:
        # # aws ec2 describe-instance-types --filters "Name=current-generation,Values=true" --query "InstanceTypes[*].[InstanceType]" --output text | sort
        cluster.add_capacity(
            "ClusterCapacity",
            instance_type=ec2.InstanceType("t3.micro"),
            desired_capacity=1,
        )

        task_definition = ecs.Ec2TaskDefinition(self, "Ec2TaskDefinition")

        # Add a container to the task definition
        container = task_definition.add_container(
            "AppContainer",
            image=container_image,
            memory_limit_mib=256,
            logging=ecs.LogDrivers.aws_logs(stream_prefix="AppContainer"),
        )

        # Add a port mapping to the container
        container.add_port_mappings(ecs.PortMapping(container_port=80))

        # Create an EC2 service for the task definition
        ec2_service = ecs.Ec2Service(
            self,
            "Ec2Service",
            cluster=cluster,
            task_definition=task_definition,
            desired_count=1,
        )
        self.ec2_service = ec2_service

        ec2_service.node.add_dependency(listener)

        # Output the ECS service ARN
        core.CfnOutput(self, "EcsServiceArn", value=ec2_service.service_arn)

        ### Authentication from ALB to Cognito

        if testing:
            target_after_auth = elbv2.ListenerAction.fixed_response(
                200, content_type="text/plain", message_body="Authenticated"
            )
        else:
            target_group = elbv2.ApplicationTargetGroup(
                self, "MyTargetGroup", vpc=vpc, port=80, targets=[ec2_service]
            )
            target_after_auth = elbv2.ListenerAction.forward([target_group])

        # There might be more. This is the one where I found the problem.
        # See https://stackoverflow.com/questions/65718635/cannot-add-cognito-authentification-to-aws-load-balancer-elb
        oidc_regions = ["eu-north-1"]

        if self.region in oidc_regions:
            # aws_elasticloadbalancingv2_actions.AuthenticateCognitoAction would be preferred here, but it raises error:
            # Action type 'authenticate-cognito' must be one of 'redirect,fixed-response,forward,authenticate-oidc'
            # If having trouble getting authorization working, see working example:
            # https://www.cognitobuilders.training/20-lab1/20-setup-and-explore/10-create-userpool/
            msg = "WARNING! 'authenticate-cognito' does not work in {self.region}. Attempting OIDC, but this is buggy."
            print((len(msg) + 4) * "#")
            print("# " + msg + " #")
            print((len(msg) + 4) * "#")
            issuer = user_pool.user_pool_provider_url
            cognito_auth_config = dict(
                authorization_endpoint=authorization_endpoint,
                token_endpoint=issuer + "/oauth2/token",
                user_info_endpoint=issuer + "/oauth2/userInfo",
                issuer=issuer,
                client_id=user_pool_client.user_pool_client_id,
            )

            for k, v in cognito_auth_config.items():
                core.CfnOutput(self, snake_case_to_camel_case(k), value=v)

            core.CfnOutput(
                self,
                "OpenIdConfig",
                value=f"{user_pool.user_pool_provider_url}/.well-known/openid-configuration",
            )
            authenticate_action = elbv2.ListenerAction.authenticate_oidc(
                **cognito_auth_config,
                client_secret=user_pool_client.user_pool_client_secret,
                next=target_after_auth,
                on_unauthenticated_request=elbv2.UnauthenticatedAction.AUTHENTICATE,
            )
        else:
            authenticate_action = actions.AuthenticateCognitoAction(
                user_pool=user_pool,
                user_pool_client=user_pool_client,
                user_pool_domain=user_pool_domain,
                next=target_after_auth,
            )

        listener.add_action(
            "AutheticateAction",
            action=authenticate_action,
        )
        load_balancer.connections.allow_to_any_ipv4(
            ec2.Port.tcp(443), "Allow ALB to communicate with Cognito IdP endpoint"
        )

class CognitoURLModifierStack(core.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        user_pool: cognito.UserPool,
        user_pool_client: cognito.UserPoolClient,
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)

        # Create a Lambda function
        url_modifier_function = _lambda.Function(
            self,
            "URLModifierFunction",
            runtime=_lambda.Runtime.PYTHON_3_8,
            handler="url_modifier.handler",
            code=_lambda.Code.from_asset("lambda/url_modifier"),
        )

        # Provide the Lambda function permissions to modify the UserPoolClient
        url_modifier_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "cognito-idp:DescribeUserPoolClient",
                    "cognito-idp:UpdateUserPoolClient"
                ],
                resources=[
                    f"arn:aws:cognito-idp:{self.region}:{self.account}:userpool/{user_pool.user_pool_id}/client/{user_pool_client.user_pool_client_id}",
                    f"arn:aws:cognito-idp:{self.region}:{self.account}:userpool/{user_pool.user_pool_id}"
                ],
            )
        )

        # Create a Custom Resource to invoke the Lambda function
        invoke_lambda = custom_resources.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": url_modifier_function.function_name,
                    "Payload": json.dumps(
                        {
                            "UserPoolId": user_pool.user_pool_id,
                            "ClientId": user_pool_client.user_pool_client_id,
                        }
                    ),
                },
                physical_resource_id=custom_resources.PhysicalResourceId.of(datetime.datetime.now().strftime("InvokeURLModifierLambda-%Y%m%d-%H%M%S")),
            )
        url_modifier_custom_resource = custom_resources.AwsCustomResource(
            self,
            "URLModifierCustomResource",
            policy=custom_resources.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        actions=["lambda:InvokeFunction"],
                        resources=[url_modifier_function.function_arn],
                    )
                ]
            ),
            on_create=invoke_lambda,
            on_update=invoke_lambda,
        )

        # Do not create the Custom Resource before the UserPoolClient
        url_modifier_custom_resource.node.add_dependency(user_pool_client)

        # Output the result of the URL modification (optional)
        core.CfnOutput(
            self,
            "ModifiedURLsOutput",
            value=url_modifier_custom_resource.get_response_field("Payload"),
        )
