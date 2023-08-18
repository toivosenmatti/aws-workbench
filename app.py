#!/usr/bin/env python3
import os

import aws_cdk as core

from app.load_balancer_stack import LoadBalancerStack, CognitoURLModifierStack
from app.vpc_stack import VpcStack

app = core.App()

env = core.Environment(
    account=os.environ["CDK_DEFAULT_ACCOUNT"],
    region="eu-west-1"
)

testing = False

vpc_stack = VpcStack(app, "EcsVpcStack", env=env)
lb_stack = LoadBalancerStack(
    app,
    "LoadBalancerStack",
    vpc=vpc_stack.vpc,
    env=env,
    testing=testing
)
CognitoURLModifierStack(
    app,
    "CognitoURLModifierStack",
    env=env,
    user_pool=lb_stack.user_pool,
    user_pool_client=lb_stack.user_pool_client,
)

app.synth()
