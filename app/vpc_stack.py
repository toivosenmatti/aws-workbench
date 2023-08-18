import aws_cdk as core
from constructs import Construct

from aws_cdk import (
    aws_ec2 as ec2,
)

class VpcStack(core.Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        self.vpc = ec2.Vpc(self, "EcsVpc", max_azs=2)
