import boto3
from pprint import pprint

def handler(event, context):
    client = boto3.client("cognito-idp")
    pprint(event)
    cognito_ids = dict(
        UserPoolId=event["UserPoolId"], ClientId=event["ClientId"]
    )
    pprint(cognito_ids)
    describe_response = client.describe_user_pool_client(**cognito_ids)
    pprint(describe_response)

    keys = [
        "AllowedOAuthFlows",
        "AllowedOAuthFlowsUserPoolClient",
        "AllowedOAuthScopes",
        "AuthSessionValidity",
        "CallbackURLs",
        "ClientId",
        "ClientName",
        "EnablePropagateAdditionalUserContextData",
        "EnableTokenRevocation" "ExplicitAuthFlows",
        "RefreshTokenValidity",
        "SupportedIdentityProviders",
        "TokenValidityUnits",
        "UserPoolId",
    ]
    update_kwargs = {k: v for k, v in describe_response["UserPoolClient"].items() if k in keys}
    update_kwargs["CallbackURLs"] = [url.lower() for url in update_kwargs["CallbackURLs"]]
    pprint(update_kwargs)
    response = client.update_user_pool_client(**update_kwargs)
    pprint(response)

    return response['UserPoolClient']["CallbackURLs"][0]



