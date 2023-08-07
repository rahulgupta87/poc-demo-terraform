import json
import boto3
import ast
import datetime
import logging
import uuid
import json
import requests

# Global variables to confiugrations
logger     = logging.getLogger()
request_id = str(uuid.uuid4())

# Remove current logger handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Logger configuration
logger.setLevel(logging.INFO)

# Create a custom format to print logs
formatter = logging.Formatter('{"log_data": {"trace": "' + request_id + '", "message": "%(message)s"}}')

# Configure and add handler
handler = logging.StreamHandler()
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
logger.addHandler(handler)

def lambda_handler(event, context):
    request = json.loads(event['body'])
    
    logging.info(f"Request: {request}")
    message = execute_task_handler(request)

    return {
        "message": message,
    }

def execute_task_handler(request):

    user_id = request["user_id"]
    env            = request["env"]

    parameter_name = f"/{env}/poc-demo/thirdparty"
    parameter_value, err = get_ssm_without_decryption(parameter_name)
    domain = ast.literal_eval(parameter_value)

    secret_name    = f"/{env}/poc-demo/sm-thirdparty-creds"
    token, err = get_secret(secret_name)

    message = executeThirdpartyApi(domain, token, user_id)

    insert_audit_record(request)

    return message

def get_secret(secret_name):
    session = boto3.session.Session()
    client  = session.client("secretsmanager")

    try:
        response     = client.get_secret_value(SecretId=secret_name)
        secret_value = response["SecretString"]

        return ast.literal_eval(secret_value), None
    except Exception as err:
        return None, err

def get_max_db_id(env):
    parameter_name = f"/{env}/poc-demo/maxId"
     
    parameter_value, err = get_ssm_without_decryption(parameter_name)
    if(err):
        raise err

    return int(parameter_value)

def update_max_db_id(max_id, env):
    client         = boto3.client('ssm')
    parameter_name = f"/{env}/poc-demo/maxId"

    client.put_parameter(
        Name=parameter_name,
        Value=max_id,
        Type='String',
        Overwrite=True,
    )

def insert_audit_record(request):
    env        = request['env']
    current_id = get_max_db_id(env)+1
    epoch_time = int(datetime.datetime.now().timestamp())
    dynamodb   = boto3.resource('dynamodb')
    table      = dynamodb.Table(f"poc-demo-audit-{env}")

    table.put_item(
        Item = {
            "id": current_id,
            "fecha": epoch_time,
            "accountId": request['account'],
            "clientCedula": request['clientCedula'],
            "operation": request['action'],
            "operation_for": request['actionFor'],
            "source": request["source"],
            "userEmail": request['userEmail'],
            "userName": request['userName']
        }
    )

    update_max_db_id(str(current_id), env)

def executeThirdpartyApi(self, domain, token, user_id):
        url     = f"https://{domain}/api/tp/{user_id}"
        headers = {"Authorization": f"Bearer {token}"}

        tp_api_response = requests.patch(url, data, headers=headers)

        if(tp_api_response.status_code == 200):
            logging.info("Thirdparty-Api-Response: OK")

            value = "Thirdparty task executed successfully"
            err   = False
        else:
            logging.error(f"Thirdparty-Api-Response: ERROR {tp_api_response}")

            value = "ERROR IN THIRDPARTY API"
            err   = True

        return value, err

def get_ssm_without_decryption(ssm_name):
    session  = boto3.session.Session()
    client   = session.client("ssm")

    try:
        response = client.get_parameter(Name=ssm_name, WithDecryption=False)
        value    = response["Parameter"]["Value"]

        return value, None
    except Exception as err:
        return None, err