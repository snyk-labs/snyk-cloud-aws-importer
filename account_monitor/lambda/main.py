CT_EVENT_ORGANIZATIONS = "CreateAccountResult"
CT_EVENT_CONTROLTOWER = "CreateManagedAccount"

def lambda_handler(event, context):
    if event["detail"]["eventName"] == CT_EVENT_CONTROLTOWER:
        ROLE = ""
    elif event["detail"]["eventName"] == CT_EVENT_ORGANIZATIONS:
        ROLE = ""
    else:
        pass # Unknown role