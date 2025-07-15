from azure.identity import ClientSecretCredential
import json

tenant_id = ""
client_id = ""
client_secret = ""

credential = ClientSecretCredential(tenant_id, client_id, client_secret)
tokens = {
    "arm": credential.get_token("https://management.azure.com/.default").token,
    "graph": credential.get_token("https://graph.microsoft.com/.default").token
}

with open("access_tokens.json", "w") as f:
    json.dump(tokens, f)

print("Access tokens saved to access_tokens.json")