import os
import ssl
import logging
from typing import Dict, List

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("llama_stack_auth")
logging.basicConfig(level=logging.INFO)

class AuthRequest(BaseModel):
    path: str
    headers: Dict[str, str]
    params: Dict[str, List[str]]

class TokenValidationRequest(BaseModel):
    api_key: str
    request: AuthRequest

class User(BaseModel):
    principal: str
    attributes: Dict[str, List[str]]

class OpenShiftAuthProvider:
    def __init__(self):
        self.api_server_url = f"https://{os.getenv('KUBERNETES_SERVICE_HOST')}:{os.getenv('KUBERNETES_SERVICE_PORT_HTTPS', '443')}"
        self.ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    async def validate_token(self, token: str) -> User:
        # Create SSL context with OpenShift CA
        ssl_context = ssl.create_default_context(cafile=self.ca_cert_path)

        user_api_url = f"{self.api_server_url}/apis/user.openshift.io/v1/users/~"

        async with httpx.AsyncClient(verify=ssl_context) as client:
            try:
                response = await client.get(
                    user_api_url,
                    headers={"Authorization": f"Bearer {token}"},
                )

                if response.status_code == 401:
                    raise HTTPException(status_code=401, detail="Invalid token")
                if response.status_code != 200:
                    logger.warning(f"OpenShift API returned status {response.status_code}")
                    raise HTTPException(status_code=500, detail="OpenShift API error")

                user_response = response.json()
                metadata = user_response.get("metadata", {})
                username = metadata.get("name")

                if not username:
                    raise HTTPException(status_code=500, detail="No username found")

                groups = user_response.get("groups", [])
                logger.info(f"Authenticated user: {username}, groups: {groups}")

                user_attributes = {}

                # Map OpenShift groups directly to roles (this is what Llama Stack expects)
                if groups:
                    user_attributes["roles"] = groups
                else:
                    # If no groups, use username as role fallback
                    user_attributes["roles"] = [username]

                return User(principal=username, attributes=user_attributes)

            except httpx.RequestError as e:
                logger.error(f"Request error: {e}")
                raise HTTPException(status_code=500, detail="Connection error")

# Initialize FastAPI app
app = FastAPI(title="Llama Stack OpenShift Auth Provider")
auth_provider = OpenShiftAuthProvider()

@app.post("/validate", response_model=User)
async def validate(request: TokenValidationRequest):
    """
    Validate token against OpenShift OAuth and return a User.
    """
    try:
        user = await auth_provider.validate_token(request.api_key)
        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during token validation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
