import os
import ssl
import logging
from typing import Dict, List
from datetime import datetime

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

class KubernetesAuthProvider:
    def __init__(self):
        self.api_server_url = f"https://{os.getenv('KUBERNETES_SERVICE_HOST')}:{os.getenv('KUBERNETES_SERVICE_PORT_HTTPS', '443')}"
        self.ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    async def validate_token(self, token: str) -> User:
        # Create SSL context with Kubernetes CA
        ssl_context = ssl.create_default_context(cafile=self.ca_cert_path)

        # Use SelfSubjectReview API to validate token and get user info
        self_subject_review_url = f"{self.api_server_url}/apis/authentication.k8s.io/v1/selfsubjectreviews"

        # SelfSubjectReview payload
        self_subject_review_payload = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "SelfSubjectReview",
            "spec": {}
        }

        async with httpx.AsyncClient(verify=ssl_context) as client:
            try:
                response = await client.post(
                    self_subject_review_url,
                    json=self_subject_review_payload,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"
                    },
                )

                if response.status_code == 401:
                    raise HTTPException(status_code=401, detail="Invalid token")
                if response.status_code != 201:
                    logger.warning(f"SelfSubjectReview API returned status {response.status_code}")
                    raise HTTPException(status_code=500, detail="Authentication API error")

                review_response = response.json()
                user_info = review_response.get("status", {}).get("userInfo", {})

                username = user_info.get("username")
                if not username:
                    raise HTTPException(status_code=500, detail="No username found in token")

                groups = user_info.get("groups", [])
                uid = user_info.get("uid", "")
                extra = user_info.get("extra", {})

                logger.info(f"Authenticated user: {username}, groups: {groups}")

                user_attributes = {}

                # Map groups directly to roles (this is what Llama Stack expects)
                if groups:
                    user_attributes["roles"] = groups
                else:
                    # If no groups, use username as role fallback
                    user_attributes["roles"] = [username]

                # Add additional attributes if available
                if uid:
                    user_attributes["uid"] = [uid]

                if extra:
                    # Flatten extra attributes
                    for key, value in extra.items():
                        if isinstance(value, list):
                            user_attributes[key] = value
                        else:
                            user_attributes[key] = [str(value)]

                return User(principal=username, attributes=user_attributes)

            except httpx.RequestError as e:
                logger.error(f"Request error: {e}")
                raise HTTPException(status_code=500, detail="Connection error")

# Initialize FastAPI app
app = FastAPI(title="Llama Stack Kubernetes Auth Provider")
auth_provider = KubernetesAuthProvider()

@app.post("/validate", response_model=User)
async def validate(request: TokenValidationRequest):
    """
    Validate token against Kubernetes using SelfSubjectReview and return a User.
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
    uvicorn.run("validate:app", host="0.0.0.0", port=8000)
