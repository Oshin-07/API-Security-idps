from pydantic import BaseModel
from typing import List, Optional


class Parameter(BaseModel):
    name: str
    location: str
    type: str
    required: bool = False


class Endpoint(BaseModel):
    path: str
    method: str
    parameters: List[Parameter] = []
    authentication: Optional[str] = None


class APIDetails(BaseModel):
    api_url: str
    title: Optional[str] = None
    version: Optional[str] = None
    endpoints: List[Endpoint]