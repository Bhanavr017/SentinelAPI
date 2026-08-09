from pydantic import BaseModel
from typing import Dict


class DetectionRequest(BaseModel):
    url: str
    body: str = ""
    headers: Dict[str, str] = {}


class DetectionResponse(BaseModel):
    blocked: bool
    score: int
    reason: str
