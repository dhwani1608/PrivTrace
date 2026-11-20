from pydantic import BaseModel


class SignupRequest(BaseModel):
    name: str
    email: str
    phone: str
    pan: str
    password: str


class ChatRequest(BaseModel):
    user_id: int
    message: str
