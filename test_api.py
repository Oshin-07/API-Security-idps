from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel


app = FastAPI(
    title="Demo E-Commerce API",
    version="1.0.0"
)

security = HTTPBearer()


class User(BaseModel):
    name: str
    email: str
    age: int


@app.get("/users")
def get_users():
    return {"message": "Get users"}


@app.post("/users")
def create_user(user: User, auth=Depends(security)):
    return {"message": "User created", "user": user}


@app.get("/users/{user_id}")
def get_user(user_id: int, auth=Depends(security)):
    return {"message": "Get user", "user_id": user_id}


@app.put("/users/{user_id}")
def update_user(user_id: int, user: User, auth=Depends(security)):
    return {"message": "User updated", "user_id": user_id}


@app.delete("/users/{user_id}")
def delete_user(user_id: int, auth=Depends(security)):
    return {"message": "User deleted", "user_id": user_id}