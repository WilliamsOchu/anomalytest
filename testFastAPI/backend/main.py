import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

class Baller(BaseModel):
    name: str


class Ballers(BaseModel):
    ballers: List[Baller]


app = FastAPI()

origins = [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

memory_db = {"ballers": []}


@app.get("/ballers", response_model=Ballers)
def get_ballers():
    return Ballers(ballers=memory_db["ballers"])


@app.post("/ballers", response_model=Baller)
def add_baller(baller: Baller):
    memory_db["ballers"].append(baller)
    return baller

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)