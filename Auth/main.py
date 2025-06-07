# main.py
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes import auth
from backend.routes import user

from backend import models # Import your models file
from backend.database import engine # Import the engine from your database setup
models.Base.metadata.create_all(bind=engine)

app = FastAPI(debug=True)

origins = [
    "http://localhost:3000",
    # Add more origins here
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(user.router)
app.include_router(auth.router, prefix="/auth")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)