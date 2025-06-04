## Setup Libraries
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os
from .models import Base

## Database Connection Details
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

## Initiate Connection
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
metadata = MetaData()

## Get the Database Conection
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

## Create all Database Tables 
Base.metadata.create_all(bind=engine)
