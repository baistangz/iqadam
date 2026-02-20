from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from supabase import create_client, Client
import os
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# 1. Initialize Supabase Client
# Ensure you set these environment variables in your deployment (e.g., Render or Railway)
# Just assign the strings directly!

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase credentials in environment variables.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="ORT Prep Backend")
# 1. Add this right after app = FastAPI(...) to allow your frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows any frontend to connect (great for local dev)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Define the Pydantic Data Model for Validation
class QuestionOptions(BaseModel):
    A: str
    B: str
    C: str
    D: str

class QuestionInsert(BaseModel):
    subject: str
    question: str
    options: QuestionOptions

# 3. Create the Endpoint
@app.post("/api/questions/bulk-upload")
async def upload_questions(questions: list[QuestionInsert]):
    """
    Accepts a JSON array of questions and inserts them into Supabase.
    """
    try:
        # Convert the Pydantic models to a list of dicts for Supabase
        # We store options as a JSONB column in Postgres
        data_to_insert = [
            {
                "subject": q.subject,
                "question_text": q.question,
                "options": q.options.model_dump() # Convert nested options to dict
            }
            for q in questions
        ]

        # Insert into the 'questions' table in Supabase
        response = supabase.table("questions").insert(data_to_insert).execute()
        
        return {
            "status": "success",
            "message": f"Successfully inserted {len(response.data)} questions.",
            "data": response.data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
# 2. Add this new endpoint at the bottom of the file
@app.get("/api/questions")
async def get_questions():
    """Fetches all questions from the Supabase database."""
    response = supabase.table("questions").select("*").execute()
    return response.data