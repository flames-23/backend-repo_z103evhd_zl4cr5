import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal, Any, Dict

import jwt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import bcrypt
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI(title="Student Portal API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------
# Utils
# ----------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
JWT_EXP_MIN = int(os.getenv("JWT_EXP_MIN", "60"))


def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id format")


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    d = {**doc}
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.astimezone(timezone.utc).isoformat()
    return d


# ----------------------
# Auth Models
# ----------------------
Role = Literal["student", "teacher", "admin"]


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Role = "student"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None


# Teacher models
class CourseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    subject: Optional[str] = None


class AssignmentCreate(BaseModel):
    course_id: str
    title: str
    description: Optional[str] = None
    due_date: Optional[datetime] = None


class AnnouncementCreate(BaseModel):
    title: str
    content: str
    course_id: Optional[str] = None
    audience: Literal["all", "course"] = "all"


class MaterialCreate(BaseModel):
    course_id: str
    title: str
    description: Optional[str] = None
    file_url: Optional[str] = None


# Student models
class EnrollRequest(BaseModel):
    course_id: str


class SubmissionCreate(BaseModel):
    assignment_id: str
    content: Optional[str] = None
    file_url: Optional[str] = None


class GradeRequest(BaseModel):
    submission_id: str
    grade: float
    feedback: Optional[str] = None


# Admin models
class ApproveUserRequest(BaseModel):
    user_id: str
    approved: bool = True


class AssignTeacherRequest(BaseModel):
    course_id: str
    teacher_id: str


# ----------------------
# Auth helpers
# ----------------------

def create_token(user: dict) -> str:
    payload = {
        "sub": str(user["_id"]),
        "role": user.get("role", "student"),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MIN),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            raise Exception("Invalid scheme")
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise Exception("No sub in token")
        if db is None:
            raise Exception("Database unavailable")
        user = db["user"].find_one({"_id": oid(user_id)})
        if not user:
            raise Exception("User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(user: dict, roles: List[str]):
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")


# ----------------------
# Startup: seed admin
# ----------------------
@app.on_event("startup")
def seed_admin():
    # If DB is not configured, skip seeding so the app can start
    if db is None:
        return
    try:
        admin_email = os.getenv("ADMIN_EMAIL", "admin@portal.com")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
        existing = db["user"].find_one({"email": admin_email})
        if not existing:
            db["user"].insert_one(
                {
                    "name": "Administrator",
                    "email": admin_email,
                    "password_hash": bcrypt.hash(admin_pass),
                    "role": "admin",
                    "approved": True,
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                }
            )
    except Exception:
        # don't crash startup on seeding error
        pass


# ----------------------
# Basic routes
# ----------------------
@app.get("/")
def root():
    return {"message": "Student Portal API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ Connected but error: {str(e)[:80]}"
    return response


# ----------------------
# Auth endpoints
# ----------------------
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    if payload.role == "admin":
        raise HTTPException(status_code=400, detail="Cannot self-register as admin")
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    approved = payload.role == "student"  # students auto-approved; teachers need admin approval
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": bcrypt.hash(payload.password),
        "role": payload.role,
        "approved": approved,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    user_doc["_id"] = res.inserted_id
    token = create_token(user_doc)
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    user = db["user"].find_one({"email": payload.email})
    if not user or not bcrypt.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("role") != "admin" and not user.get("approved", False):
        raise HTTPException(status_code=403, detail="Account pending approval")
    token = create_token(user)
    return TokenResponse(access_token=token)


@app.get("/me")
def me(current=Depends(get_current_user)):
    return serialize_doc({k: v for k, v in current.items() if k != "password_hash"})


@app.patch("/me")
def update_me(update: ProfileUpdate, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    data = {k: v for k, v in update.model_dump().items() if v is not None}
    if not data:
        return serialize_doc(current)
    data["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": current["_id"]}, {"$set": data})
    refreshed = db["user"].find_one({"_id": current["_id"]})
    return serialize_doc({k: v for k, v in refreshed.items() if k != "password_hash"})


# ----------------------
# Teacher endpoints
# ----------------------
@app.post("/teacher/courses")
def create_course(body: CourseCreate, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["teacher", "admin"])  # admin can also create
    doc = {
        "title": body.title,
        "description": body.description,
        "subject": body.subject,
        "teacher_id": str(current["_id"]) if current["role"] == "teacher" else body.__dict__.get("teacher_id") or str(current["_id"]),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["course"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/teacher/courses")
def my_courses(current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["teacher", "admin"])
    q = {}
    if current["role"] == "teacher":
        q = {"teacher_id": str(current["_id"])}
    courses = [serialize_doc(c) for c in db["course"].find(q).sort("created_at", -1)]
    return courses


@app.post("/teacher/assignments")
def create_assignment(body: AssignmentCreate, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["teacher", "admin"])
    course = db["course"].find_one({"_id": oid(body.course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    if current["role"] == "teacher" and course.get("teacher_id") != str(current["_id"]):
        raise HTTPException(status_code=403, detail="Not your course")
    doc = {
        "course_id": body.course_id,
        "title": body.title,
        "description": body.description,
        "due_date": body.due_date,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["assignment"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/teacher/submissions/{assignment_id}")
def list_submissions(assignment_id: str, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["teacher", "admin"])
    assignment = db["assignment"].find_one({"_id": oid(assignment_id)})
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    course = db["course"].find_one({"_id": oid(assignment["course_id"])})
    if current["role"] == "teacher" and course.get("teacher_id") != str(current["_id"]):
        raise HTTPException(status_code=403, detail="Not your course")
    subs = [serialize_doc(s) for s in db["submission"].find({"assignment_id": assignment_id}).sort("created_at", -1)]
    return subs


@app.post("/teacher/grade")
def grade_submission(body: GradeRequest, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["teacher", "admin"])
    sub = db["submission"].find_one({"_id": oid(body.submission_id)})
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found")
    assignment = db["assignment"].find_one({"_id": oid(sub["assignment_id"])})
    course = db["course"].find_one({"_id": oid(assignment["course_id"])})
    if current["role"] == "teacher" and course.get("teacher_id") != str(current["_id"]):
        raise HTTPException(status_code=403, detail="Not your course")
    db["submission"].update_one({"_id": sub["_id"]}, {"$set": {"grade": body.grade, "feedback": body.feedback, "updated_at": datetime.now(timezone.utc)}})
    updated = db["submission"].find_one({"_id": sub["_id"]})
    return serialize_doc(updated)


@app.post("/teacher/announcements")
def create_announcement(body: AnnouncementCreate, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["teacher", "admin"])
    if body.audience == "course":
        if not body.course_id:
            raise HTTPException(status_code=400, detail="course_id required for course audience")
        course = db["course"].find_one({"_id": oid(body.course_id)})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")
        if current["role"] == "teacher" and course.get("teacher_id") != str(current["_id"]):
            raise HTTPException(status_code=403, detail="Not your course")
    doc = {
        "title": body.title,
        "content": body.content,
        "author_id": str(current["_id"]),
        "course_id": body.course_id,
        "audience": body.audience,
        "created_at": datetime.now(timezone.utc),
    }
    res = db["announcement"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.post("/teacher/materials")
def upload_material(body: MaterialCreate, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["teacher", "admin"])
    course = db["course"].find_one({"_id": oid(body.course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    if current["role"] == "teacher" and course.get("teacher_id") != str(current["_id"]):
        raise HTTPException(status_code=403, detail="Not your course")
    doc = {
        "course_id": body.course_id,
        "title": body.title,
        "description": body.description,
        "file_url": body.file_url,
        "created_at": datetime.now(timezone.utc),
    }
    res = db["material"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


# ----------------------
# Student endpoints
# ----------------------
@app.get("/student/courses")
def student_courses(current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["student"])  # students view their enrollments
    enrolls = list(db["enrollment"].find({"student_id": str(current["_id"]), "status": "enrolled"}))
    course_ids = [oid(e["course_id"]) for e in enrolls]
    courses = [serialize_doc(c) for c in db["course"].find({"_id": {"$in": course_ids}})] if course_ids else []
    return courses


@app.post("/student/enroll")
def enroll_course(body: EnrollRequest, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["student"])
    course = db["course"].find_one({"_id": oid(body.course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    exists = db["enrollment"].find_one({"course_id": body.course_id, "student_id": str(current["_id"])})
    if exists and exists.get("status") == "enrolled":
        return serialize_doc(exists)
    doc = {
        "course_id": body.course_id,
        "student_id": str(current["_id"]),
        "status": "enrolled",
        "created_at": datetime.now(timezone.utc),
    }
    res = db["enrollment"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/student/assignments")
def student_assignments(current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["student"])
    enrolls = list(db["enrollment"].find({"student_id": str(current["_id"]), "status": "enrolled"}))
    course_ids = [e["course_id"] for e in enrolls]
    assns = [serialize_doc(a) for a in db["assignment"].find({"course_id": {"$in": course_ids}}).sort("created_at", -1)] if course_ids else []
    return assns


@app.post("/student/submit")
def submit_assignment(body: SubmissionCreate, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["student"])
    assignment = db["assignment"].find_one({"_id": oid(body.assignment_id)})
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    # ensure student enrolled in course
    enr = db["enrollment"].find_one({"course_id": assignment["course_id"], "student_id": str(current["_id"]), "status": "enrolled"})
    if not enr:
        raise HTTPException(status_code=403, detail="Not enrolled in course")
    existing = db["submission"].find_one({"assignment_id": body.assignment_id, "student_id": str(current["_id"])})
    doc = {
        "assignment_id": body.assignment_id,
        "student_id": str(current["_id"]),
        "content": body.content,
        "file_url": body.file_url,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    if existing:
        db["submission"].update_one({"_id": existing["_id"]}, {"$set": doc})
        updated = db["submission"].find_one({"_id": existing["_id"]})
        return serialize_doc(updated)
    res = db["submission"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.get("/announcements")
def list_announcements(current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    role = current.get("role")
    if role == "student":
        enrolls = list(db["enrollment"].find({"student_id": str(current["_id"]), "status": "enrolled"}))
        course_ids = [e["course_id"] for e in enrolls]
        q = {"$or": [{"audience": "all"}, {"audience": "course", "course_id": {"$in": course_ids}}]}
    elif role == "teacher":
        # teachers see their course announcements + global
        q = {"$or": [{"audience": "all"}, {"audience": "course"}]}
    else:
        q = {}
    anns = [serialize_doc(a) for a in db["announcement"].find(q).sort("created_at", -1)]
    return anns


@app.get("/materials")
def list_materials(current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    role = current.get("role")
    if role == "student":
        enrolls = list(db["enrollment"].find({"student_id": str(current["_id"]), "status": "enrolled"}))
        course_ids = [e["course_id"] for e in enrolls]
        q = {"course_id": {"$in": course_ids}} if course_ids else {"_id": None}
    elif role == "teacher":
        q = {}
    else:
        q = {}
    mats = [serialize_doc(m) for m in db["material"].find(q).sort("created_at", -1)]
    return mats


# ----------------------
# Admin endpoints
# ----------------------
@app.get("/admin/users")
def list_users(current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["admin"])
    users = [serialize_doc({k: v for k, v in u.items() if k != "password_hash"}) for u in db["user"].find().sort("created_at", -1)]
    return users


@app.post("/admin/approve")
def approve_user(body: ApproveUserRequest, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["admin"])
    db["user"].update_one({"_id": oid(body.user_id)}, {"$set": {"approved": body.approved, "updated_at": datetime.now(timezone.utc)}})
    user = db["user"].find_one({"_id": oid(body.user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return serialize_doc({k: v for k, v in user.items() if k != "password_hash"})


@app.post("/admin/assign-teacher")
def assign_teacher(body: AssignTeacherRequest, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["admin"])
    # ensure teacher exists & role
    teacher = db["user"].find_one({"_id": oid(body.teacher_id)})
    if not teacher or teacher.get("role") != "teacher":
        raise HTTPException(status_code=400, detail="Invalid teacher")
    db["course"].update_one({"_id": oid(body.course_id)}, {"$set": {"teacher_id": body.teacher_id, "updated_at": datetime.now(timezone.utc)}})
    course = db["course"].find_one({"_id": oid(body.course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return serialize_doc(course)


@app.get("/admin/stats")
def stats(current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    require_role(current, ["admin"])
    return {
        "users": db["user"].count_documents({}),
        "students": db["user"].count_documents({"role": "student"}),
        "teachers": db["user"].count_documents({"role": "teacher"}),
        "courses": db["course"].count_documents({}),
        "assignments": db["assignment"].count_documents({}),
        "submissions": db["submission"].count_documents({}),
        "announcements": db["announcement"].count_documents({}),
        "materials": db["material"].count_documents({}),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
