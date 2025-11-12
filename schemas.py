"""
Database Schemas for Student Portal

Each Pydantic model corresponds to a MongoDB collection. The collection name is the lowercase
of the class name (e.g., User -> "user").
"""
from typing import Optional, Literal, List
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

Role = Literal["student", "teacher", "admin"]

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Password hash")
    role: Role = Field("student", description="User role")
    approved: bool = Field(False, description="Whether the account is approved (admin only)")
    bio: Optional[str] = Field(None, description="Short bio")
    avatar_url: Optional[str] = Field(None, description="Profile avatar URL")

class Course(BaseModel):
    title: str
    description: Optional[str] = None
    teacher_id: str = Field(..., description="Teacher user id")
    subject: Optional[str] = None

class Enrollment(BaseModel):
    course_id: str
    student_id: str
    status: Literal["enrolled", "dropped"] = "enrolled"

class Assignment(BaseModel):
    course_id: str
    title: str
    description: Optional[str] = None
    due_date: Optional[datetime] = None

class Submission(BaseModel):
    assignment_id: str
    student_id: str
    content: Optional[str] = None
    file_url: Optional[str] = None
    grade: Optional[float] = None
    feedback: Optional[str] = None

class Announcement(BaseModel):
    title: str
    content: str
    author_id: str
    course_id: Optional[str] = None
    audience: Literal["all", "course"] = "all"

class Material(BaseModel):
    course_id: str
    title: str
    description: Optional[str] = None
    file_url: Optional[str] = None
