"""System status response contracts."""

from pydantic import BaseModel


class DatabaseReadiness(BaseModel):
    status: str
    database: str
