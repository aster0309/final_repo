from typing import Optional
from sqlmodel import Field, SQLModel, create_engine, Session
from datetime import datetime

# 1. 基礎模型 (共用欄位)
class TodoBase(SQLModel):
    title: str
    # 這裡只寫定義，不寫 table=True
    due_date: Optional[datetime] = None 
    priority: int = 1

# 2. 輸入專用模型 (Create DTO)
# 這裡專門給 API 用，Pydantic 在這裡工作最準確
class TodoCreate(TodoBase):
    pass

# 3. 資料庫專用模型 (Database Table)
# 這裡專門給資料庫用
class Todo(TodoBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    is_completed: bool = False

# 設定資料庫連線 (本機開發用 SQLite)
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url)

# 初始化資料庫 (建立資料表)
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
