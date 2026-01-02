from typing import List, Optional
from sqlmodel import Field, SQLModel, create_engine, Session, Relationship,create_engine
from datetime import datetime
import os

# 1. 基礎模型 (共用欄位)
class TodoBase(SQLModel):
    title: str
    # 這裡只寫定義，不寫 table=True
    due_date: Optional[datetime] = None 
    priority: int = 1
    
    # category 代表「類別」，我們給它一個預設值 "一般"
    # index=True 可以讓資料庫查詢類別時速度更快
    category: str = Field(default="一般", index=True)

# 2. 輸入專用模型 (Create DTO)
# 這裡專門給 API 用，Pydantic 在這裡工作最準確
class TodoCreate(TodoBase):
    pass

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True) # 帳號不能重複
    hashed_password: str

    # 這是關聯設定 (這是給程式看的，不是資料庫欄位)
    todos: List["Todo"] = Relationship(back_populates="owner")

    # 對話紀錄關聯
    messages: List["ChatMessage"] = Relationship(back_populates="owner")

# 用來接收前端註冊資料的模型
class UserCreate(SQLModel):
    username: str
    password: str # 使用者輸入的明碼

# 3. 資料庫專用模型 (Database Table)
# 這裡專門給資料庫用
class Todo(TodoBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    is_completed: bool = False

    # --- 新增這行：外鍵 ---
    #這代表這個欄位必須對應到 User 表的 id
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")
    # 這是關聯設定 (方便你用 todo.owner 直接拿到使用者資料)
    owner: Optional[User] = Relationship(back_populates="todos")

# 4. 新增 ChatMessage 模型 (資料庫表格)
class ChatMessage(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    role: str   # "user" (使用者) 或 "assistant" (AI)
    content: str # 內容
    timestamp: datetime = Field(default_factory=datetime.now) # 自動填入時間
    
    # 關聯到使用者
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")
    owner: Optional["User"] = Relationship(back_populates="messages")

#  增加一個「輸出專用」的模型 (加工模型)
# 5. 給前端看的輸出 (保證有 id, 有 title, 有 is_expired)
class TodoRead(TodoBase):
    id: int              # 這裡定義了，id 就一定會回傳
    is_completed: bool
    owner_id: Optional[int]
    is_expired: bool = False 

    @classmethod
    def from_db(cls, todo: Todo):
        # 使用 model_validate 來繼承原本的所有資料
        obj = cls.model_validate(todo)
        # 額外計算過期邏輯
        if todo.due_date and not todo.is_completed:
            obj.is_expired = datetime.now() > todo.due_date
        return obj
class TodoListResponse(SQLModel):
    status: str
    total_count: int
    data: List[TodoRead]

# 讀取 Render 設定的環境變數
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # 修正：SQLAlchemy 要求使用 postgresql:// 而非 postgres://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DATABASE_URL)
else:
    # 如果在本機開發，沒有環境變數，就用原本的 SQLite
    sqlite_url = "sqlite:///database.db"
    engine = create_engine(sqlite_url)

# 初始化資料庫 (建立資料表)
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
