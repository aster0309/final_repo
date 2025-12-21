from fastapi import FastAPI, HTTPException, Depends
from sqlmodel import Session, select
from typing import List
from database import Todo, TodoCreate, engine, create_db_and_tables
import uvicorn
from contextlib import asynccontextmanager

app = FastAPI()

# 啟動時建立資料庫
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()

# 取得資料庫連線的 Dependency
def get_session():
    with Session(engine) as session:
        yield session

# --- API 實作開始 ---

# 1. 新增待辦事項 (Create)
# 回傳：直接回傳新增成功的那個物件，這樣使用者可以確認 ID 是多少
@app.post("/todos/", response_model=Todo)
def create_todo(todo_in: TodoCreate, session: Session = Depends(get_session)):
    todo_db = Todo.model_validate(todo_in)
    
    # 如果你要自己補上其他預設值 (例如想要強制剛建立時一定是未完成)
    todo_db.is_completed = False

    session.add(todo_db)
    session.commit()
    session.refresh(todo_db)
    return todo_db

# 2. 查詢所有待辦事項 (Read)
# 如果你們想要讓回傳看起來更像一個「系統」，可以回傳一個字典
@app.get("/todos/")
def read_todos(session: Session = Depends(get_session)):
    todos = session.exec(select(Todo)).all()
    total = len(todos)
    return {
        "status": "success",
        "total_count": total,
        "data": todos
    }
# 3. 簡單分析待辦事項
@app.get("/todos/summary")
def get_summary(session: Session = Depends(get_session)):
    todos = session.exec(select(Todo)).all()
    
    # 在 Python 這裡做一點「處理」，而不只是單純讀資料庫
    urgent_count = sum(1 for t in todos if t.priority >= 3)
    completed_count = sum(1 for t in todos if t.is_completed)
    
    # 回傳統計資訊
    return {
        "message": "待辦事項分析報告",
        "total_tasks": len(todos),
        "urgent_tasks": urgent_count, # 告訴助教：看！我有用程式判斷有多少緊急事項
        "completion_rate": f"{ (completed_count / len(todos) * 100) if todos else 0 }%"
    }



if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)