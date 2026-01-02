import bcrypt
from fastapi import FastAPI, HTTPException, Depends, Response, Cookie, status
from sqlmodel import Session, select, SQLModel
from database import Todo,TodoRead,TodoListResponse, TodoCreate, User, UserCreate, ChatMessage, engine, create_db_and_tables
import uvicorn
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from google import genai
from google.genai import types # 引入型別定義，讓設定更方便
from pydantic import BaseModel # 用來定義請求格式
from google.api_core import exceptions
import csv
import io
from fastapi.responses import StreamingResponse

# --- 🔐 安全設定 (Config) ---
SECRET_KEY = "jasfSGSGagsShui5454g" # 真實上線時要換成很長很複雜的亂碼
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Token 有效期 30 分鐘
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Refresh Token 7天後過期
# 密碼加密器
#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- 🛠️ 工具函式 (Helper Functions) ---

# 取得資料庫連線的 Dependency
def get_session():
    with Session(engine) as session:
        yield session

# 1. 驗證密碼 (檢查輸入的跟資料庫的亂碼是否一樣)
def verify_password(plain_password: str, hashed_password: str):
    """驗證密碼是否正確"""
    try:
        # bcrypt 需要 bytes 格式進行比較
        return bcrypt.checkpw(
            plain_password.encode('utf-8'), 
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False

# 2. 密碼加密 (把 "123456" 變成亂碼)
def get_password_hash(password: str):
    """將密碼加密"""
    # bcrypt 限制密碼長度為 72 字节（通常不用擔心，除非密碼超級長）
    # 這裡我們手動處理，避免 passlib 的內部測試 Bug
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8') # 轉成字串存入資料庫

# 3. 製作 JWT Token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire}) # 加入過期時間
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 從 Cookie 讀取 Token 的依賴函式
def get_current_user(
        access_token: Optional[str] = Cookie(default=None),
        session: Session = Depends(get_session)
):
    
    # 如果沒有 token，或是 token 格式不對
    if not access_token:
        raise HTTPException(status_code=401, detail="未登入 (找不到 Cookie)")
    
    try:
        # 去掉 "Bearer " 前綴
        scheme, _, param = access_token.partition(" ")
        payload = jwt.decode(param, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type") # 讀取剛剛存的 type

        # --- 安全檢查 ---
        if user_id is None:
            raise HTTPException(status_code=401, detail="無效的憑證")
        
        # 如果有人拿 refresh token 來想存取待辦事項，直接擋掉
        if token_type != "access":
            raise HTTPException(status_code=401, detail="憑證類型錯誤")
        
    except JWTError:
        raise HTTPException(status_code=401, detail="憑證解析失敗")
    
    # 去資料庫撈出這個人
    user = session.get(User, int(user_id))
    if not user:
        raise HTTPException(status_code=401, detail="找不到使用者")
    
    return user

# 登入帳號格式
class LoginRequest(SQLModel):
    username: str
    password: str

# --- 定義請求模型 ---
class ChatRequest(BaseModel):
    message: str
    api_key: str
    # Gemini 目前主流是用 gemini-1.5-flash (快且便宜) 或 gemini-1.5-pro (強大)
    model: str = "gemini-2.5-flash"

# 啟動時建立資料庫
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)

origins = [
    "http://127.0.0.1:5500",  # Live Server 最常見的埠號   # 後端自己的埠號
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "null"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

# ========================api路由========================

# ________________________帳號功能________________________

# 註冊帳號
@app.post("/register")
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    # 檢查輸入是否空白
    if not user_in.username or not user_in.username.strip() or not user_in.password or not user_in.password.strip():
        raise HTTPException(status_code=400, detail="帳號或密碼不能輸入空白")
    
    user_in.username = user_in.username.strip()
    user_in.password = user_in.password.strip()

    # 檢查帳號是否重複
    existing_user = session.exec(select(User).where(User.username == user_in.username)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="帳號已存在")
    
    # 把密碼加密
    hashed_pw = get_password_hash(user_in.password)
    
    # 建立新使用者
    new_user = User(username=user_in.username, hashed_password=hashed_pw)
    session.add(new_user)
    session.commit()
    
    return {"message": "註冊成功"}

# 登入帳號
@app.post("/login")
def login(data: LoginRequest, response: Response, session: Session = Depends(get_session)):
    # 檢查輸入是否空白
    if not data.username or not data.username.strip() or not data.password or not data.password.strip():
        raise HTTPException(status_code=400, detail="帳號或密碼不能輸入空白")
    
    # 1. 找使用者
    user = session.exec(select(User).where(User.username == data.username)).first()
    
    # 2. 驗證帳號是否存在 且 密碼是否正確
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    
    # 3. 製作 Access Token (短命，標記 type=access)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "type": "access"},# 多加一個 type
        expires_delta=access_token_expires
    )
    
    # 4. 製作 Refresh Token (長命，標記 type=refresh)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_access_token(
        data={"sub": str(user.id), "type": "refresh"}, # 多加一個 type
        expires_delta=refresh_token_expires
    )

    # 5.  設定 Cookie 
    # httponly=True 代表這個 Cookie 只能被後端讀取，JavaScript 拿不到 (防駭客 XSS 攻擊)
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True,
        samesite="lax", # 建議加上這個
        secure=False 
    )
    
    # 新增這行：把 refresh token 也存進 cookie
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, # Refresh token 通常不需要 "Bearer " 前綴，直接存就好
        httponly=True,
        samesite="lax",
        secure=False
    )

    return {"message": "登入成功", "access_token": access_token, "refresh_token": refresh_token}

# 登出帳號
@app.post("/logout")
async def logout(response: Response):
    # 這裡的 key 必須跟你登入時設定的名稱一模一樣 (通常是 access_token)
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        samesite="lax",
        secure=False  # 如果你是在本地 http 執行，設為 False
    )
    return {"message": "已登出"}

# 刷新token
@app.post("/refresh")
def refresh_token(
    response: Response,
    refresh_token: Optional[str] = Cookie(default=None), # 這裡我們要讀取 refresh_token cookie
    session: Session = Depends(get_session)
):
    # 1. 檢查有沒有 refresh token
    if not refresh_token:
        raise HTTPException(status_code=401, detail="請重新登入")
        
    try:
        # 2. 解析並驗證 Refresh Token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type")
        
        # 3. 確保這真的是一張 refresh token
        if token_type != "refresh":
             raise HTTPException(status_code=401, detail="無效的刷新憑證")
             
        # 4. 確認使用者還存在 (防止使用者被刪除後還能刷新)
        user = session.get(User, int(user_id))
        if not user:
            raise HTTPException(status_code=401, detail="使用者不存在")
            
        # 5. 簽發「新的」 Access Token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": str(user.id), "type": "access"},
            expires_delta=access_token_expires
        )
        
        # 6. 把新的 Access Token 寫回 Cookie
        response.set_cookie(
            key="access_token", 
            value=f"Bearer {new_access_token}", 
            httponly=True,
            samesite="lax"
        )
        
        return {"message": "Token 刷新成功", "access_token": new_access_token}
        
    except JWTError:
        raise HTTPException(status_code=401, detail="刷新失敗，請重新登入")

# ________________________基本功能________________________

# 1. 新增待辦事項 (Create)
# 回傳：直接回傳新增成功的那個物件，這樣使用者可以確認 ID 是多少
@app.post("/todos/", response_model=Todo)
def create_todo(
    todo_in: TodoCreate, 
    current_user: User = Depends(get_current_user), # <--- 這裡變了！
    session: Session = Depends(get_session)
):
    todo_db = Todo.model_validate(todo_in)
    todo_db.is_completed = False
    todo_db.owner_id = current_user.id # 直接從 user 物件拿 ID
    
    session.add(todo_db)
    session.commit()
    session.refresh(todo_db)
    return TodoRead.from_db(todo_db)

# 2. 查詢所有待辦事項 (Read)
# 如果你們想要讓回傳看起來更像一個「系統」，可以回傳一個字典
@app.get("/todos/", response_model=TodoListResponse)
def read_todos(
    
    category: Optional[str] = None, # 新增查詢參數
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # 只撈 current_user 自己的資料
    statement = select(Todo).where(Todo.owner_id == current_user.id)
    # 如果使用者有傳入類別（不是 None），就在 SQL 加上過濾條件
    if category:
        statement = statement.where(Todo.category.contains(category))

    results = session.exec(statement).all()

    total = len(session.exec(statement).all())
    return {
        "status": "success",
        "total_count": total,
        "data": [TodoRead.from_db(t) for t in results]
    }

# 3. 簡單分析待辦事項
@app.get("/todos/summary")
def get_summary(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    statement = select(Todo).where(Todo.owner_id == current_user.id)
    todos = session.exec(statement).all()
    
    # 在 Python 這裡做一點「處理」，而不只是單純讀資料庫
    urgent_count = sum(1 for t in todos if t.priority >= 3)
    completed_count = sum(1 for t in todos if t.is_completed)
    
    # 回傳統計資訊
    return {
        "message": "待辦事項分析報告",
        "total_tasks": len(todos),
        "urgent_tasks": urgent_count, # 告訴助教：看！我有用程式判斷有多少緊急事項
        "completion_rate": f"{ int(completed_count / len(todos) * 100) if todos else 0 }%"
    }

# ________________________個人助理功能________________________

# 1. 聊天 API (BYOK + 儲存紀錄 + 附帶上下文)
@app.post("/chat")
def chat_with_gemini(
    chat_in: ChatRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # 1. 檢查 Key
    if not chat_in.api_key:
        raise HTTPException(status_code=400, detail="請提供 Google API Key")

    # 2. 儲存使用者提問
    user_msg = ChatMessage(
        role="user",
        content=chat_in.message,
        owner_id=current_user.id
    )
    session.add(user_msg)
    session.commit()

    # ==========================================
    # ★★★ RAG: 撈取待辦事項 (這段邏輯不變) ★★★
    # ==========================================
    todos = session.exec(select(Todo).where(Todo.owner_id == current_user.id)).all()
    
    todo_list_text = []
    for t in todos:
        status = "已完成" if t.is_completed else "未完成"
        due_str = f", 到期日:{t.due_date}" if t.due_date else ""
        info = f"- [ID:{t.id}] {t.title} (狀態:{status}, 優先度:{t.priority}{due_str})"
        todo_list_text.append(info)
    
    todo_context_str = "\n".join(todo_list_text) if todo_list_text else "(目前沒有任何待辦事項)"

    system_prompt = f"""
    你是一個專業的個人任務管理助理。
    這是使用者目前的待辦事項資料庫：
    {todo_context_str}
    
    請遵守以下規則：
    1. 根據上述資料庫回答問題。
    2. 如果使用者問「我還有什麼事沒做？」，請幫他列出「未完成」且「優先度高」的項目。
    3. 用繁體中文回答，語氣親切活潑。
    4. 你無法直接操作資料庫，如果使用者想刪除或新增，請引導他操作介面按鈕。
    """
    
    # ==========================================
    # ★★★ 新版 SDK 實作開始 ★★★
    # ==========================================
    
    # 3. 準備歷史對話 (轉換成新版格式)
    # 新版格式建議：types.Content(role="user", parts=[types.Part(text="...")])
    
    db_history = session.exec(
        select(ChatMessage)
        .where(ChatMessage.owner_id == current_user.id)
        .order_by(ChatMessage.timestamp.desc())
        .limit(10)
    ).all()
    db_history = reversed(db_history)

    gemini_history = []
    for msg in db_history:
        # 轉換角色名稱: DB存的是 "assistant" 或 "user"，但 Gemini API 用 "model" 代表 AI
        role = "user" if msg.role == "user" else "model"
        
        # 建立物件
        gemini_history.append(
            types.Content(
                role=role,
                parts=[types.Part(text=msg.content)]
            )
        )

    try:
        # 4. 初始化 Client
        client = genai.Client(api_key=chat_in.api_key)
        
        # 5. 建立聊天室並發送訊息
        # 新版把 system_instruction 放在 config 裡面
        chat = client.chats.create(
            model=chat_in.model,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.7 # 可以設定創意程度
            ),
            history=gemini_history
        )
        
        response = chat.send_message(chat_in.message)
        ai_reply_text = response.text

    except Exception as e:
        print(f"Gemini Error: {e}") # 印出錯誤方便除錯
        raise HTTPException(status_code=500, detail=f"Gemini API 錯誤: {str(e)}")
    
    # 6. 儲存 AI 回答 (這裡不變)
    ai_msg = ChatMessage(
        role="assistant", 
        content=ai_reply_text,
        owner_id=current_user.id
    )
    session.add(ai_msg)
    session.commit()

    return {"reply": ai_reply_text}

# 2. 獲取歷史對話紀錄 (讓前端一打開頁面可以顯示舊對話)
@app.get("/chat/history")
def get_chat_history(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # 撈取該使用者的所有對話 (或是限制最近 50 筆)
    statement = (
        select(ChatMessage)
        .where(ChatMessage.owner_id == current_user.id)
        .order_by(ChatMessage.timestamp.asc()) # 依照時間順序：舊 -> 新
    )
    results = session.exec(statement).all()
    
    return results

# ________________________其他功能________________________

# 1. 更改完成狀態 (Update)
@app.patch("/todos/{todo_id}/complete", response_model=Todo)
def mark_completed(todo_id: int, session: Session = Depends(get_session)):
    # 步驟 1: 根據 ID 去資料庫找這筆資料
    todo = session.get(Todo, todo_id)
    
    # 步驟 2: 如果找不到 (是 None)，就回傳 404 錯誤
    if not todo:
        raise HTTPException(status_code=404, detail="找不到這筆待辦事項")
    
    # 步驟 3: 修改狀態
    # 這裡我們設計成：只要呼叫這個 API，就視為「已完成」(True)
    # 如果你想做成「切換」(True 變 False, False 變 True)，可以寫: todo.is_completed = not todo.is_completed
    todo.is_completed = True 
    
    # 步驟 4: 存檔
    session.add(todo)
    session.commit()
    session.refresh(todo)
    
    return todo

# 2. 刪除待辦事項
@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int, session: Session = Depends(get_session)):
    # 步驟 1: 找資料
    todo = session.get(Todo, todo_id)
    
    # 步驟 2: 找不到就報錯
    if not todo:
        raise HTTPException(status_code=404, detail="找不到這筆待辦事項")
    
    # 步驟 3: 刪除
    session.delete(todo)
    session.commit()
    
    # 步驟 4: 回傳一個簡單的訊息告訴使用者刪除成功
    return {"message": "刪除成功", "deleted_id": todo_id}



if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)


# ________________________匯出功能________________________

@app.get("/todos/download/csv")
def download_todos_csv(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # 1. 撈取該使用者的所有待辦事項
    statement = select(Todo).where(Todo.owner_id == current_user.id)
    todos = session.exec(statement).all()

    # 2. 建立一個記憶體內的文字流 (In-memory text stream)
    output = io.StringIO()
    # 寫入 UTF-8 BOM 以防止 Excel 開啟時中文亂碼
    output.write('\ufeff')
    
    writer = csv.writer(output)

    # 3. 寫入標題列 (Column Headers)
    writer.writerow(["ID", "標題", "描述", "類別", "優先度", "狀態", "到期日"])

    # 4. 寫入內容
    for t in todos:
        status = "已完成" if t.is_completed else "未完成"
        writer.writerow([
            t.id,
            t.title,
            t.category or "無",
            t.priority,
            status,
            t.due_date or "無"
        ])

    # 5. 指標移回開頭，準備讀取
    output.seek(0)

    # 6. 回傳串流回應，設定檔案名稱
    filename = f"todos_{datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

 
