# 📝 AI 智慧待辦清單 (AI Todo List)

這是一個結合 **FastAPI** 後端、**PostgreSQL** 雲端資料庫與 **Gemini AI** 助理的任務管理系統。專案支援自動化部署與多環境切換。

---

## 🌟 核心功能

* **🔒 安全認證系統**：採用 JWT 雙 Token 機制與 HttpOnly Cookie 提升安全性。
* **🤖 Gemini AI 助理**：整合 Google Gemini API，根據待辦事項提供智慧分析。
* **📊 任務管理**：支援新增、刪除、分類篩選、優先權設定及逾期偵測。
* **📥 資料匯出**：支援將待辦清單匯出為 CSV 報表。
* **🚀 自動化 CI/CD**：透過 GitHub Actions 自動進行測試與部署。

---

## 📁 專案結構

* **main.py**：FastAPI 核心邏輯與 API 路由設定。
* **database.py**：SQLModel 資料庫模型定義與連線切換邏輯。
* **index.html**：前端網頁介面 (由 Tailwind CSS 構建)。
* **Dockerfile**：定義容器化執行環境與啟動指令。
* **requirements.txt**：專案所需的 Python 依賴套件清單。
* **.github/workflows/deploy.yml**：GitHub Actions 自動化部署流程設定。

---

## 🌿 分支使用說明

本專案採用的分支管理策略如下：

* **`release` 分支**：**部署專用**。當程式碼推送到此分支時，會觸發 GitHub Actions 並部署至 Render 雲端平台。
* **`main` 分支**：**本地測試專用**。建議在此分支進行功能的開發與本地環境的測試驗證。

---

### 技術棧 (Tech Stack)
* 後端：Python 3.12, FastAPI, SQLModel
* 資料庫：PostgreSQL (雲端), SQLite (本地)
* 部署：Docker, GitHub Actions, Render