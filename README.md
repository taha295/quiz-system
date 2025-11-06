# Quiz System (Flask)

A minimal Flask-based quiz system to learn dynamic question rendering and user tracking.

Features:
- Admin can create quizzes by pasting JSON for questions
- Users can view quizzes and attempt them
- Score calculation and attempt storage

Quick start (Windows PowerShell):

```powershell
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser. Use the Admin page to paste sample JSON and create quizzes.

Notes:
- This is intentionally minimal to focus on dynamic rendering and data tracking.
- For production set a secure SECRET_KEY and use a proper database.
