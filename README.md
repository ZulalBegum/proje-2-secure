# SWE210 Secure Grade Portal

This project is a Flask-based secure student grade portal.

## Security Features

- Passwords are stored with bcrypt hashes.
- Grades are encrypted at rest with Fernet symmetric encryption.
- SQLite queries use parameter binding to prevent SQL injection.
- Student and instructor screens are separated with role-based access control.
- Students can only view their own grade records.
- Only instructor accounts can create/delete grades and change user roles.
- Grade values are restricted to `AA`, `AB`, `BB`, `CB`, `CC`, `DC`, `DD`, `FF`.
- Forms include CSRF tokens.
- Session cookies and common browser security headers are configured.
- Weak legacy instructor password `isu2026` is automatically rotated on first boot.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5001`.

Admin login uses this username and password:

```text
Username: instructor
Password: isu2026
```

For local testing, the first run creates `admin_initial_password.txt`; use the password listed there. For production, set `FLASK_SECRET_KEY` and `ADMIN_PASSWORD` as environment variables before first boot.

## Deployment Notes

Do not commit generated secrets or local data files. The app creates these files on first run and they are ignored by Git:

- `.flask_secret`
- `encryption.key`
- `admin_initial_password.txt`
- `grades.db`

For a public deployment on a Python host such as Render, set these environment variables:

```text
FLASK_SECRET_KEY=use-a-long-random-secret
ADMIN_PASSWORD=use-a-strong-instructor-password
FLASK_ENV=production
```

Use this start command:

```bash
gunicorn app:app
```

If you deploy with Render Blueprint, the repository also includes `render.yaml`, so Render can detect the web service automatically.
