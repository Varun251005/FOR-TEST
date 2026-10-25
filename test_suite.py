import os
import unittest
import tempfile
import sqlite3
import shutil
import logging
from werkzeug.security import check_password_hash

# Ensure test secret key is set before import if needed
os.environ["FLASK_SECRET_KEY"] = "test-secret-key-for-automated-verification-12345"

from app import create_app, init_db, get_db_connection


class ForTestApplicationTestCase(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_database.db")
        self.log_path = os.path.join(self.test_dir, "logs", "test_requests.log")

        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-key-32-bytes-long-string-sample!",
            "DATABASE_PATH": self.db_path,
            "LOG_FILE_PATH": self.log_path,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        logger_name = f"for_test.requests.{os.path.abspath(self.log_path)}"
        req_logger = logging.getLogger(logger_name)
        for h in req_logger.handlers[:]:
            h.close()
            req_logger.removeHandler(h)
        shutil.rmtree(self.test_dir)

    def test_01_login_page_loads_successfully(self):
        """Case 1: Login page loads successfully."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("FOR-TEST", html)
        self.assertIn("AI-IDS-IPS Testing Environment", html)
        self.assertIn("Sign in to continue", html)
        self.assertIn("Controlled Security Testing Environment", html)
        self.assertIn("This application is intended for authorized laboratory testing.", html)

    def test_02_correct_admin_credentials_work(self):
        """Case 2: Correct admin credentials work."""
        response = self.client.post("/login", data={"username": "admin", "password": "admin123"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/dashboard", response.headers["Location"])

        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "admin")
            self.assertEqual(sess.get("role"), "admin")
            self.assertIsNotNone(sess.get("user_id"))

    def test_03_correct_user_credentials_work(self):
        """Case 3: Correct normal-user credentials work."""
        response = self.client.post("/login", data={"username": "user", "password": "user123"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/dashboard", response.headers["Location"])

        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "user")
            self.assertEqual(sess.get("role"), "user")
            self.assertIsNotNone(sess.get("user_id"))

    def test_04_incorrect_credentials_are_rejected(self):
        """Case 4: Incorrect credentials are rejected."""
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "wrongpassword999"},
        )
        self.assertEqual(response.status_code, 401)
        html = response.get_data(as_text=True)
        self.assertIn("Invalid username or password.", html)

        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    def test_05_passwords_never_written_to_logs(self):
        """Case 5: Passwords are never written to logs."""
        sensitive_secret = "UltraSecretPasswordDoNotLogMe987654321"
        self.client.post(
            "/login",
            data={"username": "admin", "password": sensitive_secret},
        )

        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as f:
            log_content = f.read()

        self.assertNotIn(sensitive_secret, log_content)
        self.assertIn("LOGIN_FAILURE", log_content)

    def test_06_successful_login_redirects_to_dashboard(self):
        """Case 6: Successful login redirects to dashboard."""
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Authentication Dashboard", html)
        self.assertIn("Welcome, <span class=\"user-highlight\">admin</span>", html)
        self.assertIn("AUTHENTICATED", html)
        self.assertIn("Controlled AI-IDS-IPS Network Traffic Testing", html)

    def test_07_unauthenticated_dashboard_access_rejected(self):
        """Case 7: Unauthenticated dashboard access is rejected."""
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_08_logout_clears_session(self):
        """Case 8: Logout clears the session."""
        # Log in first
        self.client.post("/login", data={"username": "admin", "password": "admin123"})
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "admin")

        # Perform logout
        logout_response = self.client.post("/logout")
        self.assertEqual(logout_response.status_code, 302)
        self.assertIn("/login", logout_response.headers["Location"])

        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertNotIn("username", sess)

    def test_09_dashboard_access_after_logout(self):
        """Case 9: Dashboard access after logout requires authentication."""
        self.client.post("/login", data={"username": "admin", "password": "admin123"})
        self.client.post("/logout")

        dash_response = self.client.get("/dashboard")
        self.assertEqual(dash_response.status_code, 302)
        self.assertIn("/login", dash_response.headers["Location"])

    def test_10_requests_recorded_in_log(self):
        """Case 10: Requests are recorded in the log with expected telemetry fields."""
        self.client.get("/login")
        self.client.post("/login", data={"username": "admin", "password": "admin123"})
        self.client.post("/logout")
        self.client.post("/login", data={"username": "admin", "password": "bad"})

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        self.assertGreaterEqual(len(lines), 4)
        has_page_request = any("PAGE_REQUEST" in l and "/login" in l for l in lines)
        has_login_success = any("LOGIN_SUCCESS" in l and "302" in l for l in lines)
        has_logout = any("LOGOUT" in l and "302" in l for l in lines)
        has_login_failure = any("LOGIN_FAILURE" in l and "401" in l for l in lines)

        self.assertTrue(has_page_request, "PAGE_REQUEST missing in log")
        self.assertTrue(has_login_success, "LOGIN_SUCCESS missing in log")
        self.assertTrue(has_logout, "LOGOUT missing in log")
        self.assertTrue(has_login_failure, "LOGIN_FAILURE missing in log")

    def test_11_repeated_logins_not_blocked(self):
        """Case 11: Repeated login requests are not blocked by rate limiting or lockout."""
        # Send 35 rapid failed requests
        for i in range(35):
            res = self.client.post("/login", data={"username": "admin", "password": f"wrong_{i}"})
            self.assertEqual(res.status_code, 401, f"Request {i} was blocked or returned unexpected status {res.status_code}")

        # The 36th request with valid credentials should still succeed immediately
        res_valid = self.client.post("/login", data={"username": "admin", "password": "admin123"})
        self.assertEqual(res_valid.status_code, 302)

    def test_12_secret_key_enforcement(self):
        """Case 12: Secret key is strictly required in production configuration."""
        old_env_flask = os.environ.pop("FLASK_SECRET_KEY", None)
        old_env_secret = os.environ.pop("SECRET_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                create_app()
        finally:
            if old_env_flask:
                os.environ["FLASK_SECRET_KEY"] = old_env_flask
            if old_env_secret:
                os.environ["SECRET_KEY"] = old_env_secret

    def test_13_no_duplicate_demo_accounts_on_restart(self):
        """Case 13: Database does not create duplicate demo accounts on restart."""
        # Initial call created accounts
        # Call init_db multiple times
        init_db(self.db_path)
        init_db(self.db_path)

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, password_hash FROM users ORDER BY username")
        rows = cursor.fetchall()
        conn.close()

        self.assertEqual(len(rows), 2)
        usernames = [r["username"] for r in rows]
        self.assertEqual(usernames, ["admin", "user"])

        # Check passwords match hashes
        admin_row = [r for r in rows if r["username"] == "admin"][0]
        user_row = [r for r in rows if r["username"] == "user"][0]

        self.assertTrue(check_password_hash(admin_row["password_hash"], "admin123"))
        self.assertTrue(check_password_hash(user_row["password_hash"], "user123"))


if __name__ == "__main__":
    unittest.main()
