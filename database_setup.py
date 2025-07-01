import sqlite3

def setup_database():
    """Creates/updates the database with a vt_score column for caching."""
    try:
        conn = sqlite3.connect('user_data.db')
        cursor = conn.cursor()

        # User table is fine as is
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                reset_token TEXT, token_expiry TIMESTAMP
            )''')

        # Create scan_history table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                vt_score TEXT,
                scan_date TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Check if vt_score column exists and add it if it doesn't.
        # This prevents errors if you run the script multiple times.
        cursor.execute("PRAGMA table_info(scan_history)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'vt_score' not in columns:
            cursor.execute('ALTER TABLE scan_history ADD COLUMN vt_score TEXT')
            print("✅ Added 'vt_score' column to scan_history table for caching.")
        
        conn.commit()
        conn.close()
        print("✅ Database is set up correctly.")
    except Exception as e:
        print(f"❌ Database setup failed: {e}")


if __name__ == "__main__":
    setup_database()