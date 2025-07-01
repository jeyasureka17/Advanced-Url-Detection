#
# This is the definitive, FINAL, PORTFOLIO-READY version of the application.
#
# IT INCLUDES ALL YOUR REQUESTED FIXES AND FEATURES:
# 1. NEW UI/UX: Implements the professional, centered layout you designed.
# 2. PROFILE MENU: Places the user profile menu correctly in the top-right corner.
# 3. HISTORY BUG FIX: Ensures the verdict saved to history matches the UI.
# 4. VT API SOLUTION: Implements a 24-hour database cache to drastically reduce
#    API calls, making the project viable for a GitHub portfolio.
#

import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import threading
import joblib
import pandas as pd
import queue
import sqlite3
import hashlib
from datetime import datetime, timedelta
import smtplib, ssl, random, string

# The url_analyzer and train.py from the previous step are correct and compatible.
from url_analyzer import extract_lexical_features, analyze_host_features, analyze_content_features, analyze_url_with_virustotal

from database_setup import setup_database

# In main_app.py
# --- STYLING & CONFIG CONSTANTS ---
BG_COLOR="#121212"; PRIMARY_COLOR="#1E1E1E"; TEXT_COLOR="#FFFFFF"; SUBTEXT_COLOR="#BBBBBB"
ACCENT_COLOR="#03DAC6"; PURPLE_ACCENT="#BB86FC"; ENTRY_BG="#2D2D2D"

# Import the secure configuration
from config import SENDER_EMAIL, SENDER_PASSWORD

class AppController(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("Advanced URL Malware Detection"); self.geometry("1100x800"); self.configure(bg=BG_COLOR)
        container = tk.Frame(self); container.pack(side="top", fill="both", expand=True); container.grid_rowconfigure(0, weight=1); container.grid_columnconfigure(0, weight=1)
        self.frames = {};
        for F in (LoginPage, SignupPage, MainPage, HistoryPage, ForgotPasswordPage):
            frame = F(container, self); self.frames[F] = frame; frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(LoginPage)
    def show_frame(self, cont, data=None):
        frame = self.frames[cont]
        if hasattr(frame, 'on_show'): frame.on_show(data)
        frame.tkraise()
    def get_db_connection(self): return sqlite3.connect('user_data.db')

# --- AUTH & HISTORY FRAMES (Unchanged, collapsed for brevity) ---
class AuthFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG_COLOR); self.controller = controller;
        main_frame = tk.Frame(self, bg=PRIMARY_COLOR, padx=40, pady=40, relief='solid', bd=1, highlightbackground=ACCENT_COLOR, highlightthickness=1)
        main_frame.place(relx=0.5, rely=0.5, anchor='center'); self.create_widgets(main_frame)
    def create_widgets(self, parent): raise NotImplementedError
class LoginPage(AuthFrame):
    def create_widgets(self, parent):
        tk.Label(parent, text="Login", font=('Arial', 28, "bold"), fg=TEXT_COLOR, bg=PRIMARY_COLOR).pack(pady=(0, 30)); tk.Label(parent, text="Email Address", font=('Arial', 12), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w')
        self.email_entry = tk.Entry(parent, font=('Arial', 14), width=35, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, bd=0); self.email_entry.pack(pady=(5, 20), ipady=5)
        tk.Label(parent, text="Password", font=('Arial', 12), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w')
        self.password_entry = tk.Entry(parent, font=('Arial', 14), width=35, show="*", bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, bd=0); self.password_entry.pack(pady=(5, 10), ipady=5)
        tk.Button(parent, text="Forgot Password?", bd=0, bg=PRIMARY_COLOR, fg="cyan", activebackground=PRIMARY_COLOR, command=lambda: self.controller.show_frame(ForgotPasswordPage), cursor="hand2").pack(anchor='e')
        tk.Button(parent, text="Login", font=('Arial', 14, "bold"), bg=ACCENT_COLOR, fg="black", bd=0, command=self.login, cursor="hand2").pack(fill='x', ipady=8, pady=(20, 15))
        tk.Button(parent, text="Don't have an account? Sign Up", bd=0, bg=PRIMARY_COLOR, fg=PURPLE_ACCENT, activebackground=PRIMARY_COLOR, command=lambda: self.controller.show_frame(SignupPage), cursor="hand2").pack()
    def login(self):
        email = self.email_entry.get(); password = self.password_entry.get();
        if not email or not password: messagebox.showerror("Login Failed", "Email and password cannot be empty."); return
        password_hash = hashlib.sha256(password.encode()).hexdigest(); conn = self.controller.get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = ? AND password_hash = ?", (email, password_hash)); user = cursor.fetchone(); conn.close()
        if user: self.controller.current_user_email = user[0]; self.controller.show_frame(MainPage)
        else: messagebox.showerror("Login Failed", "Invalid email or password.")
class SignupPage(AuthFrame):
    def create_widgets(self, parent):
        tk.Label(parent, text="Create Account", font=('Arial', 28, "bold"), fg=TEXT_COLOR, bg=PRIMARY_COLOR).pack(pady=(0, 30)); tk.Label(parent, text="Email Address", font=('Arial', 12), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w')
        self.email_entry = tk.Entry(parent, font=('Arial', 14), width=35, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, bd=0); self.email_entry.pack(pady=(5, 20), ipady=5)
        tk.Label(parent, text="Password", font=('Arial', 12), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w')
        self.password_entry = tk.Entry(parent, font=('Arial', 14), width=35, show="*", bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, bd=0); self.password_entry.pack(pady=(5, 30), ipady=5)
        tk.Button(parent, text="Sign Up", font=('Arial', 14, "bold"), bg=ACCENT_COLOR, fg="black", bd=0, command=self.signup, cursor="hand2").pack(fill='x', ipady=8)
        tk.Button(parent, text="Already have an account? Login", bd=0, bg=PRIMARY_COLOR, fg=PURPLE_ACCENT, activebackground=PRIMARY_COLOR, command=lambda: self.controller.show_frame(LoginPage), cursor="hand2").pack(pady=15)
    def signup(self):
        email = self.email_entry.get(); password = self.password_entry.get()
        if not email or not password or '@' not in email: messagebox.showwarning("Input Error", "Please enter a valid email and password."); return
        password_hash = hashlib.sha256(password.encode()).hexdigest(); conn = self.controller.get_db_connection(); cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash)); conn.commit(); messagebox.showinfo("Success", "Account created successfully! Please log in."); self.controller.show_frame(LoginPage)
        except sqlite3.IntegrityError: messagebox.showerror("Error", "An account with this email already exists.")
        finally: conn.close()
class ForgotPasswordPage(AuthFrame):
    def create_widgets(self, parent):
        self.parent_frame = parent; self.show_request_view()
    def show_request_view(self):
        self.clear_frame()
        tk.Label(self.parent_frame, text="Forgot Password", font=('Arial', 24, "bold"), fg=TEXT_COLOR, bg=PRIMARY_COLOR).pack(pady=(0, 30))
        tk.Label(self.parent_frame, text="Enter your email to receive a reset code.", font=('Arial', 11), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w', pady=(0,15))
        self.email_entry = tk.Entry(self.parent_frame, font=('Arial', 14), width=35, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, bd=0); self.email_entry.pack(pady=(5, 20), ipady=5)
        tk.Button(self.parent_frame, text="Send Reset Code", font=('Arial', 14, "bold"), bg=ACCENT_COLOR, fg="black", bd=0, command=self.send_reset_code, cursor="hand2").pack(fill='x', ipady=8)
        tk.Button(self.parent_frame, text="Back to Login", bd=0, bg=PRIMARY_COLOR, fg=PURPLE_ACCENT, activebackground=PRIMARY_COLOR, command=lambda: self.controller.show_frame(LoginPage), cursor="hand2").pack(pady=15)
    def show_reset_view(self, email):
        self.clear_frame()
        tk.Label(self.parent_frame, text="Reset Password", font=('Arial', 24, "bold"), fg=TEXT_COLOR, bg=PRIMARY_COLOR).pack(pady=(0, 20))
        tk.Label(self.parent_frame, text=f"A reset code was sent to {email}", font=('Arial', 11), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w', pady=(0,15))
        tk.Label(self.parent_frame, text="Reset Code", font=('Arial', 12), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w')
        self.code_entry = tk.Entry(self.parent_frame, font=('Arial', 14), width=35, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, bd=0); self.code_entry.pack(pady=(5, 20), ipady=5)
        tk.Label(self.parent_frame, text="New Password", font=('Arial', 12), fg=SUBTEXT_COLOR, bg=PRIMARY_COLOR).pack(anchor='w')
        self.new_password_entry = tk.Entry(self.parent_frame, font=('Arial', 14), width=35, show="*", bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, bd=0); self.new_password_entry.pack(pady=(5, 30), ipady=5)
        tk.Button(self.parent_frame, text="Update Password", font=('Arial', 14, "bold"), bg=ACCENT_COLOR, fg="black", bd=0, command=lambda: self.reset_password(email), cursor="hand2").pack(fill='x', ipady=8)
    def send_reset_code(self):
        email = self.email_entry.get();
        if not email: messagebox.showwarning("Input Error", "Please enter an email address."); return
        conn = self.controller.get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if not cursor.fetchone(): messagebox.showerror("Error", "No account found with that email address."); conn.close(); return
        reset_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        expiry_time = datetime.now() + timedelta(minutes=10)
        cursor.execute("UPDATE users SET reset_token = ?, token_expiry = ? WHERE email = ?", (reset_code, expiry_time.strftime('%Y-%m-%d %H:%M:%S'), email))
        conn.commit(); conn.close()
        threading.Thread(target=self.email_user, args=(email, reset_code), daemon=True).start()
        messagebox.showinfo("Success", "A reset code has been sent to your email. It may be in your spam folder.")
        self.show_reset_view(email)
    def email_user(self, to_email, code):
        message = f"Subject: Your Password Reset Code\n\nYour password reset code is: {code}\nThis code will expire in 10 minutes."
        context = ssl.create_default_context()
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(SENDER_EMAIL, SENDER_PASSWORD); server.sendmail(SENDER_EMAIL, to_email, message)
        except Exception as e: messagebox.showerror("Email Error", f"Failed to send reset email. Check console for details. Error: {e}")
    def reset_password(self, email):
        code = self.code_entry.get(); new_password = self.new_password_entry.get()
        if not code or not new_password: messagebox.showwarning("Input Error", "Please fill in all fields."); return
        conn = self.controller.get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT reset_token, token_expiry FROM users WHERE email = ?", (email,)); result = cursor.fetchone()
        if not result or result[0] != code: messagebox.showerror("Error", "Invalid reset code."); conn.close(); return
        expiry = datetime.strptime(result[1], '%Y-%m-%d %H:%M:%S')
        if datetime.now() > expiry: messagebox.showerror("Error", "Reset code has expired."); conn.close(); return
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        cursor.execute("UPDATE users SET password_hash = ?, reset_token = NULL, token_expiry = NULL WHERE email = ?", (new_password_hash, email)); conn.commit(); conn.close()
        messagebox.showinfo("Success", "Password has been reset successfully. Please log in."); self.controller.show_frame(LoginPage)
    def clear_frame(self):
        for widget in self.parent_frame.winfo_children(): widget.destroy()
class HistoryPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR); self.controller = controller
        self.grid_rowconfigure(1, weight=1); self.grid_columnconfigure(0, weight=1)
        top_bar = tk.Frame(self, bg=PRIMARY_COLOR); top_bar.grid(row=0, column=0, sticky="ew", padx=50, pady=20)
        tk.Label(top_bar, text="Your Scan History", font=('Arial', 28, "bold"), fg=TEXT_COLOR, bg=PRIMARY_COLOR).pack(side='left')
        tk.Button(top_bar, text="< Back to Analyzer", font=('Arial', 12), command=lambda: controller.show_frame(MainPage), cursor="hand2", bg=ENTRY_BG, fg=TEXT_COLOR).pack(side='right')
        style = ttk.Style(); style.theme_use("clam")
        style.configure("Treeview", background=ENTRY_BG, foreground=SUBTEXT_COLOR, fieldbackground=ENTRY_BG, rowheight=25, font=('Courier', 11))
        style.configure("Treeview.Heading", background=PRIMARY_COLOR, foreground=PURPLE_ACCENT, font=('Arial', 12, 'bold'))
        style.map('Treeview', background=[('selected', ACCENT_COLOR)])
        tree_frame = tk.Frame(self); tree_frame.grid(row=1, column=0, sticky='nsew', padx=50, pady=(0, 20))
        self.history_tree = ttk.Treeview(tree_frame, columns=("Date", "Verdict", "VT Score", "URL"), show="headings")
        self.history_tree.heading("Date", text="Date & Time"); self.history_tree.column("Date", width=180, anchor='w')
        self.history_tree.heading("Verdict", text="Verdict"); self.history_tree.column("Verdict", width=150, anchor='w')
        self.history_tree.heading("VT Score", text="VT Score"); self.history_tree.column("VT Score", width=100, anchor='center')
        self.history_tree.heading("URL", text="URL Scanned"); self.history_tree.column("URL", anchor='w')
        self.history_tree.pack(side='left', fill='both', expand=True)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set); scrollbar.pack(side='right', fill='y')
        self.history_tree.tag_configure("safe", foreground="#4CAF50"); self.history_tree.tag_configure("risk", foreground="#FFC107"); self.history_tree.tag_configure("malicious", foreground="#F44336")
    def on_show(self, data=None):
        for i in self.history_tree.get_children(): self.history_tree.delete(i)
        conn = self.controller.get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT h.url, h.verdict, h.vt_score, h.scan_date FROM scan_history h JOIN users u ON u.id = h.user_id WHERE u.email = ? ORDER BY h.scan_date DESC LIMIT 100", (self.controller.current_user_email,))
        for row in cursor.fetchall():
            url, verdict, vt_score, date_str = row
            date_obj = datetime.strptime(date_str.split('.')[0], '%Y-%m-%d %H:%M:%S'); formatted_date = date_obj.strftime('%Y-%m-%d %I:%M %p')
            tag = ""
            if verdict == "SAFE": tag = "safe"
            elif verdict == "POTENTIAL RISK": tag = "risk"
            elif verdict == "MALICIOUS": tag = "malicious"
            self.history_tree.insert("", "end", values=(formatted_date, verdict, vt_score or "N/A", url), tags=(tag,))
        conn.close()

# --- THE NEW, REDESIGNED MainPage ---
class MainPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR); self.controller = controller
        self.gui_queue = queue.Queue(); self.load_model(); self.create_widgets(); self.after(100, self.process_queue)

    def load_model(self):
        try: payload = joblib.load('url_rf_model.pkl'); self.model, self.model_features = payload['model'], payload['features']
        except Exception as e: messagebox.showerror("Model Error", f"Could not load url_rf_model.pkl. Please train the model. Error: {e}"); self.controller.destroy()

    def create_widgets(self):
        # --- TOP BAR WITH PROFILE MENU ---
        top_bar = tk.Frame(self, bg=PRIMARY_COLOR); top_bar.pack(fill='x', padx=20, pady=10)
        tk.Label(top_bar, text="").pack(side='left', expand=True) # Spacer
        profile_menu_btn = tk.Menubutton(top_bar, text="👤 Profile", font=('Arial', 12), bg=ENTRY_BG, fg=TEXT_COLOR, padx=10, pady=5, cursor="hand2", relief='raised', bd=1)
        profile_menu = tk.Menu(profile_menu_btn, tearoff=0)
        profile_menu.add_command(label="View Scan History", command=lambda: self.controller.show_frame(HistoryPage))
        profile_menu.add_separator(); profile_menu.add_command(label="Logout", command=lambda: self.controller.show_frame(LoginPage))
        profile_menu_btn["menu"] = profile_menu; profile_menu_btn.pack(side='right')

        # --- MAIN CENTERED FRAME (YOUR NEW DESIGN) ---
        center_frame = tk.Frame(self, bg=PRIMARY_COLOR)
        center_frame.pack(expand=True, fill='x', padx=100)
        
        tk.Label(center_frame, text="Advanced URL Detector", font=('Arial', 32, "bold"), fg=TEXT_COLOR, bg=PRIMARY_COLOR).pack(pady=(20, 30))

        entry_frame = tk.Frame(center_frame, bg=PRIMARY_COLOR); entry_frame.pack(fill='x', pady=10)
        self.entry_url = tk.Entry(entry_frame, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, font=('Arial', 14), bd=0, relief='flat', width=60)
        self.entry_url.pack(side='left', fill='x', expand=True, ipady=10, padx=(0,10))
        tk.Button(entry_frame, text='ANALYZE', command=self.check_url, bg=ACCENT_COLOR, fg="black", font=('Arial', 12, 'bold'), bd=0, padx=25, cursor="hand2").pack(side='right', ipady=6)
        
        results_container = tk.Frame(center_frame, bg=PRIMARY_COLOR); results_container.pack(fill='x', expand=True, pady=30)
        results_container.grid_columnconfigure((0, 1), weight=1)

        internal_frame = tk.Frame(results_container, bg=ENTRY_BG, bd=1, relief='solid'); internal_frame.grid(row=0, column=0, sticky='ns', padx=(0, 10))
        tk.Label(internal_frame, text="Internal Verdict", font=('Arial', 14, 'bold'), fg=PURPLE_ACCENT, bg=ENTRY_BG).pack(pady=10)
        self.lbl_internal_result = tk.Label(internal_frame, text="N/A", font=('Arial', 24, 'bold'), fg=TEXT_COLOR, bg=ENTRY_BG); self.lbl_internal_result.pack(pady=10, padx=20, expand=True)

        vt_frame = tk.Frame(results_container, bg=ENTRY_BG, bd=1, relief='solid'); vt_frame.grid(row=0, column=1, sticky='ns', padx=(10, 0))
        tk.Label(vt_frame, text="VirusTotal Score", font=('Arial', 14, 'bold'), fg=PURPLE_ACCENT, bg=ENTRY_BG).pack(pady=10)
        self.lbl_vt_result = tk.Label(vt_frame, text="N/A", font=('Arial', 24, 'bold'), fg=TEXT_COLOR, bg=ENTRY_BG); self.lbl_vt_result.pack(pady=10, padx=20, expand=True)
        
        details_frame = tk.Frame(center_frame, bg=ENTRY_BG, bd=1, relief='solid'); details_frame.pack(fill='both', expand=True, pady=20)
        details_frame.grid_rowconfigure(1, weight=1); details_frame.grid_columnconfigure(0, weight=1)
        tk.Label(details_frame, text="Analysis Breakdown:", font=('Arial', 14, 'bold'), fg=PURPLE_ACCENT, bg=ENTRY_BG).grid(row=0, column=0, pady=10, padx=10, sticky='w')
        self.lbl_details = tk.Label(details_frame, text="Enter a URL and click Analyze.", wraplength=700, fg=SUBTEXT_COLOR, bg=ENTRY_BG, font=('Arial', 12), anchor='nw', justify='left'); self.lbl_details.grid(row=1, column=0, sticky='nsew', padx=10, pady=(0, 10))

    def process_queue(self):
        try:
            message = self.gui_queue.get_nowait()
            if message['type'] == 'url_result':
                self.update_ui_with_results(message)
                self.save_to_history(message)
            elif message['type'] == 'error':
                messagebox.showerror("Analysis Error", message['details'])
        except queue.Empty: pass
        self.after(100, self.process_queue)

    def check_url(self):
        url = self.entry_url.get().strip();
        if not url: messagebox.showwarning("Warning", "Please enter a URL."); return
        self.lbl_internal_result.config(text="Analyzing...", fg="#FFC107"); self.lbl_vt_result.config(text="Querying...", fg="#FFC107"); self.lbl_details.config(text="Analyzing Lexical, Host, and Content Features...")
        threading.Thread(target=self.perform_full_url_analysis, args=(url,), daemon=True).start()

    def check_cache(self, url):
        conn = self.controller.get_db_connection(); cursor = conn.cursor()
        one_day_ago = datetime.now() - timedelta(days=1)
        cursor.execute("SELECT verdict, vt_score FROM scan_history WHERE url = ? AND scan_date > ? ORDER BY scan_date DESC LIMIT 1", (url, one_day_ago))
        result = cursor.fetchone()
        conn.close()
        return result

    def perform_full_url_analysis(self, url):
        try:
            cached_result = self.check_cache(url)
            if cached_result:
                print(f"Cache hit for URL: {url}")
                verdict, vt_score = cached_result
                details_text = "- Result retrieved from recent scan history (cache)."
                self.gui_queue.put({'type': 'url_result', 'url': url, 'final_verdict': verdict, 'details': details_text, 'vt_result': vt_score})
                return

            print(f"Cache miss. Performing full analysis for URL: {url}")
            total_score = 0; all_reasons = []
            lexical_features = extract_lexical_features(url); input_df = pd.DataFrame([lexical_features]); input_df = input_df[self.model_features]
            ml_prob = self.model.predict_proba(input_df)[0][1]
            if ml_prob > 0.7: total_score += 2; all_reasons.append(f"- ML model flagged suspicious text patterns (Confidence: {ml_prob:.0%}).")
            host_results = analyze_host_features(url); total_score += host_results['score']; all_reasons.extend(host_results['reasons'])
            content_results = analyze_content_features(url); total_score += content_results['score']; all_reasons.extend(content_results['reasons'])
            vt_result = analyze_url_with_virustotal(url)
            if " / " in vt_result:
                positives = int(vt_result.split(" / ")[0])
                if positives >= 3: total_score += 5; all_reasons.append(f"- VirusTotal: Flagged by {positives} vendors.")
                elif positives > 0: total_score += 2; all_reasons.append(f"- VirusTotal: Flagged by {positives} vendor(s).")
            
            if total_score >= 5: final_verdict = "MALICIOUS"
            elif total_score >= 2: final_verdict = "POTENTIAL RISK"
            else: final_verdict = "SAFE"
            
            if not all_reasons: all_reasons.append("- No significant malicious indicators were found across multiple checks.")
            details_text = "\n".join(all_reasons)
            self.gui_queue.put({'type': 'url_result', 'url': url, 'final_verdict': final_verdict, 'details': details_text, 'vt_result': vt_result})
        except Exception as e: self.gui_queue.put({'type': 'error', 'details': f"A critical error occurred: {e}"})

    def update_ui_with_results(self, message):
        verdict, details, vt_result = message['final_verdict'], message['details'], message['vt_result']
        if verdict == "MALICIOUS": color = "#F44336"
        elif verdict == "POTENTIAL RISK": color = "#FFC107"
        else: color = "#4CAF50"
        self.lbl_internal_result.config(text=verdict, fg=color)
        vt_color = "white"
        if " / " in vt_result:
            positives = int(vt_result.split(" / ")[0])
            if positives == 0: vt_color = "#4CAF50"
            elif positives > 0: vt_color = "#FFC107"
            if positives >= 3: vt_color = "#F44336"
        self.lbl_vt_result.config(text=vt_result, fg=vt_color)
        self.lbl_details.config(text=details)

    def save_to_history(self, message):
        url, verdict, vt_score = message['url'], message['final_verdict'], message['vt_result']
        conn = self.controller.get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (self.controller.current_user_email,)); user_id_tuple = cursor.fetchone()
        if user_id_tuple:
            user_id = user_id_tuple[0]
            # Use INSERT OR REPLACE to avoid duplicate entries for the same URL by the same user, updating the latest scan
            cursor.execute("INSERT OR REPLACE INTO scan_history (id, user_id, url, verdict, vt_score, scan_date) VALUES ((SELECT id FROM scan_history WHERE url = ? AND user_id = ?), ?, ?, ?, ?, ?)", (url, user_id, user_id, url, verdict, vt_score, datetime.now()))
            conn.commit()
        conn.close()
    
    def on_show(self, data=None):
        if hasattr(self, 'controller') and hasattr(self.controller, 'current_user_email'):
            print(f"Welcome back, {self.controller.current_user_email}")

if __name__ == "__main__":
    setup_database()
    app = AppController()
    app.mainloop()