import sqlite3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import io
import os

DB_NAME = "climbing_app.db"

# === DATABASE SETUP ===
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute(""" 
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER
        );
    """)

    c.execute(""" 
        CREATE TABLE IF NOT EXISTS sectors (
            sector_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            location_gps TEXT,
            map_photo BLOB
        );
    """)

    c.execute(""" 
        CREATE TABLE IF NOT EXISTS routes (
            route_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            sector_id INTEGER,
            protection_type TEXT,
            height INTEGER,
            author TEXT,
            grade TEXT,
            gps_coordinates TEXT,
            photo BLOB,
            FOREIGN KEY(sector_id) REFERENCES sectors(sector_id)
        );
    """)

    c.execute(""" 
        CREATE TABLE IF NOT EXISTS reviews (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            route_id INTEGER,
            review_text TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id),
            FOREIGN KEY(route_id) REFERENCES routes(route_id)
        );
    """)

    # Add an admin user if none exists
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (first_name, last_name, username, password, is_admin) VALUES (?, ?, ?, ?, ?)",
                  ("Admin", "User", "admin", "admin", 1))

    conn.commit()
    conn.close()

class ClimbingApp:
    def __init__(self, root):
        self.root = root
        self.user = None
        self.setup_login()

    def setup_login(self):
        self.clear_root()
        tk.Label(self.root, text="Username").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()
        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()
        tk.Button(self.root, text="Login", command=self.login).pack()
        tk.Button(self.root, text="Register", command=self.add_user_form).pack()  # Button to open add user form
        tk.Button(self.root, text="Forgot Password", command=self.reset_password_form).pack()  # Added reset password button

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT user_id, first_name, is_admin FROM users WHERE username=? AND password=?", (username, password))
        result = c.fetchone()
        conn.close()

        if result:
            self.user = {'id': result[0], 'name': result[1], 'is_admin': result[2]}
            self.setup_main_app()
        else:
            messagebox.showerror("Login failed", "Invalid credentials.")

    def reset_password_form(self):
        self.clear_root()
        tk.Label(self.root, text="Username").pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()

        tk.Label(self.root, text="New Password").pack()
        new_password_entry = tk.Entry(self.root, show="*")
        new_password_entry.pack()

        tk.Label(self.root, text="Confirm New Password").pack()
        confirm_new_password_entry = tk.Entry(self.root, show="*")
        confirm_new_password_entry.pack()

        tk.Button(self.root,text="Reset Password",command=lambda: self._handle_password_reset(username_entry.get(),new_password_entry.get(),confirm_new_password_entry.get())).pack()


    def _handle_password_reset(self, username, new_password, confirm_password):
        if self.reset_password(username, new_password, confirm_password):
            self.setup_login()

    def reset_password(self, username, new_password, confirm_password):
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return False

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT user_id FROM users WHERE username=?", (username,))
        result = c.fetchone()

        if result:
            c.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Password reset successfully!")
            return True
        else:
            messagebox.showerror("Error", "Username not found.")
            return False


    def on_register(self, first_name, last_name, username, password, confirm_password):
        success = self.add_user_to_db(first_name, last_name, username, password, confirm_password)
        if success:
            self.setup_login()

    def add_user_form(self):
        self.clear_root()

        tk.Label(self.root, text="First Name").pack()
        first_name_entry = tk.Entry(self.root)
        first_name_entry.pack()

        tk.Label(self.root, text="Last Name").pack()
        last_name_entry = tk.Entry(self.root)
        last_name_entry.pack()

        tk.Label(self.root, text="Username").pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()

        tk.Label(self.root, text="Password").pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()

        tk.Label(self.root, text="Confirm Password").pack()
        confirm_password_entry = tk.Entry(self.root, show="*")
        confirm_password_entry.pack()

        tk.Button(self.root, text="Register", command=lambda: self.on_register(
            first_name_entry.get().strip(),
            last_name_entry.get().strip(),
            username_entry.get().strip(),
            password_entry.get(),
            confirm_password_entry.get()
        )).pack(pady=(5, 2))

        tk.Button(self.root, text="Back to Login", command=self.setup_login).pack(pady=(0, 10))




    
    def add_user_to_db(self, first_name, last_name, username, password, confirm_password):
        if not all([first_name, last_name, username, password, confirm_password]):
            messagebox.showerror("Błąd", "Wszystkie pola muszą być wypełnione.")
            return False

        if not any(char.isalpha() for char in first_name):
            messagebox.showerror("Błąd", "Imię musi zawierać litery.")
            return False
        if not any(char.isalpha() for char in last_name):
            messagebox.showerror("Błąd", "Nazwisko musi zawierać litery.")
            return False
        if not any(char.isalpha() for char in username):
            messagebox.showerror("Błąd", "Login musi zawierać litery.")
            return False

        if len(password) < 8:
            messagebox.showerror("Błąd", "Hasło musi mieć co najmniej 8 znaków.")
            return False
        if not any(char.isalpha() for char in password):
            messagebox.showerror("Błąd", "Hasło musi zawierać przynajmniej jedną literę.")
            return False
        if not any(char.isdigit() for char in password):
            messagebox.showerror("Błąd", "Hasło musi zawierać przynajmniej jedną cyfrę.")
            return False

        if password != confirm_password:
            messagebox.showerror("Błąd", "Hasła nie są zgodne.")
            return False

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (first_name, last_name, username, password, is_admin) VALUES (?, ?, ?, ?, ?)",
                    (first_name, last_name, username, password, 0))
            conn.commit()
            conn.close()
            messagebox.showinfo("Sukces", "Użytkownik został zarejestrowany.")
            return True
        except sqlite3.IntegrityError:
            messagebox.showerror("Błąd", "Taki login już istnieje.")
            return False

        

    def setup_main_app(self):
        self.clear_root()

        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)

        filter_frame = tk.Frame(self.left_frame)
        filter_frame.pack()

        self.grade_var = tk.StringVar()
        self.protection_var = tk.StringVar()
        self.sector_var = tk.StringVar()

        tk.Label(filter_frame, text="Grade").grid(row=0, column=0)
        self.grade_entry = tk.Entry(filter_frame, textvariable=self.grade_var)
        self.grade_entry.grid(row=0, column=1)

        tk.Label(filter_frame, text="Protection").grid(row=1, column=0)
        self.protection_entry = tk.Entry(filter_frame, textvariable=self.protection_var)
        self.protection_entry.grid(row=1, column=1)

        tk.Label(filter_frame, text="Sector").grid(row=2, column=0)
        self.sector_entry = tk.Entry(filter_frame, textvariable=self.sector_var)
        self.sector_entry.grid(row=2, column=1)

        tk.Button(filter_frame, text="Filter", command=self.load_routes).grid(row=3, columnspan=2)

        self.route_listbox = tk.Listbox(self.left_frame, width=40)
        self.route_listbox.pack(fill=tk.Y, expand=True)
        self.route_listbox.bind('<<ListboxSelect>>', self.display_route_details)

        if self.user['is_admin']:
            tk.Button(self.left_frame, text="Add Route", command=self.add_route_form).pack()

        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.detail_text = tk.Text(self.right_frame, height=20)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        self.photo_label = tk.Label(self.right_frame)
        self.photo_label.pack()

        # Initially, do not show the comment entry and button
        self.comment_entry = tk.Entry(self.right_frame)
        self.add_comment_button = tk.Button(self.right_frame, text="Add Comment", command=self.add_comment)

        self.load_routes()

    def add_comment(self):
        route_id = self.get_selected_route_id()  # Użycie metody get_selected_route_id
        if not route_id:
            messagebox.showerror("Error", "No route selected.")
            return

        comment_text = self.comment_entry.get()
        if not comment_text:
            messagebox.showerror("Error", "Comment cannot be empty!")
            return

        # Save the comment to the database
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO reviews (user_id, route_id, review_text) VALUES (?, ?, ?)",
                  (self.user['id'], route_id, comment_text))
        conn.commit()
        conn.close()

        # Display the new comment in the detail_text, above the current content
        current_text = self.detail_text.get(1.0, tk.END)
        new_comment = f"{self.user['name']}: {comment_text}\n\n" + current_text
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, new_comment)

        # Clear the comment entry field
        self.comment_entry.delete(0, tk.END)

        # Optionally, show a success message
        messagebox.showinfo("Success", "Comment added successfully!")

    def get_selected_route_id(self):
        selection = self.route_listbox.curselection()
        if not selection:
            return None
        return int(self.route_listbox.get(selection[0]).split(":")[0])

    def load_routes(self):
        self.route_listbox.delete(0, tk.END)
        query = "SELECT route_id, name FROM routes WHERE 1=1"
        params = []

        if self.grade_var.get():
            query += " AND grade LIKE ?"
            params.append(f"%{self.grade_var.get()}%")
        if self.protection_var.get():
            query += " AND protection_type LIKE ?"
            params.append(f"%{self.protection_var.get()}%")
        if self.sector_var.get():
            query += " AND sector_id IN (SELECT sector_id FROM sectors WHERE name LIKE ?)"
            params.append(f"%{self.sector_var.get()}%")

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute(query, params)
        routes = c.fetchall()
        conn.close()

        for route in routes:
            self.route_listbox.insert(tk.END, f"{route[0]}: {route[1]}")

    def display_route_details(self, event):
        selection = self.route_listbox.curselection()
        if not selection:
            return

        route_id = int(self.route_listbox.get(selection[0]).split(":")[0])

        self.load_route_details(route_id)

        # Show comment section above the image
        self.comment_entry.pack(before=self.photo_label)
        self.add_comment_button.pack(before=self.photo_label)

    def load_route_details(self, route_id):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute(""" 
               SELECT name, protection_type, height, author, grade, gps_coordinates, photo 
               FROM routes 
               WHERE route_id=? 
           """, (route_id,))
        route = c.fetchone()

        c.execute("""
               SELECT u.first_name, u.last_name, r.review_text 
               FROM reviews r
               JOIN users u ON r.user_id = u.user_id
               WHERE r.route_id=? 
           """, (route_id,))
        reviews = c.fetchall()
        conn.close()

        if route:
            details = (
                f"Name: {route[0]}\n"
                f"Protection: {route[1]}\n"
                f"Height: {route[2]} m\n"
                f"Author: {route[3]}\n"
                f"Grade: {route[4]}\n"
                f"GPS: {route[5]}\n\n"
                f"Reviews:\n"
            )
            for reviewer in reviews:
                details += f"{reviewer[0]} {reviewer[1]}: {reviewer[2]}\n"

            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(tk.END, details)

            if route[6]:  # photo
                image = Image.open(io.BytesIO(route[6]))
                image.thumbnail((300, 300))
                self.tk_image = ImageTk.PhotoImage(image)
                self.photo_label.config(image=self.tk_image)

    def save_route(self, name, sector, protection, height, author, grade, gps, photo_path):
        with open(photo_path, 'rb') as f:
            photo = f.read()

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute("SELECT sector_id FROM sectors WHERE name=?", (sector,))
        result = c.fetchone()
        if result:
            sector_id = result[0]
        else:
            c.execute("INSERT INTO sectors (name, location_gps) VALUES (?, ?)", (sector, ""))
            sector_id = c.lastrowid

        c.execute("""INSERT INTO routes 
            (name, sector_id, protection_type, height, author, grade, gps_coordinates, photo) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, sector_id, protection, height, author, grade, gps, photo))
        conn.commit()
        conn.close()

        messagebox.showinfo("Sukces", "Dodano nową drogę wspinaczkową.")
        self.load_routes()

    def on_save_route(self, name, sector, protection, height_str, author, grade, gps, photo_path, top_window):
        # Walidacja pól
        if not all([name, sector, protection, height_str, author, grade, gps, photo_path]):
            messagebox.showerror("Błąd", "Wszystkie pola muszą być wypełnione.")
            return

        try:
            height = int(height_str)
        except ValueError:
            messagebox.showerror("Błąd", "Wysokość musi być liczbą całkowitą.")
            return

        if not os.path.exists(photo_path):
            messagebox.showerror("Błąd", "Podana ścieżka zdjęcia nie istnieje.")
            return

        self.save_route(name, sector, protection, height, author, grade, gps, photo_path)
        top_window.destroy()
    
    def add_route_form(self):
        top = tk.Toplevel(self.root)
        top.title("Add New Route")

        labels = ["Name", "Sector", "Protection", "Height", "Author", "Grade", "GPS"]
        entries = []
        for i, label in enumerate(labels):
            tk.Label(top, text=label).grid(row=i, column=0)
            entry = tk.Entry(top)
            entry.grid(row=i, column=1)
            entries.append(entry)

        name_entry, sector_entry, protection_entry, height_entry, author_entry, grade_entry, gps_entry = entries
        photo_var = tk.StringVar()

        tk.Button(top, text="Choose Photo", command=lambda: photo_var.set(filedialog.askopenfilename())).grid(row=7, column=0)
        tk.Entry(top, textvariable=photo_var).grid(row=7, column=1)

        tk.Button(top, text="Save Route", command=lambda: self.on_save_route(name_entry.get().strip(),sector_entry.get().strip(),protection_entry.get().strip(),height_entry.get().strip(),author_entry.get().strip(),grade_entry.get().strip(),gps_entry.get().strip(),photo_var.get().strip(),top)).grid(row=8, columnspan=2)




    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    if not os.path.exists(DB_NAME):
        init_db()
    root = tk.Tk()
    root.title("Climbing Routes App")
    root.geometry("1000x600")  # Przywrócenie ustawionego rozmiaru okna
    app = ClimbingApp(root)
    root.mainloop()
