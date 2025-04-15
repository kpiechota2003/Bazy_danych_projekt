
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
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sectors (
            sector_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            location_gps TEXT,
            map_photo BLOB
        )
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
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            route_id INTEGER,
            review_text TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id),
            FOREIGN KEY(route_id) REFERENCES routes(route_id)
        )
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

        self.load_routes()

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


    def add_route_form(self):
        def save_route():
            name = name_entry.get()
            sector = sector_entry.get()
            protection = protection_entry.get()
            height = int(height_entry.get())
            author = author_entry.get()
            grade = grade_entry.get()
            gps = gps_entry.get()
            photo_path = photo_var.get()

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

            c.execute("INSERT INTO routes (name, sector_id, protection_type, height, author, grade, gps_coordinates, photo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (name, sector_id, protection, height, author, grade, gps, photo))
            conn.commit()
            conn.close()

            top.destroy()
            self.load_routes()

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
        tk.Button(top, text="Save Route", command=save_route).grid(row=8, columnspan=2)

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    root.title("Climbing Routes App")
    root.geometry("1000x600")
    app = ClimbingApp(root)
    root.mainloop()
