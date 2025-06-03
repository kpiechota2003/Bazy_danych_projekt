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

        form_frame = ttk.Frame(self.root)
        ttk.Label(form_frame, text="Welcome to Climbing App", font=("Helvetica", 16)).pack(pady=(10, 20))
        form_frame.pack(expand=True)

        row1 = ttk.Frame(form_frame)
        row1.pack(pady=5)
        ttk.Label(row1, text="Username").pack(side=tk.LEFT, padx=5)
        self.username_entry = ttk.Entry(row1)
        self.username_entry.pack(side=tk.LEFT)

        row2 = ttk.Frame(form_frame)
        row2.pack(pady=5)
        ttk.Label(row2, text="Password").pack(side=tk.LEFT, padx=5)
        self.password_entry = ttk.Entry(row2, show="*")
        self.password_entry.pack(side=tk.LEFT)

        btn_frame = ttk.Frame(form_frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Login", command=self.login).pack(pady=2, fill=tk.X)
        ttk.Button(btn_frame, text="Register", command=self.add_user_form).pack(pady=2, fill=tk.X)
        ttk.Button(btn_frame, text="Forgot Password", command=self.reset_password_form).pack(pady=2, fill=tk.X)



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
        ttk.Label(self.root, text="Username").pack(pady=2)
        username_entry = ttk.Entry(self.root)
        username_entry.pack(pady=2)

        ttk.Label(self.root, text="New Password").pack(pady=2)
        new_password_entry = ttk.Entry(self.root, show="*")
        new_password_entry.pack(pady=2)

        ttk.Label(self.root, text="Confirm New Password").pack(pady=2)
        confirm_new_password_entry = ttk.Entry(self.root, show="*")
        confirm_new_password_entry.pack(pady=2)

        ttk.Button(self.root,text="Reset Password",
                   command=lambda: self._handle_password_reset(username_entry.get(),new_password_entry.get(),confirm_new_password_entry.get())).pack(pady=5)


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

        ttk.Label(self.root, text="First Name").pack(pady=2)
        first_name_entry = ttk.Entry(self.root)
        first_name_entry.pack(pady=2)

        ttk.Label(self.root, text="Last Name").pack(pady=2)
        last_name_entry = ttk.Entry(self.root)
        last_name_entry.pack(pady=2)

        ttk.Label(self.root, text="Username").pack(pady=2)
        username_entry = ttk.Entry(self.root)
        username_entry.pack(pady=2)

        ttk.Label(self.root, text="Password").pack(pady=2)
        password_entry = ttk.Entry(self.root, show="*")
        password_entry.pack(pady=2)

        ttk.Label(self.root, text="Confirm Password").pack(pady=2)
        confirm_password_entry = ttk.Entry(self.root, show="*")
        confirm_password_entry.pack(pady=2)

        ttk.Button(self.root, text="Register", command=lambda: self.on_register(
            first_name_entry.get().strip(),
            last_name_entry.get().strip(),
            username_entry.get().strip(),
            password_entry.get(),
            confirm_password_entry.get()
        )).pack(pady=(5, 2))

        ttk.Button(self.root, text="Back to Login", command=self.setup_login).pack(pady=(0, 10))


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
        
    def delete_selected_route(self):
        selection = self.routes_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No route selected.")
            return

        selected = self.routes_listbox.get(selection[0])
        route_id = self.routes.get(selected)

        if not route_id:
            messagebox.showerror("Error", "Route not found.")
            return

        confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete this route?")
        if confirm:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("DELETE FROM routes WHERE route_id=?", (route_id,))
            c.execute("DELETE FROM reviews WHERE route_id=?", (route_id,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Route deleted.")
            self.load_routes()
            self.route_detail_label.config(text="Select a route to see details", image="")


    def setup_main_app(self):
        self.clear_root()

        self.left_frame = ttk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)

        filter_frame = ttk.Frame(self.left_frame)
        filter_frame.pack(padx=5, pady=5)

        self.grade_var = tk.StringVar()
        self.protection_var = tk.StringVar()
        self.sector_var = tk.StringVar()

        ttk.Label(filter_frame, text="Grade").grid(row=0, column=0, sticky="w", padx=2, pady=2)
        self.grade_entry = ttk.Entry(filter_frame, textvariable=self.grade_var)
        self.grade_entry.grid(row=0, column=1, padx=2, pady=2)

        ttk.Label(filter_frame, text="Protection").grid(row=1, column=0, sticky="w", padx=2, pady=2)
        self.protection_entry = ttk.Entry(filter_frame, textvariable=self.protection_var)
        self.protection_entry.grid(row=1, column=1, padx=2, pady=2)

        ttk.Label(filter_frame, text="Sector").grid(row=2, column=0, sticky="w", padx=2, pady=2)
        self.sector_entry = ttk.Entry(filter_frame, textvariable=self.sector_var)
        self.sector_entry.grid(row=2, column=1, padx=2, pady=2)

        ttk.Button(filter_frame, text="Filter", command=self.filter_routes).grid(row=3, column=0, columnspan=2, pady=5)

        self.routes_listbox = tk.Listbox(self.left_frame, width=40)
        self.routes_listbox.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.routes_listbox.bind("<<ListboxSelect>>", self.display_route_details)

        self.right_frame = ttk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.create_right_layout()
        self.load_routes()


    def create_right_layout(self):
        top_frame = ttk.Frame(self.right_frame)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        left_info = ttk.Frame(top_frame)
        left_info.pack(side=tk.LEFT, anchor='n', expand=True)

        right_buttons = ttk.Frame(top_frame)
        right_buttons.pack(side=tk.RIGHT, anchor='n')

        self.route_detail_label = ttk.Label(left_info, text="Select a route to see details", justify=tk.LEFT, wraplength=400)
        self.route_detail_label.pack()

        ttk.Button(right_buttons, text="Logout", command=self.setup_login).pack(pady=2, fill=tk.X)
        ttk.Button(right_buttons, text="Add Route", command=self.add_route_form).pack(pady=2, fill=tk.X)
        if self.user['is_admin']:
            ttk.Button(right_buttons, text="Delete Route", command=self.delete_selected_route).pack(pady=2, fill=tk.X)
            ttk.Button(right_buttons, text="Manage Users", command=self.admin_manage_users).pack(pady=2, fill=tk.X)



    def admin_manage_users(self):
        self.clear_root()

        ttk.Label(self.root, text="User Management", font=("Arial", 14)).pack(pady=5)

        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tree = ttk.Treeview(frame, columns=("ID", "Username", "Name", "Admin"), show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Username", text="Username")
        tree.heading("Name", text="Name")
        tree.heading("Admin", text="Admin")

        tree.pack(fill=tk.BOTH, expand=True)

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT user_id, username, first_name || ' ' || last_name, is_admin FROM users")
        users = c.fetchall()
        conn.close()

        for u in users:
            tree.insert("", tk.END, values=u)

        def delete_selected():
            selected = tree.selection()
            if not selected:
                messagebox.showerror("Error", "No user selected.")
                return

            user_data = tree.item(selected[0])["values"]
            user_id = user_data[0]
            username = user_data[1]
            is_admin = user_data[3]

            if user_id == self.user['id']:
                messagebox.showerror("Error", "You cannot delete yourself.")
                return

            if is_admin:
                messagebox.showerror("Error", "You cannot delete another admin.")
                return

            confirm = messagebox.askyesno("Confirm", f"Delete user '{username}'?")
            if confirm:
                conn = sqlite3.connect(DB_NAME)
                c = conn.cursor()
                c.execute("DELETE FROM users WHERE user_id=?", (user_id,))
                conn.commit()
                conn.close()
                messagebox.showinfo("Success", "User deleted.")
                self.admin_manage_users()  # reload

        ttk.Button(self.root, text="Delete Selected User", command=delete_selected).pack(pady=5)
        ttk.Button(self.root, text="Back", command=self.setup_main_app).pack(pady=2)


    def filter_routes(self):
        grade = self.grade_var.get()
        protection = self.protection_var.get()
        sector = self.sector_var.get()

        query = """
        SELECT routes.route_id, routes.name, sectors.name FROM routes 
        JOIN sectors ON routes.sector_id = sectors.sector_id
        WHERE 1=1
        """
        params = []
        if grade:
            query += " AND routes.grade LIKE ?"
            params.append(f"%{grade}%")
        if protection:
            query += " AND routes.protection_type LIKE ?"
            params.append(f"%{protection}%")
        if sector:
            query += " AND sectors.name LIKE ?"
            params.append(f"%{sector}%")

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()

        self.routes_listbox.delete(0, tk.END)
        self.routes = {}
        for route_id, route_name, sector_name in rows:
            display_name = f"{route_name} (Sector: {sector_name})"
            self.routes_listbox.insert(tk.END, display_name)
            self.routes[display_name] = route_id

    def load_routes(self):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            SELECT routes.route_id, routes.name, sectors.name FROM routes
            JOIN sectors ON routes.sector_id = sectors.sector_id
        """)
        rows = c.fetchall()
        conn.close()

        self.routes_listbox.delete(0, tk.END)
        self.routes = {}
        for route_id, route_name, sector_name in rows:
            display_name = f"{route_name} (Sector: {sector_name})"
            self.routes_listbox.insert(tk.END, display_name)
            self.routes[display_name] = route_id

    def display_route_details(self, event):
        if not self.routes_listbox.curselection():
            return
        selected = self.routes_listbox.get(self.routes_listbox.curselection())
        route_id = self.routes.get(selected)
        if not route_id:
            return

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            SELECT name, protection_type, height, author, grade, gps_coordinates, photo FROM routes WHERE route_id=?
        """, (route_id,))
        route = c.fetchone()

        c.execute("""
            SELECT name, location_gps FROM sectors
            WHERE sector_id = (SELECT sector_id FROM routes WHERE route_id=?)
        """, (route_id,))
        sector = c.fetchone()

        c.execute("""
            SELECT review_text FROM reviews WHERE route_id=?
        """, (route_id,))
        reviews = c.fetchall()
        conn.close()

        if not route:
            return

        name, protection, height, author, grade, gps, photo = route
        sector_name, sector_gps = sector if sector else ("Unknown", "Unknown")
        review_texts = "\n\n".join(r[0] for r in reviews) if reviews else "No reviews."

        # --- Czyszczenie panelu ---
        for widget in self.right_frame.winfo_children():
            widget.destroy()

        # --- Układ ogólny ---
        top_frame = ttk.Frame(self.right_frame)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        left_info = ttk.Frame(top_frame)
        left_info.pack(side=tk.LEFT, anchor='n', expand=True)

        right_buttons = ttk.Frame(top_frame)
        right_buttons.pack(side=tk.RIGHT, anchor='n')

        photo_frame = ttk.Frame(self.right_frame)
        photo_frame.pack(pady=10)

        comments_frame = ttk.Frame(self.right_frame)
        comments_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # --- Dane o ścieżce (lewa góra) ---
        details = (
            f"Route Name: {name}\nProtection: {protection}\nHeight: {height} m\nAuthor: {author}"
            f"\nGrade: {grade}\nGPS: {gps}\n\nSector: {sector_name}\nSector GPS: {sector_gps}"
        )
        ttk.Label(left_info, text=details, justify=tk.LEFT, anchor='w').pack()

        # --- Przyciski (prawa góra) ---
        ttk.Button(right_buttons, text="Logout", command=self.setup_login).pack(pady=2, fill=tk.X)
        ttk.Button(right_buttons, text="Add Route", command=self.add_route_form).pack(pady=2, fill=tk.X)
        if self.user['is_admin']:
            ttk.Button(right_buttons, text="Delete Route", command=self.delete_selected_route).pack(pady=2, fill=tk.X)
            ttk.Button(right_buttons, text="Manage Users", command=self.admin_manage_users).pack(pady=2, fill=tk.X)

        # --- Zdjęcie (środek) ---
        if photo:
            image = Image.open(io.BytesIO(photo))
            image = image.resize((300, 225), Image.ANTIALIAS)  
            self.photo_img = ImageTk.PhotoImage(image)
            ttk.Label(photo_frame, image=self.photo_img).pack()
        else:
            ttk.Label(photo_frame, text="No photo").pack()

        # --- Dodawanie komentarza (na górze sekcji) ---
        ttk.Label(comments_frame, text="Add Comment:").pack(anchor='w', pady=(5, 0))
        self.comment_entry = ttk.Entry(comments_frame)
        self.comment_entry.pack(fill=tk.X, pady=2)
        ttk.Button(comments_frame, text="Add Comment", command=self.add_comment).pack()

        # --- Lista komentarzy (na dole sekcji) ---
        ttk.Label(comments_frame, text="Reviews:", font=("Arial", 12, "bold")).pack(anchor='w', pady=(10, 0))
        ttk.Label(comments_frame, text=review_texts, justify=tk.LEFT, anchor='w', wraplength=700).pack(fill=tk.X)

        self.current_route_id = route_id





    def add_comment(self):
        route_id = getattr(self, 'current_route_id', None)
        if not route_id:
            messagebox.showerror("Error", "No route selected.")
            return

        comment_text = self.comment_entry.get()
        if not comment_text.strip():
            messagebox.showerror("Error", "Comment cannot be empty!")
            return

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO reviews (user_id, route_id, review_text) VALUES (?, ?, ?)",
                (self.user['id'], route_id, comment_text))
        conn.commit()
        conn.close()

        self.comment_entry.delete(0, tk.END)
        messagebox.showinfo("Success", "Comment added successfully!")

        # Refresh route display
        self.display_route_details(None)


    def add_sector_form(self):
        self.clear_root()
        ttk.Label(self.root, text="Sector Name").pack(pady=2)
        sector_name_entry = ttk.Entry(self.root)
        sector_name_entry.pack(pady=2)

        ttk.Label(self.root, text="GPS Location").pack(pady=2)
        gps_entry = ttk.Entry(self.root)
        gps_entry.pack(pady=2)

        def upload_map_photo():
            filename = filedialog.askopenfilename(title="Select Map Photo",
                                                  filetypes=[("Image files", "*.jpg *.png *.jpeg")])
            if filename:
                with open(filename, "rb") as f:
                    self.map_photo_blob = f.read()
                map_photo_label.config(text=os.path.basename(filename))

        map_photo_label = ttk.Label(self.root, text="No photo selected")
        map_photo_label.pack(pady=2)

        ttk.Button(self.root, text="Upload Map Photo", command=upload_map_photo).pack(pady=2)

        ttk.Button(self.root, text="Save Sector", command=lambda: self.save_sector(sector_name_entry.get(), gps_entry.get())).pack(pady=5)
        ttk.Button(self.root, text="Back", command=self.setup_main_app).pack(pady=2)

        self.map_photo_blob = None

    def save_sector(self, name, gps):
        if not name or not gps:
            messagebox.showerror("Error", "Name and GPS location are required.")
            return

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO sectors (name, location_gps, map_photo) VALUES (?, ?, ?)", (name, gps, self.map_photo_blob))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Sector added successfully.")
        self.setup_main_app()

    def add_route_form(self):
        self.clear_root()

        ttk.Label(self.root, text="Route Name").pack(pady=2)
        route_name_entry = ttk.Entry(self.root)
        route_name_entry.pack(pady=2)

        ttk.Label(self.root, text="Select Sector").pack(pady=2)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT sector_id, name FROM sectors")
        sectors = c.fetchall()
        conn.close()

        sector_names = [s[1] for s in sectors]
        sector_var = tk.StringVar()
        sector_combo = ttk.Combobox(self.root, values=sector_names, state="readonly", textvariable=sector_var)
        sector_combo.pack(pady=2)

        ttk.Label(self.root, text="Protection Type").pack(pady=2)
        protection_entry = ttk.Entry(self.root)
        protection_entry.pack(pady=2)

        ttk.Label(self.root, text="Height (m)").pack(pady=2)
        height_entry = ttk.Entry(self.root)
        height_entry.pack(pady=2)

        ttk.Label(self.root, text="Author").pack(pady=2)
        author_entry = ttk.Entry(self.root)
        author_entry.pack(pady=2)

        ttk.Label(self.root, text="Grade").pack(pady=2)
        grade_entry = ttk.Entry(self.root)
        grade_entry.pack(pady=2)

        ttk.Label(self.root, text="GPS Coordinates").pack(pady=2)
        gps_entry = ttk.Entry(self.root)
        gps_entry.pack(pady=2)

        photo_label = ttk.Label(self.root, text="No photo selected")
        photo_label.pack(pady=2)

        def upload_photo():
            filename = filedialog.askopenfilename(title="Select Route Photo",
                                                  filetypes=[("Image files", "*.jpg *.png *.jpeg")])
            if filename:
                with open(filename, "rb") as f:
                    self.route_photo_blob = f.read()
                photo_label.config(text=os.path.basename(filename))

        ttk.Button(self.root, text="Upload Photo", command=upload_photo).pack(pady=2)

        ttk.Button(self.root, text="Save Route", command=lambda: self.save_route(
            route_name_entry.get(),
            sector_var.get(),
            protection_entry.get(),
            height_entry.get(),
            author_entry.get(),
            grade_entry.get(),
            gps_entry.get()
        )).pack(pady=5)

        ttk.Button(self.root, text="Back", command=self.setup_main_app).pack(pady=2)

        self.route_photo_blob = None

    def save_route(self, name, sector_name, protection, height, author, grade, gps):
        if not all([name, sector_name, protection, height, author, grade, gps]):
            messagebox.showerror("Error", "All fields must be filled.")
            return
        try:
            height = int(height)
        except ValueError:
            messagebox.showerror("Error", "Height must be an integer.")
            return

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT sector_id FROM sectors WHERE name=?", (sector_name,))
        sector_id = c.fetchone()
        if not sector_id:
            messagebox.showerror("Error", "Selected sector not found.")
            return
        sector_id = sector_id[0]

        c.execute("""
            INSERT INTO routes (name, sector_id, protection_type, height, author, grade, gps_coordinates, photo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, sector_id, protection, height, author, grade, gps, self.route_photo_blob))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Route added successfully.")
        self.setup_main_app()

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    root.title("Climbing App")
    root.geometry("800x600")
    app = ClimbingApp(root)
    #root.geometry("400x300")
    root.mainloop()