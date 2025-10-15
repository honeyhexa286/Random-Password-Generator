import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

class AdvancedPasswordGenerator:
    def __init__(self, master):
        self.master = master
        master.title("✨ Password Generator Pro ✨")
        master.geometry("450x500") # Slightly larger window
        master.resizable(False, False)

        # --- Apply a modern theme ---
        style = ttk.Style()
        style.theme_use('clam') # 'clam' is often a good base, or 'alt', 'default'
        
        # Custom styles
        style.configure('TFrame', background='#e8f0f7') # Light blue background
        style.configure('TLabel', background='#e8f0f7', font=('Segoe UI', 10))
        style.configure('TCheckbutton', background='#e8f0f7', font=('Segoe UI', 10))
        style.configure('TScale', background='#e8f0f7')
        
        # Style for the Entry widget
        style.configure('TEntry', fieldbackground='#ffffff', borderwidth=2, relief='flat', font=('Courier New', 12))
        style.map('TEntry', 
                  fieldbackground=[('readonly', '#f0f0f0')],
                  selectbackground=[('!disabled', '#cce0ff')])

        # Specific style for the Generate Button
        style.configure('Generate.TButton', 
                        font=('Segoe UI', 11, 'bold'), 
                        foreground='white', 
                        background='#28a745', # A nice green color
                        padding=10, 
                        relief='flat', 
                        borderwidth=0)
        style.map('Generate.TButton', 
                  background=[('active', '#218838')]) # Darker green on hover

        # Specific style for other buttons
        style.configure('TButton', 
                        font=('Segoe UI', 11), 
                        foreground='#333333', 
                        background='#f0f0f0', 
                        padding=10, 
                        relief='flat', 
                        borderwidth=0)
        style.map('TButton', 
                  background=[('active', '#e0e0e0')]) # Lighter grey on hover


        # --- Character Sets ---
        self.lowercase_chars = string.ascii_lowercase
        self.uppercase_chars = string.ascii_uppercase
        self.digit_chars = string.digits
        self.symbol_chars = string.punctuation

        # --- Variables ---
        self.length_var = tk.IntVar(value=12)
        self.include_lower = tk.BooleanVar(value=True)
        self.include_upper = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        self.password_var = tk.StringVar(value="Click 'Generate' to start!")

        # --- GUI Setup ---
        self.create_widgets()

    def create_widgets(self):
        # Frame for all widgets with some padding
        main_frame = ttk.Frame(self.master, padding="25 25 25 25")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Title/Header
        header_label = ttk.Label(main_frame, text="Secure Password Generator", 
                                 font=('Segoe UI', 16, 'bold'), foreground='#333333')
        header_label.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        
        # 2. Password Display
        password_label = ttk.Label(main_frame, text="Your New Password:")
        password_label.grid(row=1, column=0, sticky="w", pady=(0, 5))

        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                        width=40, state='readonly', justify='center', 
                                        style='TEntry') # Apply custom entry style
        self.password_entry.grid(row=2, column=0, columnspan=2, pady=(0, 20), sticky="ew")

        # 3. Length Slider
        length_label_text = ttk.Label(main_frame, text="Password Length:")
        length_label_text.grid(row=3, column=0, sticky="w", pady=(10, 5))

        self.length_scale = ttk.Scale(
            main_frame,
            from_=4,
            to=32,
            orient=tk.HORIZONTAL,
            variable=self.length_var,
            command=self.update_length_label,
            length=250 # Give the scale a fixed length
        )
        self.length_scale.grid(row=4, column=0, sticky="ew")

        self.length_display = ttk.Label(main_frame, text=str(self.length_var.get()), 
                                        font=('Segoe UI', 10, 'bold'), foreground='#555555')
        self.length_display.grid(row=4, column=1, sticky="w", padx=(10,0))
        
        # 4. Complexity Options
        complexity_label = ttk.Label(main_frame, text="Include Characters:", font=('Segoe UI', 11, 'bold'))
        complexity_label.grid(row=5, column=0, sticky="w", pady=(15, 5))

        check_frame = ttk.Frame(main_frame)
        check_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=5)
        
        # Use grid for checkbuttons for better alignment
        ttk.Checkbutton(check_frame, text="Lowercase (a-z)", variable=self.include_lower).grid(row=0, column=0, sticky="w", pady=2)
        ttk.Checkbutton(check_frame, text="Uppercase (A-Z)", variable=self.include_upper).grid(row=1, column=0, sticky="w", pady=2)
        ttk.Checkbutton(check_frame, text="Digits (0-9)", variable=self.include_digits).grid(row=0, column=1, sticky="w", pady=2, padx=(20,0))
        ttk.Checkbutton(check_frame, text="Symbols (!@#$)", variable=self.include_symbols).grid(row=1, column=1, sticky="w", pady=2, padx=(20,0))

        # 5. Action Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=(30, 0), sticky="ew")
        
        generate_button = ttk.Button(button_frame, text="Generate Password", 
                                     command=self.generate_password, 
                                     style='Generate.TButton') # Apply specific style
        generate_button.pack(side=tk.LEFT, padx=(0, 10), fill="x", expand=True)

        copy_button = ttk.Button(button_frame, text="Copy to Clipboard", 
                                 command=self.copy_to_clipboard, 
                                 style='TButton') # Use default TButton style
        copy_button.pack(side=tk.LEFT, fill="x", expand=True)

    def update_length_label(self, event):
        """Updates the length display label when the slider is moved."""
        self.length_display.config(text=str(self.length_var.get()))

    def generate_password(self):
        """Generates a password based on selected criteria."""
        length = self.length_var.get()
        
        char_pool = ""
        required_chars = []

        if self.include_lower.get():
            char_pool += self.lowercase_chars
            required_chars.append(random.choice(self.lowercase_chars))
        if self.include_upper.get():
            char_pool += self.uppercase_chars
            required_chars.append(random.choice(self.uppercase_chars))
        if self.include_digits.get():
            char_pool += self.digit_chars
            required_chars.append(random.choice(self.digit_chars))
        if self.include_symbols.get():
            char_pool += self.symbol_chars
            required_chars.append(random.choice(self.symbol_chars))

        if not char_pool:
            messagebox.showerror("Error", "Please select at least one character type.")
            self.password_var.set("")
            return
        
        if len(required_chars) > length:
            messagebox.showerror("Error", f"Password length ({length}) must be at least the number of selected character types ({len(required_chars)}).")
            self.password_var.set("")
            return

        remaining_length = length - len(required_chars)
        rest_of_password = [random.choice(char_pool) for _ in range(remaining_length)]
        
        password_list = required_chars + rest_of_password
        random.shuffle(password_list)
        
        new_password = "".join(password_list)
        self.password_var.set(new_password)
        
    def copy_to_clipboard(self):
        """Copies the displayed password to the system clipboard."""
        password = self.password_var.get()
        if password and password != "Click 'Generate' to start!":
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password generated yet or it's the initial message.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedPasswordGenerator(root)
    root.mainloop()