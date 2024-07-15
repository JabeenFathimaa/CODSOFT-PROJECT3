import tkinter as tk
from tkinter import messagebox
import random
import string

# Function to generate the password
def generate_password():
    try:
        length = int(length_entry.get())
        include_upper = upper_var.get()
        include_lower = lower_var.get()
        include_numbers = number_var.get()
        include_special = special_var.get()
        include_hex = hex_var.get()

        if length <= 0:
            messagebox.showerror("Invalid Input", "Length should be a positive integer.")
            return

        characters = ""
        if include_lower:
            characters += string.ascii_lowercase
        if include_upper:
            characters += string.ascii_uppercase
        if include_numbers:
            characters += string.digits
        if include_special:
            characters += string.punctuation
        if include_hex:
            characters += "0123456789abcdef"

        if not characters:
            messagebox.showerror("Invalid Input", "No character set selected.")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        password_entry.config(state=tk.NORMAL)
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
        password_entry.config(state=tk.DISABLED)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number for length.")

# Function to copy the password to the clipboard
def copy_password():
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    messagebox.showinfo("Password Copied", "Password copied to clipboard!")

# Create the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("400x400")
root.configure(bg="#E6E6FA")  # Set background color to Lavender

# Length label and entry
length_label = tk.Label(root, text="Password Length:", bg="#E6E6FA", fg="#000000")
length_label.pack(pady=5)
length_entry = tk.Entry(root, fg="#000000")
length_entry.pack(pady=5)

# Frame to contain checkbuttons
checkbutton_frame = tk.Frame(root, bg="#E6E6FA")
checkbutton_frame.pack(pady=10)

# Checkbox options for complexity
upper_var = tk.BooleanVar()
lower_var = tk.BooleanVar()
number_var = tk.BooleanVar()
special_var = tk.BooleanVar()
hex_var = tk.BooleanVar()

upper_check = tk.Checkbutton(checkbutton_frame, text="Include Uppercase Letters", variable=upper_var, bg="#E6E6FA", fg="#000000")
upper_check.pack(side=tk.TOP, anchor=tk.CENTER, padx=10, pady=5)
lower_check = tk.Checkbutton(checkbutton_frame, text="Include Lowercase Letters", variable=lower_var, bg="#E6E6FA", fg="#000000")
lower_check.pack(side=tk.TOP, anchor=tk.CENTER, padx=10, pady=5)
number_check = tk.Checkbutton(checkbutton_frame, text="Include Numbers", variable=number_var, bg="#E6E6FA", fg="#000000")
number_check.pack(side=tk.TOP, anchor=tk.CENTER, padx=10, pady=5)
special_check = tk.Checkbutton(checkbutton_frame, text="Include Special Characters", variable=special_var, bg="#E6E6FA", fg="#000000")
special_check.pack(side=tk.TOP, anchor=tk.CENTER, padx=10, pady=5)
hex_check = tk.Checkbutton(checkbutton_frame, text="Include Hexadecimal Characters", variable=hex_var, bg="#E6E6FA", fg="#000000")
hex_check.pack(side=tk.TOP, anchor=tk.CENTER, padx=10, pady=5)

# Generate button
generate_button = tk.Button(root, text="Generate Password", command=generate_password, fg="#000000")
generate_button.pack(pady=10)

# Password display entry
password_entry = tk.Entry(root, width=30, state=tk.DISABLED, fg="#1a1a1a")
password_entry.pack(pady=5)

# Copy to clipboard button
copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_password, fg="#000000")
copy_button.pack(pady=10)

# Start the GUI event loop
root.mainloop()


