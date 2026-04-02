import tkinter as tk
from tkinter import messagebox
from password_cracker import PasswordCracker
from rainbow_table import RainbowTable

def start_cracking():
    hash_to_crack = hash_entry.get().strip()
    hash_type = hash_type_var.get().strip()
    wordlist_path = wordlist_entry.get().strip() or "mini.txt"
    use_rainbow = rainbow_var.get()
    
    try:
        min_len = int(min_len_entry.get().strip())
        max_len = int(max_len_entry.get().strip())
    except ValueError:
        messagebox.showerror("Input Error", "Min and Max length must be integers.")
        return

    if use_rainbow:
        rainbow = RainbowTable(hash_type=hash_type, min_len=min_len, max_len=max_len)
        rainbow.generate(wordlist_path)

    cracker = PasswordCracker(
        hash_to_crack=hash_to_crack,
        hash_type=hash_type,
        wordlist_path=wordlist_path,
        use_rainbow=use_rainbow
    )

    cracker.start()

    result = cracker.result
    if result:
        messagebox.showinfo("Result", f"Password found: {result}")
    else:
        messagebox.showwarning("Result", "Password not found.")

# --- GUI Setup ---
root = tk.Tk()
root.title("Password Cracker")

tk.Label(root, text="Hash to Crack:").grid(row=0, column=0, sticky="e")
hash_entry = tk.Entry(root, width=60)
hash_entry.grid(row=0, column=1, columnspan=3, padx=5, pady=5)

tk.Label(root, text="Hash Type:").grid(row=1, column=0, sticky="e")
hash_type_var = tk.StringVar(value='sha256')
hash_type_menu = tk.OptionMenu(root, hash_type_var, 'md5', 'sha1', 'sha256', 'sha512')
hash_type_menu.grid(row=1, column=1, padx=5, pady=5, sticky="w")

tk.Label(root, text="Wordlist Path (optional):").grid(row=2, column=0, sticky="e")
wordlist_entry = tk.Entry(root, width=40)
wordlist_entry.insert(0, "mini.txt")
wordlist_entry.grid(row=2, column=1, columnspan=3, padx=5, pady=5)

tk.Label(root, text="Min Length:").grid(row=3, column=0, sticky="e")
min_len_entry = tk.Entry(root, width=5)
min_len_entry.insert(0, "1")
min_len_entry.grid(row=3, column=1, sticky="w", padx=5, pady=5)

tk.Label(root, text="Max Length:").grid(row=3, column=2, sticky="e")
max_len_entry = tk.Entry(root, width=5)
max_len_entry.insert(0, "12")
max_len_entry.grid(row=3, column=3, sticky="w", padx=5, pady=5)

rainbow_var = tk.BooleanVar(value=True)
tk.Checkbutton(root, text="Use Rainbow Table", variable=rainbow_var).grid(row=4, column=1, sticky="w", pady=5)

tk.Button(root, text="Start Cracking", command=start_cracking).grid(row=5, column=1, pady=10)

root.mainloop()
