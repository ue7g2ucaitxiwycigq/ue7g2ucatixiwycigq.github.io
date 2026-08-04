import tkinter as tk
from tkinter import scrolledtext
import requests
import time
import threading
import random

API_KEY = "APi key here"

def chat_with_ai(message):
    try:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }

        data = {
            "model": "openai/gpt-4o-mini",  # تأكد أن هذا الموديل مفعّل في حسابك
            "messages": [{"role": "user", "content": message}]
        }

        response = requests.post(url, headers=headers, json=data)
        json_data = response.json()

        # لو الرد فيه خطأ أو ما فيه choices
        if "choices" not in json_data:
            if "error" in json_data:
                return f"⚠️ خطأ من OpenRouter: {json_data['error']['message']}"
            return "⚠️ لم يصل رد من الذكاء الاصطناعي."

        return json_data["choices"][0]["message"]["content"]

    except Exception as e:
        return f"⚠️ خطأ: {str(e)}"


def spawn_particle(x, y):
    size = random.randint(0, 0)
    dx = random.randint(0, 0)
    dy = random.randint(0, 0)

    particle = tk.Label(root, text="*", fg="#00ff00", bg="black", font=("Consolas", size))
    particle.place(x=x + dx, y=y + dy)

    def fade():
        for i in range(5):
            particle.config(fg=f"#00ff00")
            root.update()
            time.sleep(0.03)
        particle.destroy()

    threading.Thread(target=fade).start()


def type_animation(text, tag):
    for char in text:
        chat_window.insert(tk.END, char, tag)
        chat_window.update()

        x = chat_window.winfo_rootx() + 300
        y = chat_window.winfo_rooty() + 400
        spawn_particle(x, y)

        time.sleep(0.01)

    chat_window.insert(tk.END, "\n\n")


def send_message(event=None):
    user_text = entry.get()
    if not user_text.strip():
        return

    chat_window.insert(tk.END, "YOU> ", "user")
    type_animation(user_text, "user")
    entry.delete(0, tk.END)

    def ai_thread():
        reply = chat_with_ai(user_text)
        chat_window.insert(tk.END, "AI> ", "ai")
        type_animation(reply, "ai")

    threading.Thread(target=ai_thread).start()


root = tk.Tk()
root.title("AI Terminal")
root.geometry("700x600")
root.configure(bg="black")

root.resizable(False, False)

chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=25,
                                        bg="black", fg="#00ff00", font=("Consolas", 12))
chat_window.pack(padx=10, pady=10)

chat_window.tag_config("user", foreground="#00ff00")
chat_window.tag_config("ai", foreground="#ff0000")

entry = tk.Entry(root, width=60, font=("Consolas", 14), bg="black", fg="#00ff00", insertbackground="#00ff00")
entry.pack(side=tk.LEFT, padx=10, pady=10)

send_button = tk.Button(root, text="SEND", command=send_message,
                        bg="#003300", fg="#00ff00", font=("Consolas", 14, "bold"))
send_button.pack(side=tk.RIGHT, padx=10, pady=10)

root.bind("<Return>", send_message)

root.mainloop()
