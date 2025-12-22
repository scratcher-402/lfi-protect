from requests import Session

s = Session()
base_url = "http://localhost:1545"

# Регистрация
s.post(f"{base_url}/register", data={"username": "user", "password": "1234"})
s.post(f"{base_url}/register", data={"username": "user2", "password": "5678"})

# Тестирование заметок
s.post(f"{base_url}/login", data={"username": "user", "password": "1234"})
s.post(f"{base_url}/note/new", data={"title": "Test note", "content": "This is a test note, flag{new_note_created}"})
note1 = s.get(f"{base_url}/note/1")
if "flag{new_note_created}" in note1.text:
	print("[+] Создание заметок работает")
else:
	print("[!] Создание заметок не работает")
s.post(f"{base_url}/note/1/edit", data={"title": "New title", "content": "This is an edited note, flag{note_edited}"})
note1 = s.get(f"{base_url}/note/1")
if "flag{note_edited}" in note1.text:
	print("[+] Редактирование заметок работает")
else:
	print("[!] Редактирование заметок не работает")
s.post(f"{base_url}/note/1/edit", data={"title": "New title", "content": "This is an edited note, flag{note_edited}"}, files={"files": ("test.jpg", "+_"*100 + "flag{user_file_leaked}" + "&:" * 100)})
note1 = s.get(f"{base_url}/note/1")
if "test.jpg" in note1.text:
	print("[+] Прикрепление файлов работает")
else:
	print("[!] Прикрепление файлов не работает")
s.get(f"{base_url}/logout")

# Проверка безопасности
s.post(f"{base_url}/login", data={"username": "user2", "password": "5678"})
note1 = s.get(f"{base_url}/note/1")
if "flag{note_edited}" in note1.text:
	print("[!] Можно просматривать чужие заметки")
else:
	print("[+] Нельзя просматривать чужие заметки")
s.post(f"{base_url}/note/new", data={"title": "Test2 note", "content": "Знакомьтесь с клавиатурой Gboard! Здесь будет сохраняться текст, который вы копируете."})
app = s.get(f"{base_url}/download", params={"user_id": "2", "note_id": "2", "filename": "../../../app.py"})
if "flag{app_source_code_leaked}" in app.text:
	print("[!] Утечка исходного кода")
else:
	print("[+] Утечка исходного кода предотвращена")
leaked = False
print("Попытка brute-force атаки для получения чужого файла")
for id in range(1, 10000):
	file = s.get(f"{base_url}/download", params={"user_id": "2", "note_id": "2", "filename": f"../../1/1/{id}.jpg"})
	if file.status_code != 404:
		leaked = True
		break
	if id%100 == 0:
		print(f"Перебрано {id} возможных имён")
if leaked:
	print("[!] Утечка пользовательского файла")
else:
	print("[+] Утечка пользовательских файлов предотвращена")