from requests import Session
import random
import time

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
hosts = s.get(f"{base_url}/download", params={"user_id": "2", "note_id": "2", "filename": "/etc/hosts"})
if "localhost" in hosts.text:
	print("[!] Утечка системного файла")
else:
	print("[+] Утечка системного файла предотвращена")
leaked = False
print("Попытка brute-force атаки для получения чужого файла")
for id in range(1, 10000):
	file = s.get(f"{base_url}/download", params={"user_id": "2", "note_id": "2", "filename": f"../../1/1/{id}.jpg"})
	if "flag{user_file_leaked}" in file.text:
		leaked = True
		break
	if id%1000 == 0:
		print(f"Перебрано {id} возможных имён")
if leaked:
	print("[!] Утечка пользовательского файла")
else:
	print("[+] Утечка пользовательских файлов предотвращена")

print("Проверка JSON формата")
app = s.get(f"{base_url}/download", json={"user_id": "2", "note_id": "2", "filename": "../../../app.py"})
if "flag{app_source_code_leaked}" in app.text:
	print("[!] Утечка исходного кода")
else:
	print("[+] Утечка исходного кода предотвращена")
hosts = s.get(f"{base_url}/download", json={"user_id": "2", "note_id": "2", "filename": "/etc/hosts"})
if "localhost" in hosts.text:
	print("[!] Утечка системного файла")
else:
	print("[+] Утечка системного файла предотвращена")
leaked = False
print("Попытка brute-force атаки для получения чужого файла")
for id in range(1, 10000):
	file = s.get(f"{base_url}/download", json={"user_id": "2", "note_id": "2", "filename": f"../../1/1/{id}.jpg"})
	if "flag{user_file_leaked}" in file.text:
		leaked = True
		break
	if id%1000 == 0:
		print(f"Перебрано {id} возможных имён")
if leaked:
	print("[!] Утечка пользовательского файла")
else:
	print("[+] Утечка пользовательских файлов предотвращена")

print("Бенчмарк...")
random_string = random.randbytes(16384).hex()
fake_block = 0
begin = time.time()
for i in range(10000):
    benchmark = s.post(f"{base_url}/benchmark", data={"data": random_string[ (i*57+67)%230 : 5000+(i*116+716)%9999 ]})
    if benchmark.status_code == 403:
        fake_block += 1
    if i%1000 == 0:
        print(f"Отправлено {i}/10000 запросов")
diff = time.time() - begin
print(f"{fake_block/100}% ложных срабатываний, {10000/diff} запросов в секунду")
