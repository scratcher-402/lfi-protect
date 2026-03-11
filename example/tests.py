from requests import Session
import random
import time
import base64
import json

s = Session()
base_url = "http://localhost:1545"
insecure_url = "http://localhost:1544"

def register_users(base_url):
    s.post(f"{base_url}/register", data={"username": "user", "password": "1234"})
    s.post(f"{base_url}/register", data={"username": "user2", "password": "5678"})

def login(base_url, username, password):
	r = s.post(f"{base_url}/login", data={"username": username, "password": password})
	if r.status_code == 200 and r.url == f"{base_url}/dashboard":
		return r.headers.get("Test-User-ID")
	else:
		print(f"Ошибка входа <код {r.status_code}, URL {r.url}>")
		return False

def logout(base_url):
	s.get(f"{base_url}/logout")

def create_note(base_url, title, content):
	r = s.post(f"{base_url}/note/new", data={"title": title, "content": content})
	if r.status_code == 200 and r.url.startswith(f"{base_url}/note/"):
		note_id = r.url.split('/')[-1]
		return note_id, r.text
	else:
		print(f"Ошибка создания заметки <код {r.status_code}, URL {r.url}>")
		return False

def fetch_note(base_url, id):
	r = s.get(f"{base_url}/note/{id}")
	if r.status_code == 200:
		return r.text
	else:
		print(f"Ошибка получения заметки <код {r.status_code}, URL {r.url}>")
		return False

def edit_note(base_url, id, title, content, files=()):
	if len(files) == 0:
		r = s.post(f"{base_url}/note/{id}/edit", data={"title": title, "content": content})
	else:
		r = s.post(f"{base_url}/note/{id}/edit", data={"title": title, "content": content}, files={"files": files})
	if r.status_code == 200 and r.url == f"{base_url}/note/{id}":
		return r.text
	else:
		print(f"Ошибка редактирования заметки <код {r.status_code}, URL {r.url}>")
		return False

def gen_file():
	return ("test.jpg", "+_" * random.randint(50,200) + "flag{user_file_leaked}" + "&:" * random.randint(200,300))

def download_file(base_url, user_id, note_id, filename):
	r = s.get(f"{base_url}/download", params={"user_id": str(user_id), "note_id": str(note_id), "filename": filename})
	if r.status_code == 200:
		return r.text
	else:
		print(f"Ошибка получения файла <код {r.status_code}, URL {r.url}>")
		return False

def download_file_json(base_url, user_id, note_id, filename):
	r = s.get(f"{base_url}/download", json={"user_id": str(user_id), "note_id": str(note_id), "filename": filename})
	if r.status_code == 200:
		return r.text
	else:
		print(f"Ошибка получения файла <код {r.status_code}, URL {r.url}>")
		return False

def encode_request(payload):
    enc = base64.b64encode(bytes(json.dumps(payload), "utf-8")).decode("utf-8")
    return {
        "encoding": "base64",
        "data": enc,
    }

def download_file_base64(base_url, user_id, note_id, filename):
	r = s.get(f"{base_url}/download", json=encode_request({"user_id": str(user_id), "note_id": str(note_id), "filename": filename}))
	if r.status_code == 200:
		return r.text
	else:
		print(f"Ошибка получения файла <код {r.status_code}, URL {r.url}>")
		return False
	
def benchmrk(base_url):
	dmin, dtotal, dcount, dmax = 5000, 0, 0, -1
	fails = 0
	for _ in range(1000):
		test_string = random.randbytes(random.randint(2048, 65536)).hex()
		begin = time.time()
		r = s.post(f"{base_url}/benchmark", data={"data": test_string})
		d = (time.time()-begin)*1000
		if d > dmax: dmax = d
		if d < dmin: dmin = d
		dtotal += d
		dcount += 1
		if r.status_code != 200:
			fails += 1
	return dmin, dtotal/dcount, dmax, fails
		

results = []

def add_result(group, test, success, data=None):
	results.append((group, test, success, data))
	success_string = "УСПЕШНО" if success else "ОШИБКА"
	print(f"[{success_string}] ({group}/{test})")
	if data:
		print(data)

def print_results():
	success_count = 0
	for group, test, success, data in results:
		if success:
			success_count += 1
	print(f"Пройдено {success_count} тестов из {len(results)}")
	return success_count/len(results)

register_users(insecure_url)

test1 = login(insecure_url, "user", "1234")
add_result("Функц. веб-прил.", "Вход в систему", test1)

note_id, note_text = create_note(insecure_url, "Test note", "flag{note_created}")
test2 = note_id and "flag{note_created}" in note_text
add_result("Функц. веб-прил.", "Создание заметок", test2)

note_text = edit_note(insecure_url, note_id, "Edited note", "flag{note_edited}")
test3 = "flag{note_edited}" in note_text and "Edited note" in note_text
add_result("Функц. веб-прил.", "Редактирование заметок", test3)

logout(insecure_url)
login(insecure_url, "user2", "5678")
test4 = fetch_note(insecure_url, note_id)
add_result("Функц. веб-прил.", "Проверка безопасности", not test4)

logout(insecure_url)
login(insecure_url, "user", "1234")
file = gen_file()
note_text = edit_note(insecure_url, note_id, "Edited note", "flag{note_edited}", files=file)
test5 = "test.jpg" in note_text
add_result("Функц. веб-прил.", "Прикрепление файлов", test5)


test6 = login(base_url, "user", "1234")
add_result("Функц. веб-прил. с защитой", "Вход в систему", test6)

note_id, note_text = create_note(base_url, "Test note", "flag{note_created}")
test7 = note_id and "flag{note_created}" in note_text
add_result("Функц. веб-прил. с защитой", "Создание заметок", test7)

note_text = edit_note(base_url, note_id, "Edited note", "flag{note_edited}")
test8 = "flag{note_edited}" in note_text and "Edited note" in note_text
add_result("Функц. веб-прил. с защитой", "Редактирование заметок", test8)

logout(base_url)
login(base_url, "user2", "5678")
test9 = fetch_note(base_url, note_id)
add_result("Функц. веб-прил. с защитой", "Проверка безопасности", not test9)

logout(base_url)
login(base_url, "user", "1234")
file = gen_file()
note_text = edit_note(base_url, note_id, "Edited note", "flag{note_edited}", files=file)
test10 = "test.jpg" in note_text
add_result("Функц. веб-прил. с защитой", "Прикрепление файлов", test10)


logout(insecure_url)
user_id = login(insecure_url, "user", "1234")
note_id, note_text = create_note(insecure_url, "Test2 note", "Test")

file = download_file(insecure_url, user_id, note_id, "../../../app.py")
test11 = "flag{app_source_code_leaked}" in file
add_result("Проверка уязв.", "Стандартный запрос", test11)

file = download_file_json(insecure_url, user_id, note_id, "../../../app.py")
test12 = "flag{app_source_code_leaked}" in file
add_result("Проверка уязв.", "JSON-запрос", test12)

file = download_file_base64(insecure_url, user_id, note_id, "../../../app.py")
test13 = "flag{app_source_code_leaked}" in file
add_result("Проверка уязв.", "Закодированный запрос", test13)


logout(base_url)
user_id = login(base_url, "user", "1234")
note_id, note_text = create_note(base_url, "Test2 note", "Test")

test14 = download_file(base_url, user_id, note_id, "../../../app.py")
add_result("Проверка защ.", "Стандартный запрос", not test14)

test15 = download_file_json(base_url, user_id, note_id, "../../../app.py")
add_result("Проверка защ.", "JSON-запрос", not test15)

test16 = download_file_base64(base_url, user_id, note_id, "../../../app.py")
add_result("Проверка защ.", "Закодированный запрос", not test16)

dmin, davg, dmax, fails = benchmrk(insecure_url)
add_result("Бенчмарк", "без защиты", True, f"задержка мин. {dmin:.2f} мс, сред. {davg:.2f} мс, макс. {dmax:.2f} мс\n{(1000/davg):.2f} запросов/сек\n{fails} ложных срабатываний")

dmin, davg, dmax, fails = benchmrk(base_url)
add_result("Бенчмарк", "с защитой", True, f"задержка мин. {dmin:.2f} мс, сред. {davg:.2f} мс, макс. {dmax:.2f} мс\n{(1000/davg):.2f} запросов/сек\n{fails} ложных срабатываний")

rate = print_results()
if rate < 0.5:
	exit(1)
