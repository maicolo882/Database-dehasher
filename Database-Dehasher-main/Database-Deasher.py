import os
import re
import json
import bcrypt
import platform
from time import time, sleep
from shutil import get_terminal_size
from hashlib import md5, sha1, sha256, sha512
from time import sleep
from shutil import get_terminal_size


INPUT_FOLDER = "input/"
OUTPUT_FOLDER = "output/"

wl_passwords = []
RESULT = None
successful_count = 0
failed_count = 0


def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def get_hash_salt(content: str) -> tuple:
    if content is None:  
        return (None, None)
    
    if len(content) == 32 and all(c in '0123456789abcdef' for c in content):
        return (content, None)

    if content.startswith('SHA512$'):
        parts = content.split('$')
        if len(parts) == 3:
            return (parts[2], parts[1])

    elif content.startswith('SHA256$'):
        parts = content.split('$')
        if len(parts) == 3:
            return (parts[2], parts[1])

    if content.startswith('$SHA512$'):
        parts = content.split('$')
        if len(parts) == 4:
            return (parts[2], parts[3])

    elif content.startswith('$SHA256$'):
        parts = content.split('$')
        if len(parts) == 4:
            return (parts[2], parts[3])

    elif content.startswith('$SHA512$'):
        parts = content.split('@')
        if len(parts) == 2:
            hash_part = parts[0].split('$')[2]
            salt_part = parts[1]
            return (hash_part, salt_part)

    if content.startswith('$SHA256$'):
        parts = content.split('@')
        if len(parts) == 2:
            hash_part = parts[0].split('$')[2]
            salt_part = parts[1]
            return (hash_part, salt_part)

    if content.startswith('$2b$') or content.startswith('$2a$') or content.startswith('$2y$'):
        parts = content.split('$')
        if len(parts) >= 4:
            hash_and_salt = '$'.join(parts[:4])
            return (hash_and_salt, None)

    if '$' in content:
        result = re.findall("[^$SHA]\w{31,127}", content)

        if result:
            if len(result) > 1:
                selected = (result[1], result[0]) if len(result[1]) > len(result[0]) else (result[0], result[1])
                return selected
            
            splitted = re.findall("[^$SHA]\w+", content)
            salt = ''.join(x for x in splitted if x != result[0])
            return (result[0], salt if salt else None)

        return (None, None)
    
    elif ':' in content:
        splitted = content.split(':')
        selected = (splitted[0], splitted[1]) if len(splitted[0]) > len(splitted[1]) else (splitted[1], splitted[0])
        return selected
    
    for length in [40, 64, 128]:
        if len(content) == length and all(c in '0123456789abcdef' for c in content):
            return (content, None)

    return (None, None)

def load_wordlist(file: str):
    global wl_passwords
    with open(file, 'r', encoding='latin-1') as f:
        wl_passwords = [password.strip() for password in f]


def start_brute(password: str, hash_str: str, salt: str or None = None):
    global RESULT
    hash_length = len(hash_str)
    if hash_str.startswith('$2a$') or hash_str.startswith('$2b$') or hash_str.startswith('$2y$'):
        if bcrypt.checkpw(password.encode(), hash_str.encode()):
            RESULT = password
        return
    if hash_length == 32:
        if salt:
            if (md5(password.encode() + salt.encode()).hexdigest() == hash_str or
                md5(salt.encode() + password.encode()).hexdigest() == hash_str or
                md5(md5(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULT = password
        else:
            if md5(password.encode()).hexdigest() == hash_str:
                RESULT = password
    elif hash_length == 40:
        if salt:
            if (sha1(password.encode() + salt.encode()).hexdigest() == hash_str or
                sha1(salt.encode() + password.encode()).hexdigest() == hash_str or
                sha1(sha1(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULT = password
        else:
            if sha1(password.encode()).hexdigest() == hash_str:
                RESULT = password
    elif hash_length == 64:
        if salt:
            if (sha256(password.encode() + salt.encode()).hexdigest() == hash_str or
                sha256(salt.encode() + password.encode()).hexdigest() == hash_str or
                sha256(sha256(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULT = password
        else:
            if sha256(password.encode()).hexdigest() == hash_str:
                RESULT = password
    elif hash_length == 128:
        if salt:
            if (sha512(password.encode() + salt.encode()).hexdigest() == hash_str or
                sha512(salt.encode() + password.encode()).hexdigest() == hash_str or
                sha512(sha512(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULT = password
        else:
            if sha512(password.encode()).hexdigest() == hash_str:
                RESULT = password

def main_brute(hash_str: str, salt: str):
    global RESULT
    RESULT = None
    if hash_str is None:
        return None
    for password in wl_passwords:
        if RESULT is not None:
            break
        start_brute(password, hash_str, salt)
    return RESULT


def load_hashes_from_json(input_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_results(results, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)


def progress_bar(current, total, successful, failed, start_time):
    term_width = get_terminal_size().columns
    bar_length = term_width - 75 
    filled_length = int(bar_length * current // total)
    bar = '=' * filled_length + '-' * (bar_length - filled_length)
    percent = (current / total) * 100
    elapsed_time = time() - start_time
    print(f"\r[{bar}] {percent:6.2f}% | Dehashed: {successful} | Failed: {failed} | Time: {elapsed_time}s", end='', flush=True)


def brute_force_hashes(hashes, output_file):
    global successful_count, failed_count
    results = hashes
    total = len(results)
    start_time = time()

    for idx, entry in enumerate(results, start=1):
        name = entry.get('name', 'Unknown')
        password_hash = entry.get('password', None)

        if password_hash is None:
            failed_count += 1
            continue

        hash_str, salt = get_hash_salt(password_hash)
        password = main_brute(hash_str, salt)

        if password is not None:
            successful_count += 1
            entry['password'] = password
        else:
            failed_count += 1

        if idx % 300 == 0:
            save_results(results, output_file)

        progress_bar(idx, total, successful_count, failed_count, start_time)

    save_results(results, output_file)
    print()


def ask_for_file(prompt, folder, extension_check=None):
    while True:
        file_name = input(prompt).strip()
        file_path = os.path.join(folder, file_name)
        if not os.path.isfile(file_path):
            print(f"File '{file_name}' not found in '{folder}' folder.")
            continue
        if extension_check and not file_name.lower().endswith(extension_check):
            print(f"Only '{extension_check}' files are accepted.")
            continue
        return file_path


def main():
    clear_screen()
    print("=== DATABASE DEHASHER ===\n")

    wordlist_path = ask_for_file("Enter wordlist file name (same directory and with extension): ", ".", None)
    input_file_path = ask_for_file("Enter input file name (in 'input/' folder, must be .json): ", INPUT_FOLDER, ".json")
    output_name = input("Enter desired output file name (without extension): ").strip()
    output_file = os.path.join(OUTPUT_FOLDER, f"{output_name}.json")

    print("")
    print("Loading wordlist...")
    load_wordlist(wordlist_path)

    print("Loading hashes...")
    hashes = load_hashes_from_json(input_file_path)

    print(f"\nStarting dehashing of {len(hashes)} entries...\n")
    brute_force_hashes(hashes, output_file)

    print(f"\nProcess complete.")
    print(f"Results saved in '{output_file}'")
    print(f"Total dehashed: {successful_count}")
    print(f"Total failed: {failed_count}\n")


if __name__ == "__main__":
    main()
