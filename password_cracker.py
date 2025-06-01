#!/usr/bin/env python
# coding: utf-8

import hashlib
import itertools
import string
import threading
from rainbow_table import RainbowTable

class PasswordCracker:
    def __init__(self, hash_to_crack, hash_type='sha256', wordlist_path=None, min_len=1, max_len=4, use_rainbow=False):
        self.hash_to_crack = hash_to_crack
        self.hash_type = hash_type
        self.wordlist_path = wordlist_path
        self.min_len = min_len
        self.max_len = max_len
        self.found = False
        self.result = None
        self.use_rainbow = use_rainbow
        self.charset = string.ascii_letters + string.digits
        self.lock = threading.Lock()
        self.rainbow_table = RainbowTable(hash_type) if use_rainbow else None

    def hash_password(self, password):
        h = hashlib.new(self.hash_type)
        h.update(password.encode())
        return h.hexdigest()

    def check_password(self, password):
        hashed = self.hash_password(password)
        if hashed == self.hash_to_crack:
            with self.lock:
                self.found = True
                self.result = password
                print(f"[+] Password found: {password}")

    def dictionary_attack(self):
        if self.use_rainbow:
            match = self.rainbow_table.lookup(self.hash_to_crack)
            if match:
                self.result = match
                self.found = True
                print(f"[+] Password found (rainbow): {match}")
                return

        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if self.found:
                    break
                word = line.strip()
                self.check_password(word)

    def brute_force_worker(self, length):
        for candidate in itertools.product(self.charset, repeat=length):
            if self.found:
                return
            self.check_password(''.join(candidate))

    def brute_force_attack(self):
        threads = []
        for length in range(self.min_len, self.max_len + 1):
            t = threading.Thread(target=self.brute_force_worker, args=(length,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def start(self):
        if self.wordlist_path:
            self.dictionary_attack()
        else:
            self.brute_force_attack()
        if not self.found:
            print("[-] Password not found.")
