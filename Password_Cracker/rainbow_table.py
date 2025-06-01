#!/usr/bin/env python
# coding: utf-8

import hashlib
import os
import pickle

class RainbowTable:
    def __init__(self, hash_type='sha256', filename='rainbow.pkl', min_len=1, max_len=32):
        self.hash_type = hash_type
        self.filename = filename
        self.min_len = min_len
        self.max_len = max_len
        self.table = self.load()

    def generate(self, wordlist_path):
        self.table = {}
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for word in f:
                word = word.strip()
                if self.min_len <= len(word) <= self.max_len:
                    h = hashlib.new(self.hash_type)
                    h.update(word.encode())
                    hash_value = h.hexdigest()
                    self.table[hash_value] = word
                    # ✅ Debug print:
                    print(f"{word} -> {hash_value}")
        self.save()

    def save(self):
        with open(self.filename, 'wb') as f:
            pickle.dump(self.table, f)

    def load(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'rb') as f:
                return pickle.load(f)
        return {}

    def lookup(self, target_hash):
        return self.table.get(target_hash, None)
