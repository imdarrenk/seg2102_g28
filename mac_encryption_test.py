import time, os, csv, psutil
from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# 1. Database Setup
# Ensure MongoDB is running (brew services start mongodb-community)
client = MongoClient('mongodb://localhost:27017/')
db = client['SEG2102Research']

def benchmark_integrated(file_path, algo_name, algo_instance, key_size, block_size):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    key = os.urandom(key_size)
    iv = os.urandom(block_size)
    file_name = os.path.basename(file_path)
    proc = psutil.Process(os.getpid())
    
    # Reset CPU interval for high-precision capture on macOS
    psutil.cpu_percent(interval=None) 
    mem_start = proc.memory_info().rss / (1024 * 1024) 
    
    start_enc = time.perf_counter()
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    cipher_enc = Cipher(algo_instance(key), modes.CBC(iv))
    encryptor = cipher_enc.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    db[f'test_{algo_name}'].insert_one({
        "file": file_name, 
        "payload": ciphertext, 
        "key": key, 
        "iv": iv
    })
    end_enc = time.perf_counter()
    
    start_dec = time.perf_counter()
    record = db[f'test_{algo_name}'].find_one({"file": file_name}, sort=[('_id', -1)])
    
    cipher_dec = Cipher(algo_instance(record['key']), modes.CBC(record['iv']))
    decryptor = cipher_dec.decryptor()
    decrypted_padded = decryptor.update(record['payload']) + decryptor.finalize()
    
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    unpadder.update(decrypted_padded) + unpadder.finalize()
    end_dec = time.perf_counter()

    cpu_usage = psutil.cpu_percent(interval=None)
    mem_end = proc.memory_info().rss / (1024 * 1024)
    mem_impact = max(0, mem_end - mem_start)
    
    return (end_enc - start_enc), (end_dec - start_dec), cpu_usage, mem_impact

files = ['only_text.txt', 'alphanumerical.txt', 'numerical.txt', 'audio.mp3']

desktop_path = os.path.expanduser("~/Desktop") 

results = []

print("Starting test...")
for f_name in files:
    path = os.path.join(desktop_path, f_name)
    if os.path.exists(path):
        f_size = os.path.getsize(path) / 1024
        print(f"Currently executing: {f_name}")
        
        time.sleep(0.1) 
        
        ae, ad, ac, am = benchmark_integrated(path, "AES", algorithms.AES, 16, 16)
        be, bd, bc, bm = benchmark_integrated(path, "Blowfish", algorithms.Blowfish, 16, 8)
        de, dd, dc, dm = benchmark_integrated(path, "DES", algorithms.TripleDES, 8, 8)
        
        results.append([
            f_name, f"{f_size:.2f}",
            ae, ad, ac, am,
            be, bd, bc, bm,
            de, dd, dc, dm
        ])
    else:
        print(f"Skipping: {f_name} (Not found on Desktop)")

base_filename = "mac_results"
filename = f"{base_filename}.csv"
counter = 1
while os.path.exists(os.path.join(desktop_path, filename)):
    filename = f"{base_filename}({counter}).csv"
    counter += 1

save_path = os.path.join(desktop_path, filename)

with open(save_path, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow([
        "File", "Size_KB", 
        "AES_Enc", "AES_Dec", "AES_CPU%", "AES_Mem_MB",
        "Blow_Enc", "Blow_Dec", "Blow_CPU%", "Blow_Mem_MB",
        "DES_Enc", "DES_Dec", "DES_CPU%", "DES_Mem_MB"
    ])
    writer.writerows(results)

print(f"Done, file saved as {filename}")
