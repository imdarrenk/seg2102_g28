This repository contains a Python-based benchmarking suite designed to evaluate the performance of AES, Blowfish, and DES encryption/decryption algorithms within a MongoDB (NoSQL) workflow. The suite measures latency, CPU utilization, and memory footprint across various payload types.

<h1> Setup </h1>
Before running the benchmarks, ensure your system meets the following requirements:

- Python 3.8+
- MongoDB
- Homebrew (macOS)

❗ Windows: Install MongoDB Community Server and ensure the service is running.
- Required Libraries: Install the dependencies via pip: ```pip install pymongo pycryptodome cryptography psutil```

❗macOS: Use Homebrew: 
- brew tap mongodb/brew
- brew install mongodb-community
- brew services start mongodb-community.
- Required Libraries: Install the dependencies via pip: ```pip install pymongo pycryptodome cryptography psutil```

<h1> Files </h1>
To ensure the script runs correctly, place the following test files on your Desktop:

- only_text.txt
- alphanumerical.txt 
- numerical.txt
- audio.mp3 

<h1> Running the tests</h1>

- Windows: Open Command Prompt and type ```python win_encryption_test.py```
- Mac: Open Terminal and type ```python3 mac_encryption_test.py```


<br>
❗ The script automatically generates a CSV file on your Desktop titled results.csv. 

If not found on Windows, please follow the following procedure:

 ```File Explorer > Local Disk C > Users > [your_user], results.csv```
