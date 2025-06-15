# Database-Dehasher

A decryptor of .json files that has a password hashed with the parameter "password": everything that is here whether it is SHA512, 1, 256 or Bycrypt, MD5 it will try to deash it, I recommend not deashing bicrypt databases with the current wordlist.

# IMAGES

![image](https://github.com/user-attachments/assets/7c58badd-51c6-4eea-bbef-c7d6e431d694)

# SETUP 

- Python (PIP)
  - 1- Open cmd and go to the project folder using CD on windows or linux and run the following command.
  - 2- pip install -r requirements.txt
  - 4- Place your .json databases in the input folder.
  - 5- Then run this command in the project folder: `python Database-Deasher.py`
  - 6- Follow the steps as the example picture when you run the python file for start dehashing.
