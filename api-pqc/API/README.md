# PQC API

Simple API for experimenting with Post-Quantum Cryptography (PQC) primitives such as Kyber and Dilithium.

The API is built using **FastAPI** and is intended as a learning project to explore how PQC primitives can be exposed as web services.

## Project Goals

- Experiment with post-quantum cryptographic primitives
- Build a simple API for key generation, encryption and signing
- Learn how to deploy cryptographic services using Docker and cloud platforms

## Tech Stack

- Python 3.11
- FastAPI
- Uvicorn
- liboqs (Open Quantum Safe)
- Docker
- Render (deployment)

---

# Installation

This project requires **liboqs**, a C library from the Open Quantum Safe project that implements several post-quantum cryptographic primitives. Since liboqs is written in C, it must be compiled locally before it can be used from Python.

The following steps describe the setup process used in this project.

---

# 1. Create and activate the Python environment

Using Conda:

conda create -n pqc-api python=3.11  
conda activate pqc-api  

Install the Python dependencies:

pip install fastapi uvicorn liboqs-python  

---

# 2. Install build tools

liboqs must be compiled locally. Install the required build tools:

conda install -c conda-forge cmake ninja git  

On Windows, it is recommended to install:

Visual Studio Build Tools → Desktop development with C++

This provides the MSVC compiler, which is fully compatible with liboqs.

---

# 3. Clone liboqs

From the project root directory:

git clone https://github.com/open-quantum-safe/liboqs.git  
cd liboqs  

---

# 4. Build liboqs

Create a build directory:

mkdir build  
cd build  

Configure the build:

cmake -S . -B build -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="C:/path/to/project/liboqs/install"

Explanation of the main options:

BUILD_SHARED_LIBS=ON  
Generates a shared library (oqs.dll) required by Python.

OQS_BUILD_ONLY_LIB=ON  
Builds only the core library and skips test binaries.

Then compile and install:

cmake --build build  
cmake --build build --target install  

After installation you should have the following structure:

liboqs/install  
 ├── bin  
 │   └── oqs.dll  
 ├── include  
 └── lib  

---

# 5. Configure environment variables

Python must be able to locate the compiled oqs.dll.

Temporary solution (PowerShell):

$env:OQS_INSTALL_PATH="C:\path\to\project\liboqs\install"  
$env:PATH+=";C:\path\to\project\liboqs\install\bin"  

Permanent solution:

Add the following path to the system PATH:

C:\path\to\project\liboqs\install\bin

And create the environment variable:

OQS_INSTALL_PATH=C:\path\to\project\liboqs\install

After this configuration, restart VS Code or the terminal.

---

# 6. Verify installation

Run a simple test:

python -c "import oqs; print(oqs.get_enabled_kem_mechanisms()); print(oqs.get_enabled_sig_mechanisms())"

You should see a list of available algorithms such as:

ML-KEM (Kyber)  
ML-DSA (Dilithium)  
Falcon  
Classic McEliece  

---

# Project Structure

PQC/
│
├── API/
│   ├── app/
│   │   ├── crypto/
│   │   │   ├── kyber.py
│   │   │   └── dilithium.py
│   │   └── main.py
│   │
│   ├── requirements.txt
│   └── README.md
│
└── liboqs/

---

# Running the API

From the API directory:

uvicorn app.main:app --reload

The API will start at:

http://127.0.0.1:8000

---

# Notes

The project currently exposes experimental endpoints for:

ML-KEM (Kyber) key encapsulation  
ML-DSA (Dilithium) digital signatures  

These primitives correspond to the NIST standardized post-quantum algorithms selected in 2024.