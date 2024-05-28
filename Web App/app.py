from flask import Flask, request, send_file, render_template_string, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import bcrypt
import psutil
import time
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'file'
app.config['SECRET_KEY'] = os.urandom(32)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.route('/')
def index():
    return render_template_string('''
        <!doctype html>
        <html lang="en">
           <head>
              <!-- Required meta tags -->
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

              <!-- Tailwind CSS -->
              <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.7/tailwind.min.css">
              <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css">
              <link rel="stylesheet" type="text/css" href="{{ url_for('static', filename='style.css') }}">
              <title>SHE Cryptography</title>
           </head>
           <body class="bg-gray-100">
            <header class="py-4 px-3 md:py-8 md:px-3">
              <nav class="flex justify-between items-center">
                <h1 class="text-2xl md:text-3xl font-bold text-grey-500" style="color: yellow">SHE Cryptography</h1>
              </nav>
            </header>

            <script>
              const menuToggle = document.getElementById('menu-toggle');
              const navLinks = document.getElementById('nav-links');

              menuToggle.addEventListener('click', function() {
                navLinks.classList.toggle('hidden');
                menuToggle.classList.toggle('rotate-90');
                const isOpen = !navLinks.classList.contains('hidden');
                const openMenuPath = 'M4 6h16v2H4zm0 5h16v2H4zm0 5h16v2H4z';
                const closedMenuPath = 'M4 8h16M4 16h16';
                const openMenuClass = 'menu-open';
                const closedMenuClass = 'menu-closed';

                // Toggle the icon to show/hide the menu
                const menuIcon = menuToggle.querySelector('svg');
                menuIcon.querySelector(`.${openMenuClass}`).classList.toggle('hidden', isOpen);
                menuIcon.querySelector(`.${closedMenuClass}`).classList.toggle('hidden', !isOpen);
                menuIcon.setAttribute('viewBox', isOpen ? '0 0 24 24' : '0 0 20 20');
                menuIcon.setAttribute('width', isOpen ? '24' : '20');
                menuIcon.setAttribute('height', isOpen ? '24' : '20');
                menuIcon.querySelector('path').setAttribute('d', isOpen ? openMenuPath : closedMenuPath);
              });
            </script>


          <div class="px-10 py-8 text-white" id="fileencryp">
          <h2 class="text-xl font-bold mb-2">What is SHE?</h2>
          <hr class="my-4 border-gray-300 border-1">
          <p class="text-gray-700">
          <dl>
            <div class="mb-4 mx-4">
              <dd>
                <h5> SHE means "Secure Hybrid Encryption". It is a lightweight cryptographic system that protects IoT devices from several crucial cyberattacks. The main objective of this research project is to robust the security without decreasing its performance. </h5>
              </dd>
            </div>
          </dl>
        </p> <br />


          <h2 class="text-xl font-bold mb-2">How To Encrypt & Decrypt File</h2>
          <hr class="my-4 border-gray-300 border-1">
          <p class="text-gray-700">
          <dl class="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-2">
            <div class="mb-4 mx-4">
              <dt class="font-bold">Encryption:</dt>
              <dd>
                <ul class="list-disc list-inside">
                  <li>Upload your file (format: XLSX)</li>
                  <li>Click on "Encrypt" button to download a the encrypted file</li>
                </ul>
              </dd>
            </div>
            <div class="mb-4 mx-4">
              <dt class="font-bold">Decryption:</dt>
              <dd>
                <ul class="list-disc list-inside">
                  <li>Upload the encrypted file</li>
                  <li>Click on "Decrypt" button to get the decrypted form.</li>
                </ul>
              </dd>
            </div>
          </dl>
        </p>

        </div>

              <div class="container mx-auto p-4">

                 <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="card rounded-lg p-4 text-center hover:shadow-lg transition-shadow">
                       <h1 class="text-xl font-bold mb-2">File Encryption</h1>
                       <form action="/upload" method="post" enctype="multipart/form-data">
                          <div class="mb-4">
                             <label for="file" class="block text-gray-700 font-bold mb-2 text-left">Select file to encrypt:</label>
                             <input type="file" class="border rounded w-full py-2 px-3" name="file" required>
                          </div>
                          <button type="submit" class="bg-blue-700 text-white font-bold py-2 px-4 mx-auto rounded hover:bg-yellow-700 transition-colors">Encrypt</button>
                       </form>
                    </div>
                    <div class="card rounded-lg p-4 text-center hover:shadow-lg transition-shadow">
                       <h1 class="text-xl font-bold mb-2">File Decryption</h1>
                       <form action="/decrypt" method="post" enctype="multipart/form-data">
                          <div class="mb-4">
                             <label for="file" class="block text-gray-700 font-bold mb-2 text-left">Select file to decrypt:</label>
                             <input type="file" class="border rounded w-full py-2 px-3" name="file" required>
                          </div>
                          <button type="submit" class="bg-blue-700 text-white font-bold py-2 px-4  mx-auto mt-0 rounded hover:bg-yellow-700 transition-colors">Decrypt</button>
                       </form>
                    </div>
                 </div>

        </div>

        <br /> <br />

        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/popper.js@2.10.2/dist/umd/popper.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.js"></script>


        <footer class=" p-4 mt-auto" style="background-color: rgba(36, 36, 88, 0.608);">
           <div class="flex justify-between">
             <div class="text-white">
                 <p class="mb-2">Copyright &copy; <a href="https://www.bracu.ac.bd/" target="_blank">BRAC University</a> </p> <br />
                 <p> <div style="color: yellow"> Designed and Developed by - </div>
                   <a href="https://www.hack4tahsin.com" target="_blank">Tahsin Ahmed</a> <br />
                   <a href="https://www.facebook.com/arjita.saha44" target="_blank">Arjita Saha</a> <br />
                   <a href="https://www.facebook.com/arian.n.180" target="_blank">Arian Nuhan</a> <br />
                   <a href="https://www.facebook.com/itzNafim1999" target="_blank">Nafim Ahmed Bin Mohammad Noor</a>

                   <br /> <br />

                   <div style="color: yellow"> Supervisor: </div> <a href="https://cse.sds.bracu.ac.bd/faculty_profile/24/dr_muhammad_iqbal_hossain" target="_blank">Dr. Muhammad Iqbal Hossain</a> <br />
                   <div style="color: yellow"> Co-supervisor: </div> <a href="https://cse.sds.bracu.ac.bd/faculty_profile/16/md_faisal_ahmed" target="_blank"> Md. Faisal Ahmed </a>
               </p>
             </div>
           </div>
         </footer>

        </body>
        </html>
''')


# Measure power consumption and RAM usage
def measure_performance():
    process = psutil.Process(os.getpid())
    cpu_times = process.cpu_times()
    memory_info = process.memory_info()

    cpu_usage = cpu_times.user
    memory_usage = memory_info.rss / (1024 * 1024)

    return cpu_usage, memory_usage

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def ecdh_key_exchange(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = bcrypt.kdf(password=shared_key, salt=b'salt', desired_key_bytes=32, rounds=100)
    return derived_key


def ecdsa_sign(private_key, ciphertext):
    with open(ciphertext, 'rb') as file:
        data = file.read()
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature


def ecdsa_verify(public_key, ciphertext_file, signature):
    with open(ciphertext_file, 'rb') as file:
        data = file.read()
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def generate_mac(key, ciphertext):
    mac = Poly1305.generate_tag(key, ciphertext)
    return mac


def verify_mac(key, ciphertext, provided_mac):
    computed_mac = Poly1305.generate_tag(key, ciphertext)
    return computed_mac == provided_mac

def generate_token():
    nonce = os.urandom(16)
    return nonce


performance_start = time.time()

key_cpu_before = measure_performance()[0]
key_memory_before = measure_performance()[1]

# Sender's keypair
sender_private_key, sender_public_key = generate_keypair()

# Receiver's keypair
receiver_private_key, receiver_public_key = generate_keypair()

# ECDH key exchange
sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key)
receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key)

performance_end = time.time()
performance_total_time = performance_end - performance_start

with open('./analysis/performance_analysis.txt', 'a') as performance_total:
    performance_total.write("Key Generation: {} second".format(performance_total_time))

key_cpu_after = measure_performance()[0]
key_memory_after = measure_performance()[1]

key_cpu_result = key_cpu_after - key_cpu_before
key_memory_result = key_memory_after - key_memory_before

with open('./analysis/hardware_analysis.txt', 'a') as key_cpu:
    key_cpu.write("CPU Time (Key Generation): {} second".format(key_cpu_result))

with open('./analysis/hardware_analysis.txt', 'a') as key_ram:
    key_ram.write("\nRAM Usage (Key Generation): {} MB".format(key_memory_result))


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and file.filename.endswith('.xlsx'):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('encrypt_file', filename=filename))
    return redirect(request.url)


encryption_cpu_before = measure_performance()[0]
encryption_memory_before = measure_performance()[1]

@app.route('/encrypt/<filename>')
def encrypt_file(filename):
    start = time.time()

    if sender_shared_key == receiver_shared_key:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        nonce = generate_token()

        cipher = Cipher(algorithms.ChaCha20(sender_shared_key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        mac = generate_mac(sender_shared_key, ciphertext)

        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_' + filename)

        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(nonce + ciphertext + mac)

        end = time.time()
        total_time = end - start

        with open('./analysis/performance_analysis.txt', 'a') as performance:
            performance.write("\nEncryption: {} second".format(total_time))

        return send_file(encrypted_path, as_attachment=True)


encryption_cpu_after = measure_performance()[0]
encryption_memory_after = measure_performance()[1]

encryption_cpu_result = encryption_cpu_after - encryption_cpu_before
encryption_memory_result = encryption_memory_after - encryption_memory_before

with open('./analysis/hardware_analysis.txt', 'a') as encryption_cpu:
    encryption_cpu.write("\n\nCPU Time (Encryption): {} second".format(encryption_cpu_result))

with open('./analysis/hardware_analysis.txt', 'a') as encryption_cpu:
    encryption_cpu.write("\nRAM Usage (Encryption): {} MB".format(encryption_memory_result))


decryption_cpu_before = measure_performance()[0]
decryption_memory_before = measure_performance()[1]


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    start = time.time()

    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and file.filename.startswith('encrypted_'):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        with open(encrypted_path, 'rb') as enc_file:
            data = enc_file.read()

        nonce = data[:16]
        ciphertext = data[16:-16]
        provided_mac = data[-16:]

        if verify_mac(sender_shared_key, ciphertext, provided_mac):
            cipher = Cipher(algorithms.ChaCha20(receiver_shared_key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + filename[10:])

            with open(decrypted_path, 'wb') as dec_file:
                dec_file.write(plaintext)

            end = time.time()
            total_time = end - start

            with open('./analysis/performance_analysis.txt', 'a') as performance:
                performance.write("\nDecryption: {} second".format(total_time))

            return send_file(decrypted_path, as_attachment=True)

        else:
            print("Alert: Intruder altered the MAC address")
            exit(1)

    return redirect(request.url)


decryption_cpu_after = measure_performance()[0]
decryption_memory_after = measure_performance()[1]

decryption_cpu_result = decryption_cpu_after - decryption_cpu_before
decryption_memory_result = decryption_memory_after - decryption_memory_before

with open('./analysis/hardware_analysis.txt', 'a') as encryption_cpu:
    encryption_cpu.write("\n\nCPU Time (Decryption): {} second".format(decryption_cpu_result))

with open('./analysis/hardware_analysis.txt', 'a') as decryption_cpu:
    decryption_cpu.write("\nRAM Usage (Decryption): {} MB".format(decryption_memory_result))


if __name__ == '__main__':
    app.run(debug=True)