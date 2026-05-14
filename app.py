from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

def caesar_cipher(text, shift, mode='encrypt'):
    if not text:
        return ""
    
    shift = shift % 26
    if mode == 'decrypt':
        shift = -shift
    
    result = []
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + shift) % 26
            result.append(chr(shifted + ascii_offset))
        else:
            result.append(char)
    return ''.join(result)

message_history = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/process', methods=['POST'])
def process_text():
    data = request.json
    plain_text = data.get('text', '')
    shift = int(data.get('shift', 3))
    mode = data.get('mode', 'encrypt')
    
    if mode == 'encrypt':
        cipher_text = caesar_cipher(plain_text, shift, 'encrypt')
    else:
        cipher_text = caesar_cipher(plain_text, shift, 'decrypt')
    
    if plain_text.strip():
        message_history.insert(0, {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'plain': plain_text[:50],
            'cipher': cipher_text[:50],
            'shift': shift,
            'mode': mode
        })
        while len(message_history) > 50:
            message_history.pop()
    
    return jsonify({
        'result': cipher_text,
        'history': message_history[:10]
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify({'history': message_history[:10]})

@app.route('/api/clear', methods=['POST'])
def clear_history():
    global message_history
    message_history = []
    return jsonify({'status': 'cleared'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
