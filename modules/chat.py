from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit 
import base64
from io import BytesIO
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import os
from hashlib import sha256
import uuid
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

message_passphrases = {}

@app.route('/')
def index():
    return render_template('chat.html')

def process_content(content, passphrase, is_file=False, cover_image=None):
    """Chiffre et cache le contenu dans une image"""
    try:
        key = base64.urlsafe_b64encode(sha256(passphrase.encode()).digest())
        fernet = Fernet(key)

        if is_file:
            encrypted_content = fernet.encrypt(content)
        else:
            encrypted_content = fernet.encrypt(content.encode())

        # Utiliser l'image fournie par l'utilisateur ou l'image par défaut
        if cover_image:
            cover_bytes = base64.b64decode(cover_image)
            cover_image_obj = Image.open(BytesIO(cover_bytes))
        else:
            cover_image_obj = Image.open("base.png")

        secret_image = lsb.hide(cover_image_obj, encrypted_content.decode('latin-1'))
        buffer = BytesIO()
        secret_image.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()

        message_id = str(uuid.uuid4())
        message_passphrases[message_id] = passphrase

        return img_str, message_id

    except Exception as e:
        raise Exception(f"Erreur de traitement: {str(e)}")

@socketio.on('send_message')
def handle_send_message(data):
    try:
        is_file = data.get('is_file', False)
        sender = data['sender']
        passphrase = data.get('passphrase')
        cover_image = data.get('cover_image')

        if not passphrase:
            emit('error', {'message': 'Passphrase required'}, room=request.sid)
            return

        if is_file:
            file_data = base64.b64decode(data['file_data'])
            img_str, message_id = process_content(file_data, passphrase, is_file=True, cover_image=cover_image)
        else:
            message = data['message']
            img_str, message_id = process_content(message, passphrase, cover_image=cover_image)

        emit('receive_message', {
            'image': img_str,
            'sender': sender,
            'message_id': message_id,
            'is_file': is_file,
            'filename': data.get('filename'),
            'filetype': data.get('filetype'),
            'timestamp': datetime.now().isoformat()
        }, broadcast=True, include_self=False)

        emit('message_sent', {
            'sender': sender,
            'is_file': is_file,
            'filename': data.get('filename'),
            'timestamp': datetime.now().isoformat()
        }, room=request.sid)

    except Exception as e:
        emit('error', {'message': str(e)}, room=request.sid)

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        image_data = data['image'].split(",")[1] if "," in data['image'] else data['image']
        message_id = data['message_id']
        passphrase = data['passphrase']

        if not passphrase:
            return jsonify({'status': 'error', 'message': 'Passphrase required'})

        key = base64.urlsafe_b64encode(sha256(passphrase.encode()).digest())
        fernet = Fernet(key)

        image_bytes = base64.b64decode(image_data)
        image = Image.open(BytesIO(image_bytes))
        encrypted_content = lsb.reveal(image).encode('latin-1')

        decrypted_content = fernet.decrypt(encrypted_content)

        if data.get('is_file'):
            return jsonify({
                'status': 'success',
                'is_file': True,
                'file_data': base64.b64encode(decrypted_content).decode(),
                'filename': data['filename'],
                'filetype': data['filetype']
            })
        else:
            return jsonify({
                'status': 'success',
                'message': decrypted_content.decode(),
                'is_file': False
            })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0')
