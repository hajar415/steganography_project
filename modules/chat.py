from flask import Flask, render_template, request, jsonify, session
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
import random
from cryptography.fernet import InvalidToken
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app)

# Stockage temporaire des passphrases (à remplacer par une DB en production)
message_passphrases = {}
failed_attempts = {}

def generate_random_alias():
    """Génère un alias aléatoire pour l'anonymat"""
    adjectives = ["Rouge", "Silencieux", "Crypté", "Mystère", "Ombre"]
    nouns = ["Panda", "Phantom", "Ninja", "Agent", "Byte"]
    return f"{random.choice(adjectives)}-{random.choice(nouns)}-{random.randint(100, 999)}"

@app.route('/')
def index():
    if 'user_alias' not in session:
        session['user_alias'] = generate_random_alias()
    return render_template('chat.html')

def process_content(content, passphrase, is_file=False, cover_image=None, filename=None, filetype=None):
    """Chiffre et cache le contenu dans une image"""
    try:
        key = base64.urlsafe_b64encode(sha256(passphrase.encode()).digest())
        fernet = Fernet(key)

        # Prépare les métadonnées si c'est un fichier
        if is_file and filename and filetype:
            metadata = {
                'filename': filename,
                'filetype': filetype
            }
            # Ajouter les métadonnées au contenu à chiffrer
            content_with_meta = json.dumps({
                'metadata': metadata,
                'content': base64.b64encode(content).decode('utf-8')
            }).encode()
            encrypted_content = fernet.encrypt(content_with_meta)
        else:
            encrypted_content = fernet.encrypt(content if is_file else content.encode())

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
        message_passphrases[message_id] = passphrase  # Stockage sécurisé à implémenter

        return img_str, message_id

    except Exception as e:
        raise Exception(f"Erreur de traitement: {str(e)}")

@socketio.on('send_message')
def handle_send_message(data):
    try:
        if 'user_alias' not in session:
            session['user_alias'] = generate_random_alias()

        is_file = data.get('is_file', False)
        passphrase = data.get('passphrase')
        cover_image = data.get('cover_image')

        if not passphrase or len(passphrase) < 8:
            emit('error', {'message': 'Passphrase invalide (minimum 8 caractères)'}, room=request.sid)
            return

        if is_file:
            file_data = base64.b64decode(data['file_data'])
            filename = data.get('filename', 'fichier_secure')
            filetype = data.get('filetype', 'application/octet-stream')
            img_str, message_id = process_content(
                file_data, 
                passphrase, 
                is_file=True, 
                cover_image=cover_image,
                filename=filename,
                filetype=filetype
            )
        else:
            message = data['message']
            img_str, message_id = process_content(message, passphrase, cover_image=cover_image)

        # Send to other clients
        emit('receive_message', {
            'image': img_str,
            'sender': session['user_alias'],
            'message_id': message_id,
            'is_file': is_file,
            'filename': data.get('filename'),
            'filetype': data.get('filetype'),
            'timestamp': datetime.now().isoformat()
        }, broadcast=True, include_self=False)

        # Send confirmation to the sender
        emit('message_sent', {
            'status': 'success',
            'message': 'Message envoyé avec succès',
            'image': img_str,
            'sender': session['user_alias'],
            'message_id': message_id,
            'is_file': is_file,
            'filename': data.get('filename'),
            'filetype': data.get('filetype'),
            'timestamp': datetime.now().isoformat()
        }, room=request.sid)

    except Exception as e:
        emit('error', {'message': str(e)}, room=request.sid)

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        message_id = data.get('message_id')
        
        # Vérification des tentatives échouées
        if message_id and failed_attempts.get(message_id, 0) >= 3:
            return jsonify({
                'status': 'error',
                'message': 'Trop de tentatives échouées. Veuillez réessayer plus tard.'
            })

        image_data = data['image'].split(",")[1] if "," in data['image'] else data['image']
        passphrase = data['passphrase']

        if not passphrase:
            return jsonify({'status': 'error', 'message': 'Passphrase requise'})

        key = base64.urlsafe_b64encode(sha256(passphrase.encode()).digest())
        fernet = Fernet(key)

        image_bytes = base64.b64decode(image_data)
        image = Image.open(BytesIO(image_bytes))
        encrypted_content = lsb.reveal(image).encode('latin-1')

        try:
            decrypted_content = fernet.decrypt(encrypted_content)
            
            # Vérifier si le contenu décrypté est au format JSON (contient des métadonnées)
            try:
                content_json = json.loads(decrypted_content)
                if 'metadata' in content_json and 'content' in content_json:
                    metadata = content_json['metadata']
                    original_filename = metadata.get('filename', 'fichier_secure')
                    original_filetype = metadata.get('filetype', 'application/octet-stream')
                    file_content = base64.b64decode(content_json['content'])
                    
                    return jsonify({
                        'status': 'success',
                        'is_file': True,
                        'file_data': base64.b64encode(file_content).decode(),
                        'filename': original_filename,
                        'filetype': original_filetype
                    })
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Si ce n'est pas du JSON, c'est soit un message texte, soit un fichier sans métadonnées
                pass
                
            # Traitement standard pour les messages texte ou fichiers sans métadonnées
            if data.get('is_file'):
                return jsonify({
                    'status': 'success',
                    'is_file': True,
                    'file_data': base64.b64encode(decrypted_content).decode(),
                    'filename': data.get('filename', 'fichier_secure'),
                    'filetype': data.get('filetype', 'application/octet-stream')
                })
            else:
                return jsonify({
                    'status': 'success',
                    'message': decrypted_content.decode(),
                    'is_file': False
                })
                
        except InvalidToken:
            if message_id:
                failed_attempts[message_id] = failed_attempts.get(message_id, 0) + 1
            return jsonify({
                'status': 'error',
                'message': 'Passphrase incorrecte'
            })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
