# api.py
import datetime
import json
from flask import Blueprint, request, current_app, url_for
from flask_login import current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User, Codes, ResPass, Groups, Beacons, UserGroups, GroupsMapping, Notifications, SentNotifications
from iqsms_rest import Gate
import random, string
import time
from .config import *
from .helpers import send_email, send_notification


def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password


auth_api = Blueprint('auth_api', __name__)


@auth_api.route('/api/auth')
def auth():
    '''
    ---
       get:
         summary: Вход
         parameters:
             - in: query
               name: email
               schema:
                 type: string
                 example: example2@gmail.com
               description: email
             - in: query
               name: password
               schema:
                 type: string
                 example: 123
               description: password
         responses:
           '200':
             description: Результат
             content:
               application/json:
                 schema:      # Request body contents
                   type: object
                   properties:
                       result:
                         type: boolean
                       token:
                         type: string
                       role:
                         type: integer
                       msg:
                         type: string
           '400':
             description: Не передан обязательный параметр
             content:
               application/json:
                 schema: ErrorSchema
           '401':
             description: Неверный пароль или пользователь не существует
             content:
               application/json:
                 schema: ErrorSchema
           '403':
             description: Пользователь заблокирован
             content:
               application/json:
                 schema: ErrorSchema
         tags:
           - mobile
        '''
    try:
        email = request.args.get('email')
        password = request.args.get('password')
        user = User.query.filter_by(email=email).first()
        print(User.query.filter_by().first().email)
        print(password)
        if user:
            msg = ''
            if user.confirmed == 0:
                msg = 'Номер телефона не подтверждкен'
            if user.status == 'blocked':
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'error': "USER BLOCKED",
                            'role': '',
                            'token': ''
                        }
                    ),
                    status=403,
                    mimetype='application/json'
                )
            if check_password_hash(user.password, password):
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'result': True,
                            'token': user.token,
                            'role': user.role,
                            'msg': msg
                        }
                    ),
                    status=200,
                    mimetype='application/json'
                )
            else:
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'result': 'INCORRECT PASSWORD',
                            'token': '',
                            'role': ''
                        }
                    ),
                    status=401,
                    mimetype='application/json'
                )
        else:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'result': 'USER DOES NOT EXIST',
                        'token': '',
                        'role': ''
                    }
                ),
                status=401,
                mimetype='application/json'
            )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/profile')
def profile():
    '''
    ---
       get:
         summary: Профиль
         parameters:
             - in: query
               name: token
               schema:
                 type: string
                 example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
                 description: token
         responses:
           '200':
             description: Результат
             content:
               application/json:
                 schema:      # Request body contents
                   type: object
                   properties:
                       id:
                         type: integer
                       email:
                         type: string
                       phone:
                         type: string
                       name:
                         type: string
                       status:
                         type: string
                       role:
                         type: integer
                       msg:
                         type: string
           '400':
             description: Не передан обязательный параметр
             content:
               application/json:
                 schema: ErrorSchema
           '401':
             description: Неверный токен
             content:
               application/json:
                 schema: ErrorSchema
           '403':
             description: Пользователь заблокирован
             content:
               application/json:
                 schema: ErrorSchema
         tags:
           - mobile
        '''
    try:
        token = request.args.get('token')
        user = User.query.filter_by(token=token).first()
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'USER DOES NOT EXIST'}
                ),
                status=403,
                mimetype='application/json'
            )
        msg = ''
        if user.confirmed == 0:
            msg = 'Номер телефона не подтверждкен'
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        return current_app.response_class(
            response=json.dumps(
                {
                    "id": user.id,
                    "email": user.email,
                    "phone": user.phone,
                    "name": user.name,
                    "status": user.status,
                    "role": user.role,
                    'msg': msg
                }
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/sign_up', methods=['GET', 'POST'])
def sign_up():
    '''
   ---
  post:
    summary: Регистрация
    requestBody:
       content:
         application/json:
             schema:
               type: object
               properties:
                  name:
                    type: string
                  email:
                    type: string
                  phone:
                    type: string
                  password:
                    type: string
               example:   # Sample object
                 name: Ivan
                 email: example@gmail.com
                 phone: 79151290130
                 password: 123
    responses:
      '200':
        description: Результат
        content:
          application/json:
            schema:      # Request body contents
              type: object
              properties:
                  result:
                    type: boolean
                  token:
                    type: string
      '400':
        description: Не передан обязательный параметр
        content:
          application/json:
            schema: ErrorSchema
      '401':
        description: Неверный токен
        content:
          application/json:
            schema: ErrorSchema
      '403':
        description: Пользователь заблокирован
        content:
          application/json:
            schema: ErrorSchema
    tags:
           - mobile
   '''
    email = request.json.get('email')
    phone = str(request.json.get('phone')).replace('(', '').replace(')', '').replace('-', '').replace('+', '').replace(
        ' ', '')
    name = request.json.get('name')
    password = request.json.get('password')
    if User.query.filter_by(phone=phone).first():
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'USER EXIST'
                }
            ),
            status=403,
            mimetype='application/json'
        )
    if User.query.filter_by(email=email).first():
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': False,
                    'error': f'USER EXIST'
                }
            ),
            status=403,
            mimetype='application/json'
        )
    token = generate_password_hash(str(phone), method='sha256').replace('sha256$', '')
    new_user = User(email=email, phone=phone, name=name,
                    password=generate_password_hash(str(password), method='sha256'),
                    status="active", token=token, registered=int(time.time()), role=0)
    db.session.add(new_user)
    db.session.commit()
    code = 1234  # random.randint(1001, 9999)
    new_code = Codes(code=code, phone=phone)
    db.session.add(new_code)
    db.session.commit()
    sender = Gate(SMS_LOGIN, SMS_PASSWORD)
    status = sender.send_message(phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'token': token
            }
        ),
        status=200,
        mimetype='application/json'
    )
    try:
        pass
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {
                    'error': f'ERROR: {e}!'
                }
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/check-code')
def check_code():
    '''
---
   get:
     summary: Подтверждение номера
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
         - in: query
           name: code
           schema:
             type: integer
             example: 1234
           description: code
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: boolean
                   user:
                     type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.query.filter_by(token=token).first()
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'result': 'USER DOES NOT EXIST',
                        'token': '',
                        'role': ''
                    }
                ),
                status=401,
                mimetype='application/json'
            )
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        code = request.args.get('code')
        if Codes.query.filter_by(phone=user.phone).all()[-1].code == code:
            _ = User.query.filter_by(token=token).update({'confirmed': 1})
            db.session.commit()
            return current_app.response_class(
                response=json.dumps(
                    {'status': True,
                     'user': token}
                ),
                status=200,
                mimetype='application/json'
            )
        else:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'status': False,
                        'error': "Invalid code"
                    }
                ),
                status=401,
                mimetype='application/json'
            )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/roles')
def roles():
    '''
    ---
   get:
     summary: Профиль
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   0:
                     type: string
                   1:
                     type: string
                   2:
                     type: string
     tags:
           - mobile
    '''
    return current_app.response_class(
        response=json.dumps(
            {
                0: 'Обычный пользователь',
                1: 'Локалный админ',
                2: 'Главный админ'
            }
        ),
        status=200,
        mimetype='application/json'
    )


@auth_api.route('/api/logout')
def logout():
    """
---
get:
  summary: Выйти из всех аккаунтов
  parameters:
      - in: query
        name: token
        schema:
          description: Токен
          type: string
          example: 5zqxZa16b0vEE1sx$9a74b2452862f8b0061a5356079f69c3b83af9aec7430d070901f745b984a3f9
        description: Токен
  responses:
    '200':
          description: Результат
          content:
            application/json:
              schema:      # Request body contents
                  type: object
                  properties:
                    status:
                        type: string
                  example:   # Sample object
                    status: ok
    '401':
      description: Не верный токен
      content:
        application/json:
          schema: ErrorSchema
    '400':
      description: Не передан обязательный параметр
      content:
        application/json:
          schema: ErrorSchema
  tags:
           - mobile
"""
    try:
        token = request.args.get('token')
        if not User.query.filter_by(token=token).first():
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'USER DOES NOT EXIST'}
                ),
                status=403,
                mimetype='application/json'
            )
        if User.query.filter_by(token=token).first().status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        else:
            user = User.query.filter_by(token=token).first()
            User.query.filter_by(token=token).update({'status': 'incative', "token": generate_password_hash(user.phone,
                                                                                                            method='sha256').replace(
                'sha256$', '')})
            db.session.commit()
            return current_app.response_class(
                response=json.dumps(
                    {
                        "status": True
                    }
                ),
                status=200,
                mimetype='application/json'
            )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/edit_profile', methods=['POST'])
def edit_profile():
    '''
---
   post:
     summary: Изменить профиль
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   phone:
                     type: string
                   email:
                     type: string
                   name:
                     type: string
                example:   # Sample object

                  phone: 79151290131
                  email: example2@gmail.com
                  name: Иван Иванов
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.query.filter_by(token=token).first()
        name = request.json.get('name')
        email = request.json.get('email')
        phone = str(request.json.get('phone')).replace('(', '').replace(')', '').replace('-', '').replace('+',
                                                                                                          '').replace(
            ' ', '')
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Incorrect TOKEN'}
                ),
                status=401,
                mimetype='application/json'
            )
        if User.query.filter_by(token=token).first().status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        if user.phone != phone:
            code = 1234  # random.randint(1001, 9999)
            new_code = Codes(code=code, phone=phone)
            db.session.add(new_code)
            db.session.commit()
            sender = Gate(SMS_LOGIN, SMS_PASSWORD)
            status = sender.send_message(phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
            _ = User.query.filter_by(id=user.id).update(
                {'name': name, 'phone': phone, 'email': email, 'confirmed': 0})
        else:
            _ = User.query.filter_by(id=user.id).update(
                {'name': name, 'email': email})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'status': f'ok'}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/res-pass', methods=['GET', 'POST'])
def res_pass():
    '''
   ---
   get:
     summary: Запросить сброс пароля
     parameters:
         - in: query
           name: phone
           schema:
             type: string
             example: 79151290130
           description: phone
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        phone = str(request.args.get('phone')).replace('(', '').replace(')', '').replace('-', '').replace('+',
                                                                                                          '').replace(
            ' ', '')
        print(phone)
        if not User.query.filter_by(phone=phone).first():
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'USER DOES NOT EXIST'}
                ),
                status=403,
                mimetype='application/json'
            )
        code = 1234  # random.randint(1001, 9999)
        new_code = ResPass(code=code, phone=phone)
        db.session.add(new_code)
        db.session.commit()
        sender = Gate(SMS_LOGIN, SMS_PASSWORD)
        status = sender.send_message(phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'status': f'ok'}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/check-code-res-pass')
def check_code_res_pass():
    '''
   ---
   get:
     summary: Проверить код для сброса пароля
     parameters:
         - in: query
           name: phone
           schema:
             type: string
             example: 79151290130
           description: phone
         - in: query
           name: code
           schema:
             type: integer
             example: 1234
           description: code
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: boolean
                   token:
                     type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        code = request.args.get('code')
        phone = request.args.get('phone')
        user = User.query.filter_by(phone=phone).first()
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'result': 'USER DOES NOT EXIST',
                        'token': '',
                        'role': ''
                    }
                ),
                status=401,
                mimetype='application/json'
            )
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        if ResPass.query.filter_by(phone=user.phone).all()[-1].code == code:
            return current_app.response_class(
                response=json.dumps(
                    {'status': True,
                     'token': user.token}
                ),
                status=200,
                mimetype='application/json'
            )
        else:
            return current_app.response_class(
                response=json.dumps(
                    {
                        'status': False,
                        'error': "Invalid code"
                    }
                ),
                status=401,
                mimetype='application/json'
            )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/set-password', methods=['POST'])
def set_password():
    '''
   ---
   post:
     summary: Задать пароль
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: oD7MgOrsO9hIVXa8$7552d24bf84b3eb71f8f185ce723409ec6e8a08c63f90789d6b7f389e738d952
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   password:
                     type: integer
                example:   # Sample object

                  password: 1234
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.query.filter_by(token=token).first()
        password = request.json.get('password')
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Incorrect TOKEN'}
                ),
                status=401,
                mimetype='application/json'
            )
        if User.query.filter_by(token=token).first().status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        _ = User.query.filter_by(id=user.id).update(
            {'password': password})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'status': f'ok'}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/api/send-phone-confirmation', methods=['POST'])
def send_phone_confirmation():
    '''
   ---
   get:
     summary: Отправить СМС подтверждение номера
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:
        
                   password:
                     type: integer
                example:   # Sample object
        
                  password: 1234
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   status:
                     type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.query.filter_by(token=token).first()
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Incorrect TOKEN'}
                ),
                status=401,
                mimetype='application/json'
            )
        if User.query.filter_by(token=token).first().status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': "USER BLOCKED"}
                ),
                status=403,
                mimetype='application/json'
            )
        code = 1234  # random.randint(1001, 9999)
        new_code = Codes(code=code, phone=user.phone)
        db.session.add(new_code)
        db.session.commit()
        sender = Gate(SMS_LOGIN, SMS_PASSWORD)
        status = sender.send_message(user.phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
        return current_app.response_class(
            response=json.dumps(
                {'status': f'ok'}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )


@auth_api.route('/beacon-detected', methods=['GET', 'POST'])
@auth_api.route('/api/beacon-detected', methods=['GET', 'POST'])
def beacon_detected():
    '''
    ---
   get:
     summary: Метка обнаружена
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
         - in: query
           name: uuid
           schema:
             type: string
             example: e5b9e3a6-27e2-4c36-a257-7698da5fc140
           description: uuid
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   success:
                     type: boolean
                   data:
                     type: object
                     properties:
                           pdf_url:
                             type: string
                           text:
                             type: string
                           title:
                             type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        uuid = request.args.get('uuid')
        token = request.args.get('token')

        beacon = Beacons.query.filter_by(uuid=uuid).first()
        if not beacon:
            return current_app.response_class(
                response=json.dumps(
                    {'success': False,
                     'error': 'BEACON NOT FOUND'}
                ),
                status=400,
                mimetype='application/json'
            )
        user = User.query.filter_by(token=token).first()
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'success': False,
                     'error': 'USER NOT FOUND'}
                ),
                status=401,
                mimetype='application/json'
            )

        if user.status == 'blocked':
            return current_app.response_class(
                response=json.dumps(
                    {'success': False,
                     'error': 'USER BLOCKED'}
                ),
                status=403,
                mimetype='application/json'
            )

        notifications = Notifications.query.filter_by(beacon=beacon.id).all()
        status = 'NOTHING TO SEND'
        return current_app.response_class(
            response=json.dumps(
                {
                    'success': True,
                    'data': {
                        "pdf_url": url_for('static', filename='files/' + '2.pdf'),
                        "text": uuid,
                        "title": 'Beacon detected'
                    }
                }
            ),
            status=200,
            mimetype='application/json'
        )

        for notification in notifications:
            if notification.time_start <= datetime.datetime.now() <= notification.time_finish:
                user_group = UserGroups.query.filter_by(id=notification.group).first()
                users = [i.user for i in GroupsMapping.query.filter_by(user_group=user_group.id).all()]
                if user.id in users:
                    if True:  # not SentNotifications.query.filter_by(notification=notification.id, user=user.id).first():
                        # status = send_notification(notification, deviceId)
                        new_record = SentNotifications(notification=notification.id, user=user.id,
                                                       time=int(time.time()))
                        db.session.add(new_record)
                        db.session.commit()

                        return current_app.response_class(
                            response=json.dumps(
                                {
                                    'success': True,
                                    'data': {
                                        "pdf_url": url_for('static', filename='files/' + notification.attachment),
                                        "text": notification.text,
                                        "title": notification.title
                                    }
                                }
                            ),
                            status=200,
                            mimetype='application/json'
                        )
        return current_app.response_class(
            response=json.dumps(
                {'success': False,
                 'status': status}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )



@auth_api.route('/api/all_beacons', methods=['GET', 'POST'])
def all_beacons():
    '''
       ---
   get:
     summary: Метка обнаружена
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:
                   success:
                     type: boolean
                   beacons:
                     type: array
                     items:
                       type: object
                       properties:
                           name:
                             type: string
                           uuid:
                             type: string
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
           - mobile
    '''
    try:
        token = request.args.get('token')
        user = User.query.filter_by(token=token).first()
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'success': False,
                     'error': 'USER NOT FOUND'}
                ),
                status=401,
                mimetype='application/json'
            )

        if user.status == 'blocked':
            return current_app.response_class(
                response=json.dumps(
                    {'success': False,
                     'error': 'USER BLOCKED'}
                ),
                status=403,
                mimetype='application/json'
            )
        beacons = Beacons.query.filter_by(group=user.group).all()
        guest = [
            {
                'uuid': user.tag,
                'name': 'Комната гостя'
            }
        ] if user.tag else []

        return current_app.response_class(
            response=json.dumps(
                {
                    'success': True,
                    'beacons': [
                                   {
                                       'uuid': i.uuid,
                                       'name': i.name
                                   } for i in beacons
                               ] + guest
                }
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )
