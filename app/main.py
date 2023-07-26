# _XiuCNs7:@xu
import json
from datetime import datetime, timedelta
from os import getcwd
from flask import Blueprint, render_template, request, send_from_directory, make_response, session, redirect, url_for, \
    current_app
from flask_login import login_required, current_user, login_user, logout_user
import os

from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from app.models import User, Groups, Beacons, UserGroups, GroupsMapping, Notifications, Codes, Texts, Backgrounds
from functools import wraps
from flask import current_app, request, jsonify
from iqsms_rest import Gate
import random
import time

from .api import generate_password
from .config import *
from .helpers import send_email


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        if not user:
            return current_app.response_class(
                response=json.dumps(
                    {'error': 'USER DOES NOT EXIST'}
                ),
                status=403,
                mimetype='application/json'
            )
        if user.status == "blocked":
            return current_app.response_class(
                response=json.dumps(
                    {'error': 'USER BLOCKED'}
                ),
                status=403,
                mimetype='application/json'
            )
        if user.role not in [1, 2]:
            return current_app.response_class(
                response=json.dumps(
                    {'error': 'PERMISSION DENIED'}
                ),
                status=403,
                mimetype='application/json'
            )
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(e)
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'ERROR: {e}!'}
                ),
                status=400,
                mimetype='application/json'
            )

    return wrapper


main = Blueprint('main', __name__)

CWD = '' # '/root/MeashStore/'


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/api/auth-admin')
def auth_admin():
    '''
    ---
       get:
         summary: Вход админа
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
             - in: query
               name: remember
               schema:
                 type: boolean
                 example: true
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
           - admin
        '''
    try:
        email = request.args.get('email')
        password = request.args.get('password')
        remember = True if request.args.get('remember') else False
        user = User.query.filter_by(email=email).first()
        if user:
            msg = ''
            if user.confirmed == 0:
                msg = 'Номер телефона не подтверждкен'
            if user.role not in [1, 2]:
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'error': "NOT ADMIN",
                            'role': '',
                            'token': ''
                        }
                    ),
                    status=400,
                    mimetype='application/json'
                )
            if user.status == 'blocked':
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'error': "USER BLOCKED",
                            'role': '',
                            'token': ''
                        }
                    ),
                    status=400,
                    mimetype='application/json'
                )
            if check_password_hash(user.password, password):
                login_user(user, remember=remember)
                return current_app.response_class(
                    response=json.dumps(
                        {
                            'result': True,
                            'token': user.generate_auth_token(),
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
                    status=400,
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
                status=400,
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


@main.route('/api/users', methods=['POST', 'GET'])
@login_required
def users():
    '''
    ---
   get:
     summary: Все пользователи
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search_query
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
                   users:
                     type: array
                     items:
                       type: object
                       properties:
                           id:
                             type: integer
                           name:
                             type: string
                           email:
                             type: string
                           phone:
                             type: string
                           phone_confirmed:
                             type: integer
                           status:
                             type: string
                           role:
                             type: string
                           network:
                             type: string
                           tag:
                             type: string
                   search_query:
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
       - admin
    '''
    users = []
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    if user.role == 2:
        query = User.query.filter(User.name.contains(search_query) |
                                  User.email.contains(search_query) |
                                  User.phone.contains(search_query))
        all_users = query.all()
    else:
        query = User.query.filter((User.name.contains(search_query) |
                                   User.email.contains(search_query) |
                                   User.phone.contains(search_query)) &
                                  (User.group == user.group) & (User.role != 2))
        all_users = query.all()
    for i in all_users:
        users.append({
            'id': i.id,
            'name': i.name,
            'email': i.email,
            'phone': i.phone,
            'phone_confirmed': i.confirmed,
            'status': 'Активный' if i.status == 'active' else 'Заблокирован',
            'role': 'Пользователь' if i.role == 0 else f'Админ сети {Groups.query.filter_by(id=i.group).first().name}' if i.role == 1 else 'Админ сервиса',
            'network': Groups.query.filter_by(id=i.group).first().name,
            'tag': i.tag
        })
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'users': users,
                'search_query': search_query,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-user', methods=['PUT'])
@login_required
def edit_user():
    '''
    ---
   put:
     summary: Редактировать пользователя
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                summary: имя аргумента(name, email, phone, tag)
                properties:
                   name:
                     type: string
                   email:
                     type: string
                   phone:
                     type: string
                   tag:
                     type: string
                   user_id:
                     type: integer
                example:   # Sample object
                  name: Тест
                  email: test1@gmail.com
                  phone: 79151290122
                  tag: D57092AC-DFAA-446C-8EF3-C81AA2815B5
                  user_id: 1
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
       - admin
    '''
    try:
        user_id = request.json['user_id']
        name = request.json['name']
        phone = request.json['phone']
        email = request.json['email']
        tag = request.json['tag']
        user = User.query.filter_by(id=user_id).first()
        if User.query.filter_by(email=email).first() and user.email != email:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Пользователь с таким Email адресом уже зарегистрирован'}
                ),
                status=200,
                mimetype='application/json'
            )
        if User.query.filter_by(phone=phone).first() and user.phone != phone:
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Пользователь с таким номером телефона уже зарегистрирован'}
                ),
                status=200,
                mimetype='application/json'
            )
        if user.phone != phone:
            _ = User.query.filter_by(id=user_id).update(
                {'name': name, 'phone': phone, 'email': email, 'tag': tag, 'confirmed': 0})
        else:
            _ = User.query.filter_by(id=user_id).update({'name': name, 'email': email, 'tag': tag, })
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
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


@main.route('/api/add-user', methods=['POST'])
@login_required
def add_user():
    '''
    ---
   post:
     summary: Добавить пользователя
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
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
                   tagId:
                     type: string
                   network:
                     type: integer
                   role:
                     type: integer
                example:   # Sample object

                  name: Тест
                  email: test1@gmail.com
                  phone: 79151290122
                  tagId: D57092AC-DFAA-446C-8EF3-C81AA2815B5
                  network: 1
                  role: 1
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
       - admin
    '''
    try:
        name = request.json['name']
        email = request.json['email']
        phone = str(request.json['phone']).replace('(', '').replace(')', '').replace('-', '').replace('+', '').replace(
            ' ', '')
        group = request.json['network']
        role = request.json['role']
        tagId = request.json['tagId'] if 'tagId' in dict(request.json) else ''
        if User.query.filter_by(email=email).first():
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Пользователь с таким Email адресом уже зарегистрирован'}
                ),
                status=200,
                mimetype='application/json'
            )
        if User.query.filter_by(phone=phone).first():
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'Пользователь с таким номером телефона уже зарегистрирован'}
                ),
                status=200,
                mimetype='application/json'
            )
        token = generate_password_hash(str(phone), method='sha256').replace('sha256$', '')
        password = generate_password(length=8)
        code = 1234  # random.randint(1001, 9999)
        new_code = Codes(code=code, phone=phone)
        db.session.add(new_code)
        db.session.commit()
        sender = Gate(SMS_LOGIN, SMS_PASSWORD)
        status = sender.send_message(phone, f'Ваш код для авторизации в приложении\n{code}', 'SMS DUCKOHT')
        send_email(email, 'Регистрация в приложении MeshStore',
                   f'Вы зарегистрированы в приложении MeshStore\nВаш логин: {email}\nПароль: {password}\nРекомендуем вам сменить пароль')
        new_user = User(email=email, phone=phone, name=name, group=group, role=role, confirmed=0,
                        password=generate_password_hash(str(password), method='sha256'),
                        status="active", token=token, registered=int(time.time()), tag=tagId)
        db.session.add(new_user)
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'Произошла ошибка при загрузке данных. Пожалуйста, попробуйте еще раз.'}
            ),
            status=200,
            mimetype='application/json'
        )


@main.route('/api/delete-user', methods=['DELETE'])
@login_required
def delete_user():
    '''
    ---
   delete:
     summary: Удалить пользователя
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: user
           schema:
             type: integer
             example: 10
           description: user
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
       - admin
    '''
    try:
        id = request.args.get('user')
        _ = User.query.filter_by(id=id).delete()
        db.session.commit()
        _ = GroupsMapping.query.filter_by(user=id).delete()
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'Произошла ошибка при удалении пользователя. Пожалуйста, попробуйте еще раз.'}
            ),
            status=400,
            mimetype='application/json'
        )


@main.route('/api/networks', methods=['POST', 'GET'])
@login_required
def networks():
    '''
    ---
   get:
     summary: Все сети
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
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
                   networks:
                     type: array
                     items:
                       type: object
                       properties:
                           id:
                             type: integer
                           name:
                             type: string
                           admins:
                             type: integer
                           users:
                             type: integer
                   search_query:
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
       - admin
    '''
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    if user.role != 2:
        return current_app.response_class(
            response=json.dumps(
                {
                    'error': 'NOT ALLOWED',
                }
            ),
            status=400,
            mimetype='application/json'
        )
    groups_ = []
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    query = Groups.query.filter(Groups.name.contains(search_query))
    all_groups = query.all()
    for i in all_groups:
        groups_.append({
            'id': i.id,
            'name': i.name,
            'admins': len(User.query.filter_by(role=1, group=i.id).all()),
            'users': len(User.query.filter_by(role=0, group=i.id).all())
        })
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'networks': groups_,
                'search_query': search_query,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-network', methods=['PUT'])
@login_required
def edit_network():
    '''
    ---
   put:
     summary: Редактировать сеть
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   name:
                     type: string
                   network:
                     type: integer
                example:   # Sample object

                  name: Test network
                  network: 1
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
       - admin
    '''
    try:
        user_id = request.json['network']
        new_value = request.json['name']
        _ = Groups.query.filter_by(id=user_id).update({'name': new_value})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
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


@main.route('/api/add-network', methods=['POST'])
@login_required
def add_network():
    '''
    ---
   post:
     summary: Добавить сеть
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   name:
                     type: string
                example:   # Sample object

                  name: Test network
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
       - admin
    '''
    try:
        name = request.json['name']
        new_user = Groups(name=name)
        db.session.add(new_user)
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=200,
            mimetype='application/json'
        )


@main.route('/api/delete-network/', methods=['DELETE'])
@login_required
def delete_network():
    '''
    ---
   delete:
     summary: Удалить сеть
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: network
           schema:
             type: integer
             example: 10
           description: network
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
       - admin
    '''
    try:
        id = request.args.get('network')
        _ = Groups.query.filter_by(id=id).delete()
        db.session.commit()
        _ = Beacons.query.filter_by(group=id).delete()
        db.session.commit()
        for i in UserGroups.query.filter_by(group=id).all():
            GroupsMapping.query.filter_by(user_group=id).delete()
            db.session.commit()
        _ = UserGroups.query.filter_by(group=id).delete()
        db.session.commit()
        _ = Notifications.query.filter_by(group=id).delete()
        db.session.commit()
        _ = User.query.filter_by(group=id, role=1).delete()
        db.session.commit()
        _ = User.query.filter_by(group=id, role=0).delete()
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
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


@main.route('/api/beacons', methods=['GET'])
@login_required
def beacons():
    '''
    ---
   get:
     summary: Все маяки
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
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
                   beacons:
                     type: array
                     items:
                       type: object
                       properties:
                           id:
                             type: integer
                           network:
                             type: string
                           name:
                             type: string
                           uuid:
                             type: string
                   search_query:
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
       - admin
    '''
    beacons_ = []
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    if Beacons.query.count() == 0:
        # Если база данных пуста, предоставляем сообщение или выполняем редирект
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': True,
                    'beacons': [],
                    'search_query': search_query,
                }
            ),
            status=200,
            mimetype='application/json'
        )
    if user.role == 1:
        query = Beacons.query.filter(Beacons.name.contains(search_query) & (Beacons.group == user.group))
    else:
        query = Beacons.query.filter(Beacons.name.contains(search_query))
    all_groups = query.all()
    for i in all_groups:
        if Groups.query.filter_by(id=i.group).first():
            beacons_.append({
                'id': i.id,
                'network': Groups.query.filter_by(id=i.group).first().name,
                'name': i.name,
                'uuid': i.uuid
            })
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'beacons': beacons_,
                'search_query': search_query,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-beacon', methods=['PUT'])
@login_required
def edit_beacon():
    '''
    ---
   put:
     summary: Редактировать маяк
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:
                   name:
                     type: string
                   uuid:
                     type: string
                   beacon:
                     type: integer
                example:   # Sample object
                  name: Ресторан
                  uuid: D57092AC-DFAA-446C-8EF3-C81AA2815B5
                  beacon: 1
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
       - admin
    '''
    try:
        name = request.json['name']
        user_id = request.json['beacon']
        uuid = request.json['uuid']
        _ = Beacons.query.filter_by(id=user_id).update({'name': name, 'uuid': uuid})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
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


@main.route('/api/add-beacon', methods=['POST'])
@login_required
def add_beacon():
    '''
    ---
   post:
     summary: Добавить маяк
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   name:
                     type: string
                   uuid:
                     type: string
                   network:
                     type: integer
                example:   # Sample object

                  name: Столовая
                  uuid: D57092AC-DFAA-446C-8EF3-C81AA2815B5
                  network: 1
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
       - admin
    '''
    try:
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        name = request.json['name']
        uuid = request.json['uuid']
        group = request.json['network'] if user.role == 2 else user.group
        new_user = Beacons(name=name, uuid=uuid, group=group)
        db.session.add(new_user)
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=200,
            mimetype='application/json'
        )


@main.route('/api/delete-beacon', methods=['DELETE'])
@login_required
def delete_beacon():
    '''
    ---
   delete:
     summary: Удалить маяк
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: beacon
           schema:
             type: integer
             example: 10
           description: beacon
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
       - admin
    '''
    try:
        id = request.args.get('beacon')
        _ = Beacons.query.filter_by(id=id).delete()
        db.session.commit()
        _ = Notifications.query.filter_by(beacon=id).delete()
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
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


@main.route('/api/user-groups', methods=['GET'])
@login_required
def user_groups():
    '''
    ---
   get:
     summary: Все группы пользователей
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
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
                   user_groups:
                     type: array
                     items:
                       type: object
                       properties:
                           id:
                             type: integer
                           network:
                             type: string
                           name:
                             type: string
                           users_ids:
                             type: array
                             items:
                               type: integer
                   search_query:
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
       - admin
    '''
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    user_groups_ = []
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    all_users = User.query.filter_by(
        group=user.group).all() if user.role == 1 else User.query.filter_by().all()
    if UserGroups.query.count() == 0:
        # Если база данных пуста, предоставляем сообщение или выполняем редирект
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': True,
                    'user_groups': user_groups_,
                    'search_query': search_query,
                }
            ),
            status=200,
            mimetype='application/json'
        )
    query = UserGroups.query.filter(UserGroups.name.contains(search_query) & (UserGroups.group == user.group))
    all_groups = query.all()
    for i in all_groups:
        user_groups_.append({
            'id': i.id,
            'network': Groups.query.filter_by(id=i.group).first().name,
            'name': i.name,
            'users_ids': [i.user for i in GroupsMapping.query.filter_by(user_group=i.id).all()]
        })
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'user_groups': user_groups_,
                'search_query': search_query,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/add-user-group', methods=['GET', 'POST'])
@login_required
def add_user_group():
    '''
    ---
   post:
     summary: Добавить группу пользователей
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:

                   name:
                     type: string
                   users:
                     type: array
                     items:
                       type: integer
                example:   # Sample object
                  users: [1, 2]
                  name: Test
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
       - admin
    '''
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    name = request.json.get('name')
    users = request.json.get('users')

    new_group = UserGroups(name=name, group=user.group)
    db.session.add(new_group)
    db.session.commit()

    for i in users:
        new_rec = GroupsMapping(user=i, user_group=new_group.id)
        db.session.add(new_rec)
        db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {'success': True}
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-user-group', methods=['PUT'])
@login_required
def edit_user_group():
    '''
    ---
   put:
     summary: Редактировать группу пользователей
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: group-id
           schema:
             type: integer
             example: 1
           description: group-id
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:
                   name:
                     type: string
                   users:
                     type: array
                     items:
                       type: integer
                example:   # Sample object
                  name: VIP клиенты
                  users: [1, 2, 3]
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
       - admin
    '''
    id = request.args.get('group-id')
    users = request.json.get('users')
    name = request.json.get('name')

    _ = UserGroups.query.filter_by(id=id).update({'name': name})
    db.session.commit()
    _ = GroupsMapping.query.filter_by(user_group=id).delete()
    db.session.commit()

    for i in users:
        new_rec = GroupsMapping(user=i, user_group=id)
        db.session.add(new_rec)
        db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {'success': True}
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/delete-user-group', methods=['DELETE'])
@login_required
def delete_user_group():
    '''
    ---
   delete:
     summary: Удалить группу пользователей
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: group-id
           schema:
             type: integer
             example: 1
           description: group-id
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
       - admin
    '''
    try:
        id = request.args.get('group-id')
        _ = UserGroups.query.filter_by(id=id).delete()
        db.session.commit()
        _ = GroupsMapping.query.filter_by(user_group=id).delete()
        db.session.commit()
        _ = Notifications.query.filter_by(user_group=id).delete()
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
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


@main.route('/api/notifications', methods=['GET'])
@login_required
def notifications():
    '''
    ---
   get:
     summary: Все уведомления
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
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
                   notifications:
                     type: array
                     items:
                       type: object
                       properties:
                           day:
                             type: integer
                           date:
                             type: string
                           len:
                             type: integer
                           notifications:
                             type: array
                             items:
                               type: object
                               properties:
                                   id:
                                     type: integer
                                   network:
                                     type: string
                                   beacon:
                                     type: object
                                     properties:
                                           id:
                                             type: integer
                                           name:
                                             type: string
                                   group:
                                     type: object
                                     properties:
                                           id:
                                             type: integer
                                           name:
                                             type: string
                                   day:
                                     type: integer
                                   start:
                                     type: string
                                   finish:
                                     type: string
                                   title:
                                     type: string
                                   text:
                                     type: string
                                   file:
                                     type: string
                                   length:
                                     type: object
                                     properties:
                                        length:
                                          type: integer
                                        measure:
                                          type: string
                   search_query:
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
       - admin
    '''
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    user_groups_ = {1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: []}
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    all_user_groups = UserGroups.query.filter_by(
        group=user.group).all() if user.role == 1 else UserGroups.query.filter_by().all()
    all_beacons = Beacons.query.filter_by(
        group=user.group).all() if user.role == 1 else Beacons.query.filter_by().all()
    if Notifications.query.count() == 0:
        notes = []
        for i in range(1, 8):
            notes.append({
                'day': i,
                'date': (datetime.today() + timedelta(days=i - 1)).strftime('%Y-%m-%d'),
                'len': len(user_groups_[i]),
                'notifications': user_groups_[i]
            })
        # Если база данных пуста, предоставляем сообщение или выполняем редирект
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': True,
                    'notifications': notes,
                    'search_query': search_query,
                }
            ),
            status=200,
            mimetype='application/json'
        )
    query = Notifications.query.filter(
        (Notifications.group == user.group) & (Notifications.time_start >= datetime.now().date()))
    all_groups = query.all()
    for i in all_groups:
        start = i.time_start.strftime('%Y-%m-%d %H:%M')
        finish = i.time_finish.strftime('%Y-%m-%d %H:%M')
        length = (i.time_finish - i.time_start).seconds // 60 + (i.time_finish - i.time_start).days * 24 * 60
        ed_izm = 'мин'
        print(length, length // 60 // 24 > 0)
        if length // 60 // 24 > 0:
            length = length // 60 // 24
            ed_izm = 'дней'
        elif length // 60 > 0:
            length = length // 60
            ed_izm = 'часов'
        print(length, ed_izm)
        if (i.time_start.date() - datetime.now().date()).days + 1 in user_groups_:
            user_groups_[(i.time_start.date() - datetime.now().date()).days + 1].append({
                'id': i.id,
                'network': Groups.query.filter_by(id=i.group).first().name,
                'beacon': {
                    'id': i.beacon,
                    'name': Beacons.query.filter_by(id=i.beacon).first().name if Beacons.query.filter_by(
                        id=i.beacon).first() else 'Номера гостей'
                },
                'group': {
                    'id': i.user_group,
                    'name': UserGroups.query.filter_by(id=i.user_group).first().name
                },
                'day': (i.time_start.date() - datetime.now().date()).days + 1,
                'start': start,
                'finish': finish,
                'title': i.title,
                'text': i.text,
                'file': i.attachment,
                'length': {
                    'length': length,
                    'measure': ed_izm
                }
            })
    notes = []
    for i in range(1, 8):
        notes.append({
            'day': i,
            'date': (datetime.today() + timedelta(days=i - 1)).strftime('%Y-%m-%d'),
            'len': len(user_groups_[i]),
            'notifications': user_groups_[i]
        })
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'notifications': notes,
                'search_query': search_query,
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/notification', methods=['GET'])
@login_required
def notification():
    '''
    ---
   get:
     summary: Уведомление
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: id
           schema:
             type: integer
             example: 1
           description: notification
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
                   network:
                     type: string
                   beacon:
                     type: object
                     properties:
                           id:
                             type: integer
                           name:
                             type: string
                   group:
                     type: object
                     properties:
                           id:
                             type: integer
                           name:
                             type: string
                   day:
                     type: integer
                   start:
                     type: string
                   finish:
                     type: string
                   title:
                     type: string
                   text:
                     type: string
                   file:
                     type: string
                   length:
                     type: object
                     properties:
                        length:
                          type: integer
                        measure:
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
       - admin
    '''
    token = request.args.get('token')
    id = request.args.get('id')
    user = User.verify_auth_token(token)
    note = Notifications.query.filter_by(id=id).first()
    if not note:
        return current_app.response_class(
            response=json.dumps(
                {
                    'error': 'Notification not found'
                }
            ),
            status=400,
            mimetype='application/json'
        )
    i = note
    start = i.time_start.strftime('%Y-%m-%d %H:%M')
    finish = i.time_finish.strftime('%Y-%m-%d %H:%M')
    length = (i.time_finish - i.time_start).seconds // 60 + (i.time_finish - i.time_start).days * 24 * 60
    ed_izm = 'мин'
    if length // 60 // 24 > 0:
        length = length // 60 // 24
        ed_izm = 'дней'
    elif length // 60 > 0:
        length = length // 60
        ed_izm = 'часов'
    data = {
        'id': i.id,
        'network': Groups.query.filter_by(id=i.group).first().name,
        'beacon': {
            'id': i.beacon,
            'name': Beacons.query.filter_by(id=i.beacon).first().name if Beacons.query.filter_by(
                id=i.beacon).first() else 'Номера гостей'
        },
        'group': {
            'id': i.user_group,
            'name': UserGroups.query.filter_by(id=i.user_group).first().name
        },
        'day': (i.time_start.date() - datetime.now().date()).days + 1,
        'start': start,
        'finish': finish,
        'title': i.title,
        'text': i.text,
        'file': i.attachment,
        'length': {
            'length': length,
            'measure': ed_izm
        }
    }
    return current_app.response_class(
        response=json.dumps(
            data
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/add-notification', methods=['GET', 'POST'])
@login_required
def add_notification():
    '''
    ---
   post:
     summary: Добавить уведомление
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
     requestBody:
         content:
           multipart/form-data:
             schema:
               type: object
               properties:
                 beacon:
                   type: integer
                   description: Example; 1
                 group:
                   type: integer
                   description: Example; 1
                 start:
                   type: string
                   description: Example; 2023-05-24T09:30
                 finish:
                   type: string
                   description: Example; 2023-05-24T09:30
                 title:
                   type: string
                   description: Example; Test
                 text:
                   type: string
                   description: Example; Test
                 file:
                   type: string
                   format: binary
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
       - admin
    '''
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    beacon = int(request.form.get('beacon'))
    group = int(request.form.get('group'))
    start = datetime.strptime(request.form.get('start'), '%Y-%m-%dT%H:%M') # request.form.get('start')
    finish = datetime.strptime(request.form.get('finish'), '%Y-%m-%dT%H:%M')
    title = request.form.get('title')
    text = request.form.get('text')
    if request.files:
        file = request.files['file']
    else:
        file = None
    new_note = Notifications(group=user.group, beacon=beacon, user_group=group, time_start=start,
                             time_finish=finish, text=text, title=title)
    db.session.add(new_note)
    db.session.commit()
    if file:
        filename = str(new_note.id) + '.' + file.filename.split('.')[-1]
        file.save(f'{CWD}app/static/files/' + filename)
        _ = Notifications.query.filter_by(id=new_note.id).update({'attachment': filename})
        db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {'success': True}
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-notification', methods=['PUT'])
@login_required
def edit_notification():
    '''
    ---
   put:
     summary: Редактировать уведомление
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: notification
           schema:
             type: integer
             example: 1
           description: notification ID
     requestBody:
         content:
           multipart/form-data:
             schema:
               type: object
               properties:
                 beacon:
                   type: integer
                   description: Example; 1
                 group:
                   type: integer
                   description: Example; 1
                 start:
                   type: string
                   description: Example; 2023-05-23T09:30
                 finish:
                   type: string
                   description: Example; 2023-05-24T09:30
                 title:
                   type: string
                   description: Example; Test
                 text:
                   type: string
                   description: Example; Test
                 file:
                   type: string
                   format: binary
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
       - admin
    '''
    id = request.args.get('notifications')
    beacon = int(request.form.get('beacon'))
    group = int(request.form.get('group'))
    start = datetime.strptime(request.form.get('start'), '%Y-%m-%dT%H:%M')
    finish = datetime.strptime(request.form.get('finish'), '%Y-%m-%dT%H:%M')
    title = request.form.get('title')
    text = request.form.get('text')
    if request.files:
        file = request.files['file']
    else:
        file = None
    _ = Notifications.query.filter_by(id=id).update({'beacon': beacon, 'user_group': group, 'time_start': start,
                                                     'time_finish': finish, 'text': text, 'title': title})
    db.session.commit()
    if file:
        filename = str(id) + '.' + file.filename.split('.')[-1]
        file.save(f'{CWD}app/static/files/' + filename)
        _ = Notifications.query.filter_by(id=id).update({'attachment': filename})
        db.session.commit()

    return current_app.response_class(
        response=json.dumps(
            {'success': True}
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/delete_notification', methods=['DELETE'])
@login_required
def delete_notification():
    '''
    ---
   delete:
     summary: Удалить уведомление
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
           description: token
         - in: query
           name: notification-id
           schema:
             type: integer
             example: 1
           description: notification-id
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
       - admin
    '''
    try:
        id = request.args.get('notification-id')
        _ = Notifications.query.filter_by(id=id).delete()
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
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


@main.route('/api/settings', methods=['GET'])
@login_required
def settings():
    '''
    ---
   get:
     summary: Настройки
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: eyJpZCI6MX0.ZLnd2g.Fk1Z_piqblOU6wqttWaAXVov8Ik
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
                   data:
                     type: object
                     properties:
                       screensaver_text_ru:
                         type: object
                         properties:
                               title:
                                 type: string
                               text:
                                 type: string
                       screensaver_image_ru:
                         type: object
                         properties:
                               filename:
                                 type: string
                               link:
                                 type: string
                       screensaver_text_en:
                         type: object
                         properties:
                               title:
                                 type: string
                               text:
                                 type: string
                       screensaver_image_en:
                         type: object
                         properties:
                               filename:
                                 type: string
                               link:
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
       - admin
    '''
    try:
        token = request.args.get('token')
        user = User.verify_auth_token(token)
        return current_app.response_class(
            response=json.dumps(
                {
                    'success': True,
                    'data': {
                        'screensaver_text_ru': {
                            'title': Texts.query.filter_by(name='screensaver-text-ru',
                                                           network=user.group).first().title if Texts.query.filter_by(
                                name='screensaver-text-ru', network=user.group).first() else '',
                            'text': Texts.query.filter_by(name='screensaver-text-ru',
                                                          network=user.group).first().text if Texts.query.filter_by(
                                name='screensaver-text-ru', network=user.group).first() else ''
                        },
                        'screensaver_image_ru': {
                            'filename': Backgrounds.query.filter_by(
                                name='screensaver-image-ru',
                                network=user.group).first().file if Backgrounds.query.filter_by(
                                name='screensaver-image-ru', network=user.group).first() else '',
                            'link': url_for('static',
                                            filename=f"app/{Backgrounds.query.filter_by(name='screensaver-image-ru').first().file}") if Backgrounds.query.filter_by(
                                name='screensaver-image-ru').first() else ''
                        },
                        'screensaver_text_en': {
                            'title': Texts.query.filter_by(name='screensaver-text-en',
                                                           network=user.group).first().title if Texts.query.filter_by(
                                name='screensaver-text-en', network=user.group).first() else '',
                            'text': Texts.query.filter_by(name='screensaver-text-en',
                                                          network=user.group).first().text if Texts.query.filter_by(
                                name='screensaver-text-en', network=user.group).first() else ''
                        },
                        'screensaver_image_en': {
                            'filename': Backgrounds.query.filter_by(
                                name='screensaver-image-en',
                                network=user.group).first().file if Backgrounds.query.filter_by(
                                name='screensaver-image-en', network=user.group).first() else '',
                            'link': url_for('static',
                                            filename=f"app/{Backgrounds.query.filter_by(name='screensaver-image-en', network=user.group).first().file}") if Backgrounds.query.filter_by(
                                name='screensaver-image-en', network=user.group).first() else ''
                        },
                    }
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


@main.route('/api/update-background', methods=['PATCH'])
@login_required
def update_background():
    '''
        ---
       patch:
         summary: Редактировать фон
         parameters:
             - in: query
               name: token
               schema:
                 type: string
                 example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
               description: token
         requestBody:
             content:
               multipart/form-data:
                 schema:
                   type: object
                   properties:
                     name:
                       type: string
                       description: Example; screensaver-image-en
                     file:
                       type: string
                       format: binary
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
           - admin
        '''
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    name = request.form.get('name')
    if Backgrounds.query.filter_by(name=name, network=user.group).first():
        id = Backgrounds.query.filter_by(name=name, network=user.group).first().id
    else:
        new_background = Backgrounds(name=name, network=user.group)
        db.session.add(new_background)
        db.session.commit()
        id = new_background.id
    file = request.files['file']
    if file:
        filename = name + str(id) + '.' + file.filename.split('.')[-1]
        file.save(f'{CWD}app/static/app/' + filename)
        _ = Backgrounds.query.filter_by(id=id).update({'file': filename})
        db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {'success': True}
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/update-text', methods=['PATCH'])
@login_required
def update_text():
    '''
        ---
       patch:
         summary: Редактировать текст
         parameters:
             - in: query
               name: token
               schema:
                 type: string
                 example: eyJpZCI6MX0.ZLpqAg.CtaNAVLpWRvUBlWsPYCFwx4YOqI
               description: token
         requestBody:
             content:
               application/json:
                 schema:      # Request body contents
                   type: object
                   properties:
                     name:
                       type: string
                       description: Example; screensaver-text-en
                     title:
                       type: string
                     text:
                       type: string
                   example:
                       name: screensaver-text-en
                       title: Title
                       text: Text
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
           - admin
        '''
    token = request.args.get('token')
    user = User.verify_auth_token(token)
    name = request.json.get('name')
    title = request.json.get('title')
    text = request.json.get('text')
    if Texts.query.filter_by(name=name, network=user.group).first():
        Texts.query.filter_by(name=name, network=user.group).update({'title': title, 'text': text})
        db.session.commit()
    else:
        new_text = Texts(name=name, network=user.group, title=title, text=text)
        db.session.add(new_text)
        db.session.commit()
    return current_app.response_class(
        response=json.dumps(
            {'success': True}
        ),
        status=200,
        mimetype='application/json'
    )
