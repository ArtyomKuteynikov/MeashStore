# _XiuCNs7:@xu
import json
from datetime import datetime
from os import getcwd
from flask import Blueprint, render_template, request, send_from_directory, make_response, session, redirect, url_for, \
    current_app
from flask_login import login_required, current_user
import os

from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from app.models import User, Groups, Beacons, UserGroups, GroupsMapping, Notifications, Codes
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
        print(token)
        user = User.query.filter_by(token=token).first()
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
            return current_app.response_class(
                response=json.dumps(
                    {'error': f'ERROR: {e}!'}
                ),
                status=400,
                mimetype='application/json'
            )

    return wrapper


main = Blueprint('main', __name__)

CWD = ''  # '/root/MeashStore/'


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
        user = User.query.filter_by(email=email).first()
        print(User.query.filter_by().first().email)
        print(password)
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
                    status=403,
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search_query
         - in: query
           name: page
           schema:
             type: integer
             example: 1
           description: page
         - in: query
           name: per-page
           schema:
             type: integer
             example: 10
           description: per-page
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
                   next_page:
                     type: string
                   prev_page:
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
    user = User.query.filter_by(token=token).first()
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    page = request.args.get('page', 1, type=int)  # Получаем значение параметра 'page' из URL
    per_page = request.args.get('per-page', 10, type=int)
    if user.role == 2:
        query = User.query.filter(User.name.contains(search_query) |
                                  User.email.contains(search_query) |
                                  User.phone.contains(search_query))
        all_users = query.paginate(page=page, per_page=per_page)
    else:
        query = User.query.filter((User.name.contains(search_query) |
                                   User.email.contains(search_query) |
                                   User.phone.contains(search_query)) &
                                  (User.group == user.group) & (User.role != 2))
        all_users = query.paginate(page=page, per_page=per_page)
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
                'next_page': all_users.next_num if all_users.has_next else None,
                'prev_page': all_users.prev_num if all_users.has_prev else None
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-user', methods=['POST'])
@login_required
def edit_tag():
    '''
    ---
   post:
     summary: Редактировать пользователя
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
                summary: имя аргумента(name, email, phone, tag)
                properties:
                   arg_name:
                     type: string
                   user_id:
                     type: integer
                   new_value:
                     type: string
                example:   # Sample object

                  arg_name: name // введите имя аргумента(name, email, phone, tag)
                  user_id: 1
                  new_value: Петр Иванов
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
        arg_name = request.json['arg_name']
        user_id = request.json['user_id']
        new_value = request.json['new_value']
        if arg_name == 'phone':
            _ = User.query.filter_by(id=user_id).update({arg_name: new_value, 'confirmed': 0})
        else:
            _ = User.query.filter_by(id=user_id).update({arg_name: new_value})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        print(e)
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
        print(123)
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
        print(e)
        return current_app.response_class(
            response=json.dumps(
                {'error': f'Произошла ошибка при загрузке данных. Пожалуйста, попробуйте еще раз.'}
            ),
            status=200,
            mimetype='application/json'
        )


@main.route('/api/delete-user', methods=['GET'])
@login_required
def delete_user():
    '''
    ---
   get:
     summary: Удалить пользователя
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
     summary: Все группы
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
         - in: query
           name: page
           schema:
             type: integer
             example: 1
           description: page
         - in: query
           name: per-page
           schema:
             type: integer
             example: 10
           description: per-page
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
                   next_page:
                     type: string
                   prev_page:
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
    groups_ = []
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    page = request.args.get('page', 1, type=int)  # Получаем значение параметра 'page' из URL
    query = Groups.query.filter(Groups.name.contains(search_query))
    per_page = request.args.get('per-page', 10, type=int)
    all_groups = query.paginate(page=page, per_page=per_page)
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
                'next_page': all_groups.next_num if all_groups.has_next else None,
                'prev_page': all_groups.prev_num if all_groups.has_prev else None
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-network', methods=['POST'])
@login_required
def edit_network():
    '''
    ---
   post:
     summary: Редактировать сеть
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
        print(e)
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
        print(e)
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=200,
            mimetype='application/json'
        )


@main.route('/api/delete-network/', methods=['GET', 'POST'])
@login_required
def delete_network():
    '''
    ---
   get:
     summary: Удалить сеть
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
         - in: query
           name: page
           schema:
             type: integer
             example: 1
           description: page
         - in: query
           name: per-page
           schema:
             type: integer
             example: 10
           description: per-page
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
                   next_page:
                     type: string
                   prev_page:
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
    user = User.query.filter_by(token=token).first()
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    page = request.args.get('page', 1, type=int)  # Получаем значение параметра 'page' из URL
    per_page = request.args.get('per-page', 10, type=int)
    if Beacons.query.count() == 0:
        # Если база данных пуста, предоставляем сообщение или выполняем редирект
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': True,
                    'beacons': [],
                    'search_query': search_query,
                    'next_page': None,
                    'prev_page': None
                }
            ),
            status=200,
            mimetype='application/json'
        )
    query = Beacons.query.filter(Beacons.name.contains(search_query) & (Beacons.group == user.group))
    all_groups = query.paginate(page=page, per_page=per_page)
    for i in all_groups:
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
                'next_page': all_groups.next_num if all_groups.has_next else None,
                'prev_page': all_groups.prev_num if all_groups.has_prev else None
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/api/edit-beacon', methods=['POST'])
@login_required
def edit_beacon():
    '''
    ---
   post:
     summary: Редактировать маяк
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

                   arg-name:
                     type: string
                   beacon:
                     type: integer
                   new-value:
                     type: string
                example:   # Sample object

                  arg-name: name
                  beacon: 1
                  new-value: Test
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
        arg_name = request.json['arg-name']
        user_id = request.json['beacon']
        new_value = request.json['new-value']
        _ = Beacons.query.filter_by(id=user_id).update({arg_name: new_value})
        db.session.commit()
        return current_app.response_class(
            response=json.dumps(
                {'success': True}
            ),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        print(e)
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
        user = User.query.filter_by(token=token).first()
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
        print(e)
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=200,
            mimetype='application/json'
        )


@main.route('/api/delete-beacon', methods=['GET', 'POST'])
@login_required
def delete_beacon():
    '''
    ---
   get:
     summary: Удалить маяк
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
         - in: query
           name: page
           schema:
             type: integer
             example: 1
           description: page
         - in: query
           name: per-page
           schema:
             type: integer
             example: 10
           description: per-page
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
                   user-groups:
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
                   next_page:
                     type: string
                   prev_page:
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
    user = User.query.filter_by(token=token).first()
    user_groups_ = []
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    page = request.args.get('page', 1, type=int)  # Получаем значение параметра 'page' из URL
    all_users = User.query.filter_by(
        group=user.group).all() if user.role == 1 else User.query.filter_by().all()
    if UserGroups.query.count() == 0:
        # Если база данных пуста, предоставляем сообщение или выполняем редирект
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': True,
                    'user-groups': user_groups_,
                    'search_query': search_query,
                    'next_page': None,
                    'prev_page': None
                }
            ),
            status=200,
            mimetype='application/json'
        )
    query = UserGroups.query.filter(UserGroups.name.contains(search_query) & (UserGroups.group == user.group))
    all_groups = query.paginate(page=page, per_page=5)
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
                'user-groups': user_groups_,
                'search_query': search_query,
                'next_page': all_groups.next_num if all_groups.has_next else None,
                'prev_page': all_groups.prev_num if all_groups.has_prev else None
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
                   result:
                     type: boolean
                   user-groups:
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
                   next_page:
                     type: integer
                   prev_page:
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
    user = User.query.filter_by(token=token).first()
    name = request.json.get('name')
    users = request.json.get('users')

    new_group = UserGroups(name=name, group=user.group)
    db.session.add(new_group)
    db.session.commit()

    for i in users:
        new_rec = GroupsMapping(user=i, user_group=new_group.id)
        db.session.add(new_rec)
        db.session.commit()
    return redirect(url_for('main.user_groups', token=token))


@main.route('/api/edit-user-group', methods=['GET', 'POST'])
@login_required
def edit_user_group():
    '''
    ---
   post:
     summary: Редактировать группу пользователей
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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

                   users:
                     type: array
                     items:
                       type: integer
                example:   # Sample object

                  users: [1, 2, 3]
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
                   user-groups:
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
                   next_page:
                     type: integer
                   prev_page:
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
    id = request.args.get('group-id')
    users = request.json.get('users')

    _ = GroupsMapping.query.filter_by(user_group=id)
    db.session.commit()

    for i in users:
        new_rec = GroupsMapping(user=i, user_group=id)
        db.session.add(new_rec)
        db.session.commit()
    return redirect(url_for('main.user_groups', token=token))


@main.route('/api/delete-user-group')
@login_required
def delete_user_group():
    '''
    ---
   get:
     summary: Удалить группу пользователей
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
        print(e)
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
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
           description: token
         - in: query
           name: search
           schema:
             type: string
             example:
           description: search
         - in: query
           name: page
           schema:
             type: integer
             example: 1
           description: page
         - in: query
           name: per-page
           schema:
             type: integer
             example: 10
           description: per-page
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
                   search_query:
                     type: string
                   next_page:
                     type: string
                   prev_page:
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
    user = User.query.filter_by(token=token).first()
    user_groups_ = []
    search_query = request.args.get('search', '')  # Получаем значение параметра 'search' из URL
    page = request.args.get('page', 1, type=int)  # Получаем значение параметра 'page' из URL
    all_user_groups = UserGroups.query.filter_by(
        group=user.group).all() if user.role == 1 else UserGroups.query.filter_by().all()
    all_beacons = Beacons.query.filter_by(
        group=user.group).all() if user.role == 1 else Beacons.query.filter_by().all()
    if Notifications.query.count() == 0:
        # Если база данных пуста, предоставляем сообщение или выполняем редирект
        return current_app.response_class(
            response=json.dumps(
                {
                    'result': True,
                    'notifications': user_groups_,
                    'search_query': search_query,
                    'next_page': None,
                    'prev_page': None
                }
            ),
            status=200,
            mimetype='application/json'
        )
    query = Notifications.query.filter((Notifications.group == user.group))
    all_groups = query.paginate(page=page, per_page=5)
    for i in all_groups:
        start = i.time_start.strftime('%Y-%m-%d %H:%M')
        finish = i.time_finish.strftime('%Y-%m-%d %H:%M')
        user_groups_.append({
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
            'start': start,
            'finish': finish,
            'title': i.title,
            'text': i.text,
            'file': i.attachment
        })
    return current_app.response_class(
        response=json.dumps(
            {
                'result': True,
                'notifications': user_groups_,
                'search_query': search_query,
                'next_page': all_groups.next_num if all_groups.has_next else None,
                'prev_page': all_groups.prev_num if all_groups.has_prev else None
            }
        ),
        status=200,
        mimetype='application/json'
    )


@main.route('/add-notification', methods=['GET', 'POST'])
@login_required
def add_notification():
    '''
    ---
   post:
     summary: Добавить группу пользователей
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
    token = request.args.get('token')
    user = User.query.filter_by(token=token).first()
    beacon = request.form.get('beacon')
    group = request.form.get('group')
    start = datetime.strptime(request.form.get('start'), '%Y-%m-%dT%H:%M')
    finish = datetime.strptime(request.form.get('finish'), '%Y-%m-%dT%H:%M')
    title = request.form.get('title')
    text = request.form.get('text')
    file = request.files['file']
    new_note = Notifications(group=user.group, beacon=beacon, user_group=group, time_start=start,
                             time_finish=finish, text=text, title=title)
    db.session.add(new_note)
    db.session.commit()
    filename = str(new_note.id) + '.' + file.filename.split('.')[-1]
    file.save(f'{CWD}app/static/files/' + filename)
    _ = Notifications.query.filter_by(id=new_note.id).update({'attachment': filename})
    db.session.commit()
    return redirect(url_for('main.notifications'))


@main.route('/edit-notification', methods=['GET', 'POST'])
@login_required
def edit_notification():
    '''
    ---
   post:
     summary: Добавить группу пользователей
     parameters:
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
    beacon = request.form.get('beacon')
    group = request.form.get('group')
    start = datetime.strptime(request.form.get('start'), '%Y-%m-%dT%H:%M')
    finish = datetime.strptime(request.form.get('finish'), '%Y-%m-%dT%H:%M')
    text = request.form.get('text')
    title = request.form.get('title')
    _ = Notifications.query.filter_by(id=id).update({'beacon': beacon, 'user_group': group, 'time_start': start,
                                                     'time_finish': finish, 'text': text, 'title': title})
    db.session.commit()
    file = request.files['file']
    if file:
        filename = str(id) + '.' + file.filename.split('.')[-1]
        file.save(f'{CWD}app/static/files/' + filename)
        _ = Notifications.query.filter_by(id=id).update({'attachment': filename})
        db.session.commit()

    return redirect(url_for('main.notifications'))


@main.route('/api/delete_notification', methods=['GET', 'POST'])
@login_required
def delete_notification():
    '''
    ---
   get:
     summary: Удалить уведомление
     parameters:
         - in: query
           name: token
           schema:
             type: string
             example: xv2ossY6V9fikmjp$a45f9c93467deca882d3219ba4c568e3a9ebe4a53dbd17b03ec6987a9976b8bc
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
        print(e)
        return current_app.response_class(
            response=json.dumps(
                {'error': f'ERROR: {e}!'}
            ),
            status=400,
            mimetype='application/json'
        )
