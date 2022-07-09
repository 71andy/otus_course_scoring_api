#!/usr/bin/env python
# -*- coding: utf-8 -*-

# from abc import ABC, abstractmethod
# from encodings import utf_8
# from itertools import chain
from datetime import datetime
import json
import logging
import hashlib
import uuid
import scoring
from store import Store
from optparse import OptionParser

# from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from http.server import BaseHTTPRequestHandler, HTTPServer

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class GenericField:
    """
    Дескриптор - базовый класс поля. Выполняет общие проверки
    (тип, обязательность, допустимость пустого значения)
    """

    def __init__(self, required, nullable, fieldtype):
        """
        :param required: True if the field is required
        :type required: bool
        :param nullable: True if the field can be nullable
        :type nullable: bool
        :param fieldtype: Type(s) of field
        :type fieldtype: type, tuple of types
        """
        self.required = required
        self.nullable = nullable
        self.fieldtype = fieldtype

    def __set_name__(self, owner, name):
        self.name = name
        self.private_name = "_" + name

    def __get__(self, obj, objtype=None):
        return getattr(obj, self.private_name)

    def __set__(self, obj, value):
        """
        :param value: Значение поля. Устанавливается в None, если его нет в запросе.
                      Делается для проверки на обязательные поля
        """
        if value is None:
            if self.required:
                raise ValueError(f"Field '{ self.name }' is required")
        else:
            # Проверка поля, сущестующего в запросе на тип данных
            if not isinstance(value, self.fieldtype):
                raise ValueError(f"Type of field '{ self.name }' is invalid")
            # Проверка на недопустимое пустое значение поле
            if value:
                self.validate(value)  # Валидировать в наследниках
            else:
                # Пустое значение не валидируется в наследниках.
                if not self.nullable:
                    # Пустое значение не допускается
                    raise ValueError(f"Field '{ self.name }' can't be empty")

        setattr(obj, self.private_name, value)

    def validate(self, value):
        """
        Функция реализуется в наследниках при необходимости дополнительной валидации value
        def validate(self, value):
            super().validate(value)
            ... собственные проверки
            if ошибка_валидации:
                raise ValueError(f"Field '{self.name}' is invalid: '{value}'")
        """
        pass


class CharField(GenericField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable, str)


class ArgumentsField(GenericField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable, dict)


class EmailField(CharField):
    def validate(self, value):
        super().validate(value)
        if "@" not in value:
            raise ValueError(f"Field '{self.name}' has invalid email format '{value}'")


class PhoneField(GenericField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable, (int, str))

    def validate(self, value):
        super().validate(value)
        phone = str(value) if isinstance(value, int) else value
        if len(phone) != 11 or not phone.startswith("7"):
            raise ValueError(f"Field '{self.name}' has invalid phone format '{value}'")


class DateField(CharField):
    def validate(self, value):
        super().validate(value)
        try:
            date = datetime.strptime(value, "%d.%m.%Y")
        except ValueError:
            raise ValueError(f"Field '{self.name}' has invalid date format '{value}'")

        self._date = date


class BirthDayField(DateField):
    def validate(self, value):
        super().validate(value)
        # Проверка на возраст не более 70 лет
        dt = datetime.now() - self._date
        if dt.days < 0:
            raise ValueError(f"Field '{self.name}' has invalid date. Birthday can't be in the future")
        elif dt.days > 365 * 70:
            raise ValueError(f"Field '{self.name}' has invalid date. User is too old")


class GenderField(GenericField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable, int)

    def validate(self, value):
        super().validate(value)
        if value not in (0, 1, 2):
            raise ValueError(f"Field '{self.name}' is invalid '{value}', should be 0, 1 or 2")


class ClientIDsField(GenericField):
    def __init__(self, required=False, nullable=False):
        super().__init__(required, nullable, list)

    def validate(self, value):
        super().validate(value)

        if [v for v in value if not isinstance(v, int)]:
            raise ValueError(f"Field '{self.name}' is invalid '{value}', items should be nubmers")


class Meta(type):
    """Метакласс собирает в словарь '_fields' все атрибуты класса, наследованные от GenericField"""

    def __new__(cls, name, bases, namespace):
        # Also ensure initialization is only performed for subclasses of Meta
        # (excluding Meta class itself).
        parents = [b for b in bases if isinstance(b, Meta)]
        if not parents:
            return super().__new__(cls, name, bases, namespace)

        # При наследовании классов забрать в дочерний класс все поля из базового
        base_fields_gen = (b._fields for b in bases if isinstance(b, Meta) and hasattr(b, "_fields"))
        base_fields = {}
        for f in base_fields_gen:
            base_fields = {**base_fields, **f}
        fields = {name: field for name, field in namespace.items() if isinstance(field, GenericField)}
        namespace["_fields"] = {**fields, **base_fields}
        return super().__new__(cls, name, bases, namespace)


class GenericRequest(metaclass=Meta):
    def __init__(self, request_args):
        """error string if the request is invalid, None otherwise"""
        self._request_args = request_args
        self._error = "validation has not been made yet"

    def is_valid(self):
        # Попытаться установить все поля. Если поля нет в запросе, установить его в None.
        # Для обязательных параметров установка в None вызовет исключение
        self._error = ""
        for name in self._fields:
            try:
                setattr(self, name, self._request_args[name] if name in self._request_args else None)
            except (TypeError, ValueError) as e:
                if self._error:
                    self._error += ", "
                self._error += str(e)

        return len(self._error) == 0

    def get_err(self):
        """Return error string, empty string if request is"""
        return self._error

    def get_response(self, ctx, store):
        raise NotImplementedError(f"get_response is not implemented in {repr(self.__class__)}")


class ClientsInterestsRequest(GenericRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class ClientsInterestsMethod(ClientsInterestsRequest):
    def __init__(self, method_reqest):
        super().__init__(method_reqest.arguments)

    def get_response(self, ctx, store):
        ctx.update({"nclients": len(self.client_ids)})
        interests = {str(cid): scoring.get_interests(store, cid) for cid in self.client_ids}
        return interests


class OnlineScoreRequest(GenericRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def is_valid(self):
        if not super().is_valid():
            return False

        # Дополнительная проверка на наличие пар значений
        if self.first_name and self.last_name:
            pass
        elif self.phone and self.email:
            pass
        elif self.birthday and self.gender is not None:
            pass
        else:
            self._error = "Any pair of phone/email, first_name/last_name, gender/birthday was not found"
            return False

        return True


class OnlineScoreMethod(OnlineScoreRequest):
    def __init__(self, method_reqest):
        super().__init__(method_reqest.arguments)
        self.is_admin = method_reqest.is_admin

    def get_response(self, ctx, store):

        ctx.update({"has": [field for field in self._fields.keys() if getattr(self, field) is not None]})

        score = scoring.get_score(
            store,
            phone=self.phone,
            email=self.email,
            birthday=self.birthday,
            gender=self.gender,
            first_name=self.first_name,
            last_name=self.last_name,
        )
        return {"score": 42 if self.is_admin else score}


METHODS = {"online_score": OnlineScoreMethod, "clients_interests": ClientsInterestsMethod}


class MethodRequest(GenericRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        di = datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        di = request.account + request.login + SALT

    digest = hashlib.sha512(di.encode("utf-8")).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):

    if not request["body"]:
        return "Empty request is not allowed", INVALID_REQUEST

    req = MethodRequest(request["body"])
    if not req.is_valid():
        return req.get_err(), INVALID_REQUEST

    if not check_auth(req):
        return "", FORBIDDEN

    if req.method not in METHODS:
        return f"Method {req.method} is invalid", INVALID_REQUEST

    method = METHODS[req.method](req)
    if not method.is_valid():
        return method.get_err(), INVALID_REQUEST

    response = method.get_response(ctx, store)

    return response, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = Store()

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(
        filename=opts.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
