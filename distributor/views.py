from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT, HTTP_200_OK
from rest_framework.exceptions import ValidationError
from utils import get_db_handle, LOGIN_DATABASE, get_jwt_keys
import jwt
from datetime import datetime


def authenticate_expected(request, expected_keys):
    errors = []
    for key in expected_keys:
        if key not in request.data:
            errors.append(f"Missing key {key}")

    for key in request.data.keys():
        if key not in expected_keys:
            errors.append(f"Unexpected key {key}")
    if errors:
        raise ValidationError(errors)


# Create your views here.
@api_view(["POST"])
def signup(request):
    db_handle, _client = get_db_handle()
    excpected_keys = [
        "username",
        "password",
        "email",
        "first_name",
        "last_name",
    ]
    authenticate_expected(request, excpected_keys)

    user = request.data
    for key in user:
        if key != "password":
            user[key] = user[key].lower()

    query = {
        "$or": [
            {"username": user["username"]},
            {"email": user["email"]},
        ]
    }
    response = db_handle[LOGIN_DATABASE].find_one(query)
    if response:
        errors = []
        if response.get("username") == user["username"]:
            errors.append("Username is already in use")
        if response.get("email") == user["email"]:
            errors.append("Email is already in use")
        return Response({"success": False, "error": errors}, status=HTTP_409_CONFLICT)

    db_handle[LOGIN_DATABASE].insert_one(user)
    return Response({"success": True}, status=HTTP_200_OK)


@api_view(["POST"])
def signin(request):
    db_handle, _client = get_db_handle()
    excpected_keys = [
        "username",
        "password",
    ]
    authenticate_expected(request, excpected_keys)

    user = request.data

    query = {
        "$and": [
            {"username": user["username"].lower()},
            {"password": user["password"]},
        ]
    }
    response = db_handle[LOGIN_DATABASE].find_one(query)
    if not response:
        return Response(
            {"success": False, "error": "Invalid credentials"},
            status=HTTP_400_BAD_REQUEST,
        )

    private_key, _public_key = get_jwt_keys()
    encoded_details = {
        "username": user["username"],
        "exp": datetime.utcnow().timestamp() + 3600,
        "origin": "Connections By KSU Students, Spring 2023",
    }
    token = jwt.encode(encoded_details, private_key, algorithm="ES256")
    return Response({"success": True, "token": token}, status=HTTP_200_OK)
