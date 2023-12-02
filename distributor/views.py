from bson import ObjectId
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT, HTTP_200_OK
from rest_framework.exceptions import ValidationError
from utils import get_db_handle, LOGIN_DATABASE, get_jwt_keys, QUERY_DATABASE
import jwt
from datetime import datetime, timezone


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


def authenticate_token(request):
    token = request.data["auth_token"]
    _private_key, public_key = get_jwt_keys()
    try:
        decoded_token = jwt.decode(token, public_key, algorithms=["ES256"], verify=True)
    except jwt.exceptions.InvalidSignatureError:
        raise ValidationError("Invalid token signature")
    except jwt.exceptions.ExpiredSignatureError:
        raise ValidationError("Token has expired")
    return decoded_token


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

    private_key, public_key = get_jwt_keys()
    now = datetime.now(tz=timezone.utc).timestamp()
    encoded_details = {
        "username": user["username"],
        "exp": now + 3600,
        "iss": "Connections By KSU Students, Spring 2023",
        "signer": public_key,
    }

    token = jwt.encode(encoded_details, private_key, algorithm="ES256")
    return Response({"success": True, "token": token}, status=HTTP_200_OK)


@api_view(["POST"])
def query(request):
    db_handle, _client = get_db_handle()
    excpected_keys = [
        "query_data",
        "auth_token",
        "query_categories",
    ]
    authenticate_expected(request, excpected_keys)
    auth_data = authenticate_token(request)

    for query_category in request.data["query_categories"]:
        if query_category not in request.data["query_data"]:
            raise ValidationError(f"Category {query_category} not in query data")
        if len(request.data["query_data"][query_category]) == 0:
            raise ValidationError(f"Category {query_category} is empty")
    for category in request.data["query_data"]:
        if category not in request.data["query_categories"]:
            raise ValidationError(f"Category {category} not in query categories")

    query_data = {}
    query_data["query"] = request.data["query_data"]
    query_data["username"] = auth_data["username"]
    query_data["timestamp"] = datetime.now(tz=timezone.utc).timestamp()
    query_data["status"] = "pending"
    query_data["categories"] = request.data["query_categories"]

    insert_result = db_handle[QUERY_DATABASE].insert_one(query_data)
    query_id = insert_result.inserted_id
    return Response({"success": True, "query_id": str(query_id)}, status=HTTP_200_OK)


@api_view(["GET"])
def get_queue_depth(_request):
    db_handle, _client = get_db_handle()
    tmp_query = {"status": "pending"}
    pending_queries = db_handle[QUERY_DATABASE].find(tmp_query)
    return Response(
        {"success": True, "queue_depth": pending_queries.count()}, status=HTTP_200_OK
    )


@api_view(["POST"])
def get_query_document(request):
    db_handle, _client = get_db_handle()
    excpected_keys = [
        "query_id",
        "auth_token",
    ]
    authenticate_expected(request, excpected_keys)
    auth_data = authenticate_token(request)
    query_id = request.data["query_id"]
    query_data = db_handle[QUERY_DATABASE].find_one({"_id": ObjectId(query_id)})
    del query_data["_id"]
    if not query_data:
        return Response(
            {"success": False, "error": "Invalid query ID"},
            status=HTTP_400_BAD_REQUEST,
        )
    if query_data["username"] != auth_data["username"]:
        return Response(
            {"success": False, "error": "unAuthorized query ID from user"},
            status=HTTP_400_BAD_REQUEST,
        )

    if query_data["status"] == "pending":
        tmp_query = {"status": "pending", "timestamp": {"$lt": query_data["timestamp"]}}
        pending_queries = db_handle[QUERY_DATABASE].find(tmp_query)
        query_data["queue_position"] = pending_queries.count()

    query_data["success"] = True
    return Response(query_data, status=HTTP_200_OK)
