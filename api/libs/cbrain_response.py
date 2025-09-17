from datetime import datetime


def cbrain_response(data, message=""):
    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "success": True,
        "code": 200,
        "msg": message,
        "data": data
    }, 200


def cbrain_response_fail(code=500, message=""):
    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "success": False,
        "code": code,
        "msg": message,
    }, 200
