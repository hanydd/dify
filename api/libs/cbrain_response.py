from datetime import datetime


def cbrain_response(data, message=""):
    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "success": True,
        "code": 200,
        "msg": message,
        "data": data
    }
