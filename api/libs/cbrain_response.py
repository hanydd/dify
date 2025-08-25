from datetime import datetime


def cbrain_response(data):
    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "success": True,
        "code": 200,
        "msg": "",
        "data": data
    }
