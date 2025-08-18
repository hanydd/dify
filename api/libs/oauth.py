import urllib.parse
from dataclasses import dataclass
from typing import Optional

import requests

from configs import dify_config


@dataclass
class OAuthUserInfo:
    id: str
    name: str
    email: str


class OAuth:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self):
        raise NotImplementedError()

    def get_access_token(self, code: str):
        raise NotImplementedError()

    def get_raw_user_info(self, token: str, **kwargs):
        raise NotImplementedError()

    def get_user_info(self, token: str, **kwargs) -> OAuthUserInfo:
        raw_info = self.get_raw_user_info(token, **kwargs)
        return self._transform_user_info(raw_info)

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        raise NotImplementedError()


class CbrainOAuth(OAuth):
    _CBRAIN_BASE_URL = dify_config.CBRAIN_BASE_URL
    _USER_INFO_URL = dify_config.CBRAIN_USER_INFO_URL

    def get_authorization_url(self, invite_token: Optional[str] = None):
        pass

    def get_access_token(self, code: str):
        return code

    def get_raw_user_info(self, token: str, **kwargs):
        base_url = self._CBRAIN_BASE_URL
        user_info_url = urllib.parse.urljoin(base_url, self._USER_INFO_URL)
        headers = {"Authorization": f"Bearer {token}", "environment": kwargs.get("environment")}
        response = requests.post(user_info_url, headers=headers)
        response_json = response.json()
        print("C大脑登录返回：", response_json)
        return response_json.get("data")

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        print("_transform_user_info", raw_info)
        email = raw_info["currentUserId"] + "@dify.comnova.com"
        return OAuthUserInfo(id=raw_info["currentUserId"], name=raw_info["userName"], email=email)
