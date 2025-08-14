import urllib.parse
from dataclasses import dataclass
from typing import Optional, Dict, Any

import requests


@dataclass
class OAuthUserInfo:
    id: str
    name: str
    email: str
    # 新增返回参数
    cbrain_token: Optional[str] = None
    workspace: Optional[str] = None
    entry_point: Optional[int] = None
    agent_id: Optional[str] = None


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
    _USER_INFO_URL = "http://180.168.3.12:9100/cbrain-gateway/cbrain-portal-server/application/userLogin/userInfo"

    def get_authorization_url(self, invite_token: Optional[str] = None):
        pass

    def get_access_token(self, code: str):
        print("get_access_token", code)
        return code

    def get_raw_user_info(self, token: str, **kwargs):
        print("get_raw_user_info", token, kwargs)
        
        # 构建请求头，支持新的入参
        headers = {
            "Authorization": f"Bearer {token}", 
            "environment": kwargs.get("tenant")
        }
        
        # 构建请求体，支持新的入参
        data = {
            "token": token,
            "currentUserld": kwargs.get("currentUserld"),
            "environment": kwargs.get("tenant"),
            "entry_point": kwargs.get("entry_point", 1),  # 默认普通入口
        }
        
        # 如果是活动登录，添加活动相关参数
        if kwargs.get("entry_point") == 2:
            data.update({
                "valueChainld": kwargs.get("valueChainld"),
                "valueFlowVersionld": kwargs.get("valueFlowVersionld"),
                "procedureld": kwargs.get("procedureld"),
                "modelType": kwargs.get("modelType"),
                "nodeld": kwargs.get("nodeld"),
            })
        
        response = requests.post(self._USER_INFO_URL, headers=headers, json=data)
        print(response.status_code)
        response_json = response.json()
        print(response_json)
        return response_json.get("data")

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        print("_transform_user_info", raw_info)
        email = raw_info["currentUserId"] + "@dify.comnova.com"
        
        # 构建返回的用户信息，包含新的返回参数
        return OAuthUserInfo(
            id=raw_info["currentUserId"], 
            name=raw_info["userName"], 
            email=email,
            cbrain_token=raw_info.get("cbrain_token"),
            workspace=raw_info.get("workspace"),
            entry_point=raw_info.get("entry_point", 1),
            agent_id=raw_info.get("agent_id")
        )


class GitHubOAuth(OAuth):
    _AUTH_URL = "https://github.com/login/oauth/authorize"
    _TOKEN_URL = "https://github.com/login/oauth/access_token"
    _USER_INFO_URL = "https://api.github.com/user"
    _EMAIL_INFO_URL = "https://api.github.com/user/emails"

    def get_authorization_url(self, invite_token: Optional[str] = None):
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "user:email",  # Request only basic user information
        }
        if invite_token:
            params["state"] = invite_token
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        headers = {"Accept": "application/json"}
        response = requests.post(self._TOKEN_URL, data=data, headers=headers)

        response_json = response.json()
        access_token = response_json.get("access_token")

        if not access_token:
            raise ValueError(f"Error in GitHub OAuth: {response_json}")

        return access_token

    def get_raw_user_info(self, token: str, **kwargs):
        headers = {"Authorization": f"token {token}"}
        response = requests.get(self._USER_INFO_URL, headers=headers)
        response.raise_for_status()
        user_info = response.json()

        email_response = requests.get(self._EMAIL_INFO_URL, headers=headers)
        email_info = email_response.json()
        primary_email: dict = next((email for email in email_info if email["primary"] == True), {})

        return {**user_info, "email": primary_email.get("email", "")}

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        email = raw_info.get("email")
        if not email:
            email = f"{raw_info['id']}+{raw_info['login']}@users.noreply.github.com"
        return OAuthUserInfo(
            id=str(raw_info["id"]), 
            name=raw_info["name"], 
            email=email,
            # GitHub OAuth不提供这些参数，设为None
            cbrain_token=None,
            workspace=None,
            entry_point=1,  # 默认为普通登录
            agent_id=None
        )


class GoogleOAuth(OAuth):
    _AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    _TOKEN_URL = "https://oauth2.googleapis.com/token"
    _USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

    def get_authorization_url(self, invite_token: Optional[str] = None):
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid email",
        }
        if invite_token:
            params["state"] = invite_token
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        headers = {"Accept": "application/json"}
        response = requests.post(self._TOKEN_URL, data=data, headers=headers)

        response_json = response.json()
        access_token = response_json.get("access_token")

        if not access_token:
            raise ValueError(f"Error in Google OAuth: {response_json}")

        return access_token

    def get_raw_user_info(self, token: str, **kwargs):
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(self._USER_INFO_URL, headers=headers)
        response.raise_for_status()
        return response.json()

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(raw_info["sub"]), 
            name="", 
            email=raw_info["email"],
            # Google OAuth不提供这些参数，设为None
            cbrain_token=None,
            workspace=None,
            entry_point=1,  # 默认为普通登录
            agent_id=None
        )
