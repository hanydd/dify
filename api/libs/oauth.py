import urllib.parse
from dataclasses import dataclass
from typing import Optional, Dict, Any

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

    def get_cbrain_return_params(self, code: str, user_info: OAuthUserInfo, account: Any, request_args: Any) -> Dict[str, str]:
        """
        生成C大脑OAuth所需的返回参数
        
        Args:
            code: OAuth授权码
            user_info: 用户信息
            account: 账户信息
            request_args: 请求参数
            
        Returns:
            包含C大脑OAuth所需参数的字典
        """
        params = {}
        
        # 登录相关参数
        params["code"] = code  # c大脑token
        params["currentUserld"] = user_info.id  # 账号
        params["environment"] = request_args.get("environment")  # 租户
        
        # 登录入口场景
        entry_point = request_args.get("entry_point", "1")  # 默认普通入口
        params["entry_point"] = entry_point
        
        # 活动登录相关参数（如果存在）
        if entry_point == "2":  # 活动登录
            # 活动登录相关参数
            params["valueChainId"] = request_args.get("valueChainId")
            params["valueFlowVersionId"] = request_args.get("valueFlowVersionId")
            params["procedureId"] = request_args.get("procedureId")
            params["modelType"] = request_args.get("modelType")
            params["nodeId"] = request_args.get("nodeId")
            params["agent_id"] = request_args.get("agent_id")  # 需要跳转的智能体id
        
        # 页面路径相关参数
        params["url"] = request_args.get("url", "/explore/apps")  # 默认跳转到智能体广场
        
        # 智能体相关参数（如果存在）
        params["agentName"] = request_args.get("agentName")
        params["agentDescription"] = request_args.get("agentDescription")
        
        # 过滤掉None值
        return {k: v for k, v in params.items() if v is not None}
