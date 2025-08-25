import json
import logging
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
        logging.info(f"获取C大脑登录信息:{user_info_url}, {json.dumps(headers)}")
        response = requests.post(user_info_url, headers=headers)
        response_json = response.json()
        logging.info(f"C大脑登录返回：{response_json}")
        return response_json.get("data")

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        email = raw_info["currentUserId"] + "@dify.comnova.com"
        return OAuthUserInfo(id=raw_info["currentUserId"], name=raw_info["userName"], email=email)

    @staticmethod
    def get_cbrain_tenant_list(token: str) -> list:
        """
        获取C大脑用户的租户列表

        Args:
            token: C大脑token
            **kwargs: 其他参数

        Returns:
            C大脑用户的租户列表
        """
        try:
            # C大脑租户列表接口地址
            tenant_list_url = dify_config.CBRAIN_BASE_URL + "/cbrain-gateway/cbrain-portal-server/application/tbtenant/list"

            # 设置请求头
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            # 发送GET请求获取租户列表
            response = requests.get(tenant_list_url, headers=headers, timeout=10)
            response.raise_for_status()  # 检查HTTP错误
            response_data = response.json()

            # 检查响应格式
            if not response_data.get("success") or response_data.get("code") != 200:
                print(f"C大脑租户列表获取失败: {response_data.get('msg', '未知错误')}")
                raise

            tenant_list = response_data.get("data", [])
            print(f"C大脑租户列表获取成功，共{len(tenant_list)}个租户")
            return tenant_list

        except requests.exceptions.RequestException as e:
            print(f"请求C大脑租户列表接口失败: {str(e)}")
            return []
        except Exception as e:
            print(f"解析C大脑租户列表响应失败: {str(e)}")
            return []

    @staticmethod
    def get_cbrain_return_params(code: str, request_args: Any) -> Dict[str, str]:
        """
        生成C大脑OAuth所需的返回参数

        Args:
            code: OAuth授权码
            request_args: 请求参数

        Returns:
            包含C大脑OAuth所需参数的字典
        """
        # 添加参数验证
        if not code:
            raise ValueError("code参数不能为空")

        # 登录相关参数
        params = {"cbrain_token": code, "environment": request_args.get("environment")}
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
            params["processId"] = request_args.get("processId")
            params["agent_id"] = request_args.get("agent_id")

        # 页面路径相关参数
        if "url" in request_args.keys():
            params["url"] = request_args.get("url")

        # 过滤掉None值
        return {k: v for k, v in params.items() if v is not None}
