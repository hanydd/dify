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

    def get_cbrain_tenant_list(self, token: str, **kwargs) -> list:
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
            tenant_list_url = "http://10.230.1.182/cbrain-gateway/cbrain-portal-server/application/tbtenant/list"
            
            # 设置请求头
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            # 发送GET请求获取租户列表
            response = requests.get(tenant_list_url, headers=headers, timeout=10)
            response.raise_for_status()  # 检查HTTP错误
            
            # 解析响应
            response_data = response.json()
            
            # 检查响应格式
            if response_data.get("success") and response_data.get("code") == 200:
                tenant_list = response_data.get("data", [])
                
                # 转换租户信息格式，适配Dify的租户创建逻辑
                formatted_tenants = []
                for tenant in tenant_list:
                    formatted_tenant = {
                        "id": tenant.get("tenantId"),  # 使用tenantId作为唯一标识
                        "name": tenant.get("name", ""),  # 租户名称
                        "name_en": tenant.get("nameEn", ""),  # 英文名称
                        "description": tenant.get("tenantDesc", ""),  # 租户描述
                        "status": tenant.get("status", 0),  # 租户状态
                        "manager_name": tenant.get("managerName", ""),  # 管理员名称
                        "manager_id": tenant.get("managerId", ""),  # 管理员ID
                        "creator_id": tenant.get("creatorId", ""),  # 创建者ID
                        "create_time": tenant.get("createTime", ""),  # 创建时间
                        "update_time": tenant.get("updateTime", ""),  # 更新时间
                        "user_status": tenant.get("userStatus", 0),  # 用户状态
                        "head_image": tenant.get("headImage", ""),  # 头像
                        "site_flag": tenant.get("siteFlag", False),  # 站点标志
                        "site_address": tenant.get("siteAddress", ""),  # 站点地址
                        "category_id": tenant.get("categoryId", ""),  # 分类ID
                        "menu_list": tenant.get("menuList", ""),  # 菜单列表
                        "web_water_flag": tenant.get("webWaterFlag", ""),  # 网页水印标志
                        "mobile_water_flag": tenant.get("mobileWaterFlag", "")  # 移动端水印标志
                    }
                    formatted_tenants.append(formatted_tenant)
                
                print(f"C大脑租户列表获取成功，共{len(formatted_tenants)}个租户")
                return formatted_tenants
            else:
                print(f"C大脑租户列表获取失败: {response_data.get('msg', '未知错误')}")
                return []
                
        except requests.exceptions.RequestException as e:
            print(f"请求C大脑租户列表接口失败: {str(e)}")
            return []
        except Exception as e:
            print(f"解析C大脑租户列表响应失败: {str(e)}")
            return []

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
        # 添加参数验证
        if not code:
            raise ValueError("code参数不能为空")
        
        params = {}

        # 登录相关参数
        params["cbrain_token"] = code  # c大脑token

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
            params["agent_id"] = request_args.get("agent_id")  

        # 页面路径相关参数
        params["url"] = request_args.get("url", "/explore/apps")  # 默认跳转到智能体广场

        # 智能体相关参数（如果存在）
        params["agentName"] = request_args.get("agentName")
        params["agentDescription"] = request_args.get("agentDescription")

        # 过滤掉None值
        return {k: v for k, v in params.items() if v is not None}
