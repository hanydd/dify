import logging
import urllib.parse
from typing import Optional

import requests
from werkzeug.exceptions import Unauthorized

from configs import dify_config
from extensions.ext_database import db
from libs.datetime_utils import naive_utc_now
from libs.oauth import CbrainOAuth, OAuthUserInfo
from models import AccountStatus, Account, TenantAccountJoin
from services.account_service import AccountService, TenantService


class CbrainLoginService:

    provider = "cbrain"
    cbrain_provider = CbrainOAuth(client_id="", client_secret="", redirect_uri="")

    @staticmethod
    def login(token: str, environment: str, current_user_id: str) -> Account:
        # 1. 查询C大脑登录态
        user_info: OAuthUserInfo
        try:
            base_url = dify_config.CBRAIN_BASE_URL
            userinfo_url = urllib.parse.urljoin(base_url, dify_config.CBRAIN_USER_INFO_URL)
            headers = {"Authorization": token, "environment": environment}
            login_response = requests.post(userinfo_url, headers=headers)
            login_response_json = login_response.json()

            if (login_response.status_code != 200
                    or login_response_json["code"] != 200
                    or login_response_json["data"] is None
                    or login_response_json["data"]["currentUserId"] is None):
                raise Unauthorized()
            user_info = OAuthUserInfo(id=current_user_id, name=login_response_json["data"]["userName"],
                                      email=current_user_id + "@dify.comnova.com")
        except Exception as e:
            logging.error(f"C大脑登录态无效: {current_user_id}, {e}")
            raise Unauthorized()

        # 2. 查询并创建用户
        account: Optional[Account] = Account.get_by_openid(CbrainLoginService.provider, current_user_id)
        if not account:
            account = AccountService.create_account(
                email=user_info.email,
                name=user_info.name,
                interface_language="zh-Hans",
            )
            account.status = AccountStatus.ACTIVE.value
            account.initialized_at = naive_utc_now()

            AccountService.link_account_integrate(CbrainLoginService.provider, user_info.id, account)

        # 3. 创建并加入租户对应的工作空间
        tenant = TenantService.create_and_get_tenant_for_cbrain(environment, token)
        TenantService.create_tenant_member(tenant, account, role="editor")

        # 4. 将c大脑租户对应的公共空间设为当前活跃空间
        account.set_tenant_id(tenant.id)
        db.session.query(TenantAccountJoin).filter(
            TenantAccountJoin.tenant_id == tenant.id,
            TenantAccountJoin.account_id == account.id
        ).update({"current": True})
        logging.info(f"设置工作空间 {tenant.name} 为当前活跃空间")

        db.session.commit()
        return account
