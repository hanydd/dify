import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from configs import dify_config
from extensions.ext_database import db
from libs.datetime_utils import naive_utc_now
from libs.oauth import CbrainOAuth, OAuthUserInfo
from models import Account, AccountStatus
from services.account_service import AccountService, TenantService, TokenPair
from libs.helper import extract_remote_ip


class CbrainLoginService:

    provider = "cbrain"
    cbrain_provider = CbrainOAuth(client_id="", client_secret="",
                                  redirect_uri=dify_config.CONSOLE_API_URL + "/console/api/oauth/authorize/cbrain")

    @staticmethod
    def login(token: str, environment: str, request) -> TokenPair:
        oauth_provider = CbrainLoginService.cbrain_provider
        token = oauth_provider.get_access_token(token)
        args = {"environment": environment}
        user_info = oauth_provider.get_user_info(token, **args)

        logging.info(f"开始处理C大脑OAuth回调，用户: {user_info.id}")

        account = CbrainLoginService._get_account_by_openid_or_email(CbrainLoginService.provider, user_info)
        if not account:
            account = AccountService.create_account(
                email=user_info.email,
                name=user_info.name,
                interface_language="zh-Hans",
            )
            account.status = AccountStatus.ACTIVE.value
            account.initialized_at = naive_utc_now()

            AccountService.link_account_integrate(CbrainLoginService.provider, user_info.id, account)

        logging.info(f"开始处理C大脑OAuth回调，用户: {user_info.id}, 账户: {account.id}")

        # 获取C大脑用户的租户列表
        cbrain_tenant_list = CbrainOAuth.get_cbrain_tenant_list(token)
        logging.info(f"获取到C大脑租户列表: {len(cbrain_tenant_list) if cbrain_tenant_list else 0} 个租户")

        TenantService.check_and_create_default_tenants(
            account=account,
            environment=environment,
            cbrain_tenant_list=cbrain_tenant_list
        )
        db.session.commit()

        token_pair = AccountService.login(
            account=account,
            ip_address=extract_remote_ip(request),
        )
        return token_pair

    @staticmethod
    def _get_account_by_openid_or_email(provider: str, user_info: OAuthUserInfo) -> Optional[Account]:
        account: Optional[Account] = Account.get_by_openid(provider, user_info.id)

        if not account:
            with Session(db.engine) as session:
                account = session.execute(select(Account).filter_by(email=user_info.email)).scalar_one_or_none()

        return account
