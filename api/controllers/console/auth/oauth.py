import logging
from typing import Optional

import requests
from flask import current_app, redirect, request
from flask_restful import Resource
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.exceptions import Unauthorized

from configs import dify_config
from constants.languages import languages
from extensions.ext_database import db
from libs.datetime_utils import naive_utc_now
from libs.helper import extract_remote_ip
from libs.oauth import CbrainOAuth, OAuthUserInfo
from models import Account
from models.account import AccountStatus
from services.account_service import AccountService, RegisterService, TenantService
from services.errors.account import AccountNotFoundError, AccountRegisterError
from services.errors.workspace import WorkSpaceNotAllowedCreateError, WorkSpaceNotFoundError
from services.feature_service import FeatureService
from .. import api


def get_oauth_providers():
    with current_app.app_context():
        cbrain_oauth = CbrainOAuth(client_id="", client_secret="",
                                   redirect_uri=dify_config.CONSOLE_API_URL + "/console/api/oauth/authorize/cbrain")

        OAUTH_PROVIDERS = {"cbrain": cbrain_oauth}
        return OAUTH_PROVIDERS


class OAuthLogin(Resource):
    def get(self, provider: str):
        invite_token = request.args.get("invite_token") or None
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
        if not oauth_provider:
            return {"error": "Invalid provider"}, 400

        auth_url = oauth_provider.get_authorization_url(invite_token=invite_token)
        return redirect(auth_url)


class OAuthCallback(Resource):
    def get(self, provider: str):
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
        if not oauth_provider:
            return {"error": "Invalid provider"}, 400

        code = request.args.get("code")
        environment = request.args.get("environment")
        state = request.args.get("state")
        invite_token = None
        if state:
            invite_token = state

        try:
            token = oauth_provider.get_access_token(code)
            user_info = oauth_provider.get_user_info(token, **request.args)
        except requests.exceptions.RequestException as e:
            error_text = e.response.text if e.response else str(e)
            logging.exception("An error occurred during the OAuth process with %s: %s", provider, error_text)
            return {"error": "OAuth process failed"}, 400

        if invite_token and RegisterService.is_valid_invite_token(invite_token):
            invitation = RegisterService._get_invitation_by_token(token=invite_token)
            if invitation:
                invitation_email = invitation.get("email", None)
                if invitation_email != user_info.email:
                    return redirect(f"{dify_config.CONSOLE_WEB_URL}/signin?message=Invalid invitation token.")

            return redirect(f"{dify_config.CONSOLE_WEB_URL}/signin/invite-settings?invite_token={invite_token}")

        try:
            # 对于C大脑OAuth，特殊处理租户创建
            if provider == "cbrain":
                account = _get_account_by_openid_or_email(provider, user_info)
                logging.info(f"开始处理C大脑OAuth回调，用户: {user_info.id}, 账户: {account.id}")

                # 获取C大脑用户的租户列表
                cbrain_tenant_list = CbrainOAuth.get_cbrain_tenant_list(code)
                logging.info(f"获取到C大脑租户列表: {len(cbrain_tenant_list) if cbrain_tenant_list else 0} 个租户")

                TenantService.check_and_create_default_tenants(
                    account=account,
                    environment=environment,
                    cbrain_tenant_list=cbrain_tenant_list
                )
        except Exception:
            logging.error("创建用户失败！")
            raise

        try:
            account = _generate_account(provider, user_info)
        except AccountNotFoundError:
            return redirect(f"{dify_config.CONSOLE_WEB_URL}/signin?message=Account not found.")
        except (WorkSpaceNotFoundError, WorkSpaceNotAllowedCreateError):
            return redirect(
                f"{dify_config.CONSOLE_WEB_URL}/signin"
                "?message=Workspace not found, please contact system admin to invite you to join in a workspace."
            )
        except AccountRegisterError as e:
            return redirect(f"{dify_config.CONSOLE_WEB_URL}/signin?message={e.description}")

        # Check account status
        if account.status == AccountStatus.BANNED.value:
            return redirect(f"{dify_config.CONSOLE_WEB_URL}/signin?message=Account is banned.")

        if account.status == AccountStatus.PENDING.value:
            account.status = AccountStatus.ACTIVE.value
            account.initialized_at = naive_utc_now()
            db.session.commit()

        try:
            TenantService.create_owner_tenant_if_not_exist(account)
        except Unauthorized:
            return redirect(f"{dify_config.CONSOLE_WEB_URL}/signin?message=Workspace not found.")
        except WorkSpaceNotAllowedCreateError:
            return redirect(
                f"{dify_config.CONSOLE_WEB_URL}/signin"
                "?message=Workspace not found, please contact system admin to invite you to join in a workspace."
            )

        token_pair = AccountService.login(
            account=account,
            ip_address=extract_remote_ip(request),
        )

        # 对于C大脑OAuth，拼接C大脑参数和dify的token参数
        if provider == "cbrain":
            logging.info(f"开始构建C大脑OAuth返回参数")
            # 获取C大脑OAuth的返回参数
            cbrain_params = CbrainOAuth.get_cbrain_return_params(code=code, request_args=request.args)
            logging.info(f"C大脑OAuth返回参数: {cbrain_params}")

            # 构建返回URL，包含C大脑参数和dify的token参数
            redirect_url = f"{dify_config.CONSOLE_WEB_URL}/oauth-callback?"
            param_pairs = []

            # 添加dify的token参数
            param_pairs.append(f"access_token={token_pair.access_token}")
            param_pairs.append(f"refresh_token={token_pair.refresh_token}")

            # 添加C大脑的参数
            import urllib.parse
            for key, value in cbrain_params.items():
                if value is not None:
                    # URL编码参数值，避免特殊字符问题
                    encoded_value = urllib.parse.quote(str(value))
                    param_pairs.append(f"{key}={encoded_value}")

            redirect_url += "&".join(param_pairs)
            logging.info(f"C大脑OAuth重定向URL: {redirect_url}")
            return redirect(redirect_url)
        else:
            # 其他OAuth提供商保持原有逻辑
            return redirect(
                f"{dify_config.CONSOLE_WEB_URL}?access_token={token_pair.access_token}&refresh_token={token_pair.refresh_token}"
            )


def _get_account_by_openid_or_email(provider: str, user_info: OAuthUserInfo) -> Optional[Account]:
    account: Optional[Account] = Account.get_by_openid(provider, user_info.id)

    if not account:
        with Session(db.engine) as session:
            account = session.execute(select(Account).filter_by(email=user_info.email)).scalar_one_or_none()

    return account


def _generate_account(provider: str, user_info: OAuthUserInfo):
    # Get account by openid or email.
    account = _get_account_by_openid_or_email(provider, user_info)

    if account:
        tenants = TenantService.get_join_tenants(account)
        if not tenants:
            RegisterService.create_default_tenant(account=account)

    if not account:
        account_name = user_info.name or "Dify"
        account = RegisterService.register(
            email=user_info.email, name=account_name, password=None, open_id=user_info.id, provider=provider
        )

        # Set interface language
        preferred_lang = request.accept_languages.best_match(languages)
        if preferred_lang and preferred_lang in languages:
            interface_language = preferred_lang
        else:
            interface_language = languages[0]
        account.interface_language = interface_language
        db.session.commit()

    # Link account
    AccountService.link_account_integrate(provider, user_info.id, account)

    return account


api.add_resource(OAuthLogin, "/oauth/login/<provider>")
api.add_resource(OAuthCallback, "/oauth/authorize/<provider>")
