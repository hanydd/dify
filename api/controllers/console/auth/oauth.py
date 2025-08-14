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
from events.tenant_event import tenant_was_created
from extensions.ext_database import db
from libs.datetime_utils import naive_utc_now
from libs.helper import extract_remote_ip
from libs.oauth import CbrainOAuth, GitHubOAuth, GoogleOAuth, OAuthUserInfo
from models import Account
from models.account import AccountStatus
from services.account_service import AccountService, RegisterService, TenantService
from services.errors.account import AccountNotFoundError, AccountRegisterError
from services.errors.workspace import WorkSpaceNotAllowedCreateError, WorkSpaceNotFoundError
from services.feature_service import FeatureService

from .. import api


def get_oauth_providers():
    with current_app.app_context():
        if not dify_config.GITHUB_CLIENT_ID or not dify_config.GITHUB_CLIENT_SECRET:
            github_oauth = None
        else:
            github_oauth = GitHubOAuth(
                client_id=dify_config.GITHUB_CLIENT_ID,
                client_secret=dify_config.GITHUB_CLIENT_SECRET,
                redirect_uri=dify_config.CONSOLE_API_URL + "/console/api/oauth/authorize/github",
            )
        if not dify_config.GOOGLE_CLIENT_ID or not dify_config.GOOGLE_CLIENT_SECRET:
            google_oauth = None
        else:
            google_oauth = GoogleOAuth(
                client_id=dify_config.GOOGLE_CLIENT_ID,
                client_secret=dify_config.GOOGLE_CLIENT_SECRET,
                redirect_uri=dify_config.CONSOLE_API_URL + "/console/api/oauth/authorize/google",
            )

        cbrain_oauth = CbrainOAuth(client_id="", client_secret="",
                                   redirect_uri=dify_config.CONSOLE_API_URL+ "/console/api/oauth/authorize/cbrain")

        OAUTH_PROVIDERS = {"github": github_oauth, "google": google_oauth, "cbrain": cbrain_oauth}
        return OAUTH_PROVIDERS


class OAuthLogin(Resource):
    def get(self, provider: str):
        invite_token = request.args.get("invite_token") or None
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
        if not oauth_provider:
            return {"error": "Invalid provider"}, 400

        # 获取新的入参参数
        current_user_id = request.args.get("currentUserld")
        entry_point = request.args.get("entry_point", "1")
        value_chain_id = request.args.get("valueChainld")
        value_flow_version_id = request.args.get("valueFlowVersionld")
        procedure_id = request.args.get("procedureld")
        model_type = request.args.get("modelType")
        node_id = request.args.get("nodeld")
        tenant = request.args.get("tenant")

        auth_url = oauth_provider.get_authorization_url(invite_token=invite_token)
        
        # 构建完整的授权URL，包含新的参数
        if auth_url:
            # 如果授权URL已经存在，添加新的参数
            separator = "&" if "?" in auth_url else "?"
            params = []
            
            if current_user_id:
                params.append(f"currentUserld={current_user_id}")
            if entry_point:
                params.append(f"entry_point={entry_point}")
            if value_chain_id:
                params.append(f"valueChainld={value_chain_id}")
            if value_flow_version_id:
                params.append(f"valueFlowVersionld={value_flow_version_id}")
            if procedure_id:
                params.append(f"procedureld={procedure_id}")
            if model_type:
                params.append(f"modelType={model_type}")
            if node_id:
                params.append(f"nodeld={node_id}")
            if tenant:
                params.append(f"tenant={tenant}")
            
            if params:
                auth_url += separator + "&".join(params)
        
        return redirect(auth_url)


class OAuthCallback(Resource):
    def get(self, provider: str):
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
        if not oauth_provider:
            return {"error": "Invalid provider"}, 400

        code = request.args.get("code")
        tenant = request.args.get("tenant")
        state = request.args.get("state")
        invite_token = None
        if state:
            invite_token = state

        # 获取新的入参参数
        current_user_id = request.args.get("currentUserld")
        entry_point = request.args.get("entry_point", "1")
        value_chain_id = request.args.get("valueChainld")
        value_flow_version_id = request.args.get("valueFlowVersionld")
        procedure_id = request.args.get("procedureld")
        model_type = request.args.get("modelType")
        node_id = request.args.get("nodeld")

        try:
            token = oauth_provider.get_access_token(code)
            # 传递新的入参参数
            user_info = oauth_provider.get_user_info(
                token, 
                tenant=tenant,
                currentUserld=current_user_id,
                entry_point=int(entry_point) if entry_point else 1,
                valueChainld=value_chain_id,
                valueFlowVersionld=value_flow_version_id,
                procedureld=procedure_id,
                modelType=model_type,
                nodeld=node_id
            )
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

        # 构建重定向URL，包含新的返回参数
        redirect_url = f"{dify_config.CONSOLE_WEB_URL}?access_token={token_pair.access_token}&refresh_token={token_pair.refresh_token}"
        
        # 添加新的返回参数
        if user_info.cbrain_token:
            redirect_url += f"&cbrain_token={user_info.cbrain_token}"
        if user_info.workspace:
            redirect_url += f"&workspace={user_info.workspace}"
        if user_info.entry_point:
            redirect_url += f"&entry_point={user_info.entry_point}"
        if user_info.agent_id:
            redirect_url += f"&agent_id={user_info.agent_id}"

        return redirect(redirect_url)


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
            if not FeatureService.get_system_features().is_allow_create_workspace:
                raise WorkSpaceNotAllowedCreateError()
            else:
                new_tenant = TenantService.create_tenant(f"{account.name}'s Workspace")
                TenantService.create_tenant_member(new_tenant, account, role="owner")
                account.current_tenant = new_tenant
                tenant_was_created.send(new_tenant)

    if not account:
        if not FeatureService.get_system_features().is_allow_register:
            raise AccountNotFoundError()
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
