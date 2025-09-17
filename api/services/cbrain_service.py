import logging
import urllib.parse
from typing import Optional

import requests
from werkzeug.exceptions import Unauthorized

from configs import dify_config
from extensions.ext_database import db
from extensions.ext_redis import redis_client
from libs.datetime_utils import naive_utc_now
from libs.oauth import CbrainOAuth, OAuthUserInfo
from models import AccountStatus, Account
from models.account import Tenant
from services.account_service import AccountService, TenantService
from services.errors.account import LinkAccountIntegrateError


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
        account: Optional[Account] = None

        account_cache_key = f"cbrain:account:{current_user_id}"
        cached_account_id = redis_client.get(account_cache_key)
        if cached_account_id:
            account = db.session.query(Account).filter_by(id=cached_account_id.decode("utf-8")).first()

        if not account:
            account = Account.get_by_openid(CbrainLoginService.provider, current_user_id)

        if not account:
            account_lock_name = f"cbrain_create_account_lock:{current_user_id}"
            account_lock = redis_client.lock(account_lock_name, timeout=10, blocking_timeout=3)
            if account_lock.acquire(blocking=True):
                with account_lock:
                    # Wrap create + link in a nested transaction to ensure atomicity
                    db.session.begin_nested()
                    try:
                        account = Account.get_by_openid(CbrainLoginService.provider, current_user_id)
                        if not account:
                            account = AccountService.create_account(
                                email=user_info.email,
                                name=user_info.name,
                                interface_language="zh-Hans",
                            )
                            account.status = AccountStatus.ACTIVE.value
                            account.initialized_at = naive_utc_now()

                            AccountService.link_account_integrate(CbrainLoginService.provider, user_info.id, account)
                        db.session.commit()
                    except LinkAccountIntegrateError:
                        db.session.rollback()
                        # Linking failed due to race, prefer existing account bound to openid
                        account = Account.get_by_openid(CbrainLoginService.provider, current_user_id)
                        if not account:
                            raise
                    except Exception:
                        db.session.rollback()
                        raise
            else:
                account = Account.get_by_openid(CbrainLoginService.provider, current_user_id)
        try:
            if account and not cached_account_id:
                redis_client.set(account_cache_key, account.id, ex=600)
        except Exception:
            pass

        # 3. 创建并加入租户对应的工作空间
        tenant_cache_key = f"cbrain:tenant:{environment}"
        cached_tenant_id = redis_client.get(tenant_cache_key)
        tenant: Tenant | None = None
        if cached_tenant_id:
            tenant = db.session.query(Tenant).filter_by(id=cached_tenant_id.decode("utf-8")).first()
        if not tenant:
            tenant = db.session.query(Tenant).where(Tenant.cbrain_tenant_id == environment, Tenant.is_public == True).first()
        if not tenant:
            tenant_lock_name = f"cbrain_create_tenant_lock:{environment}"
            tenant_lock = redis_client.lock(tenant_lock_name, timeout=20, blocking_timeout=3)
            if tenant_lock.acquire(blocking=True):
                with tenant_lock:
                    tenant = db.session.query(Tenant).where(
                        Tenant.cbrain_tenant_id == environment, Tenant.is_public == True).first()
                    if not tenant:
                        tenant = TenantService.create_and_get_tenant_for_cbrain(environment, token)
            else:
                tenant = db.session.query(Tenant).where(Tenant.cbrain_tenant_id == environment, Tenant.is_public == True).first()

        try:
            if tenant and not cached_tenant_id:
                redis_client.set(tenant_cache_key, tenant.id, ex=60 * 60 * 24)
        except Exception:
            pass

        ta = TenantService.create_tenant_member(tenant, account, role="editor")

        # 4. 将c大脑租户对应的公共空间设为当前活跃空间
        account._current_tenant = tenant
        account.role = ta.role
        if not ta.current:
            ta.current = True
            logging.info(f"设置工作空间 {tenant.id} 为当前活跃空间")

        db.session.commit()
        return account
