from typing import List

from flask import request
from flask_restful import Resource
from pydantic import BaseModel, Field, ValidationError

from controllers.console import api
from extensions.ext_database import db
from libs.cbrain_response import cbrain_response, cbrain_response_fail
from libs.login import login_required
from models import AppCustomConfig


class ProcesConfig(BaseModel):
    processId: str = Field(description="过程版本id")
    executeFlowVersionId: str = Field(description="执行级版本id")
    modelType: str = Field(description="过程类型")
    procedureId: str = Field(description="属性级查询画布入参")
    valueChainId: str = Field(description="属性级查询画布入参")
    valueFlowVersionId: str = Field(description="属性级查询画布入参")


class Activity(BaseModel):
    activityLabelId: str = Field(description="活动id")
    activityBasicId: str = Field(description="活动点basic id")


class ProcessPublishCallbackBody(BaseModel):
    newProcesConfig: ProcesConfig
    activityList: list[Activity]


class ProcessPublishCallback(Resource):
    """
    脑建立执行级业务流发布回调接口
    """

    @login_required
    def post(self):
        try:
            json_data = request.get_json(force=True)
            body = ProcessPublishCallbackBody(**json_data)
        except ValidationError as e:
            return {'code': 400, 'msg': '参数校验失败', 'errors': e.errors()}, 400
        try:
            # 1. 查询过程模型关联的app valueChainId
            app_custom_configs: List[AppCustomConfig] = db.session.query(AppCustomConfig).filter(
                AppCustomConfig.valueChainId == body.newProcesConfig.valueChainId,
            ).with_for_update().all()

            activity_dict = {activity.activityBasicId: activity for activity in body.activityList}

            # 2. 更新过程模型参数，判断大小升版 valueFlowVersionId
            for custom_config in app_custom_configs:
                new_activity = activity_dict.get(custom_config.activityBasicId, None)
                # 如果活动被删除，标记为升版
                if not new_activity:
                    custom_config.upgradeStatus = True
                    continue

                # 如果活动升版，升版标记
                if custom_config.valueFlowVersionId != body.newProcesConfig.valueFlowVersionId:
                    custom_config.upgradeStatus = True
                # 更新版本参数
                custom_config.processId = body.newProcesConfig.processId
                custom_config.executeFlowVersionId = body.newProcesConfig.executeFlowVersionId
                custom_config.modelType = body.newProcesConfig.modelType
                custom_config.procedureId = body.newProcesConfig.procedureId
                custom_config.valueFlowVersionId = body.newProcesConfig.valueFlowVersionId
                custom_config.activityLabelId = new_activity.activityLabelId

            db.session.commit()
            return cbrain_response(None, "更新成功")
        except Exception as e:
            db.session.rollback()
            return cbrain_response_fail(500, "更新失败")


api.add_resource(ProcessPublishCallback, "/apps/processPublishCallback")
