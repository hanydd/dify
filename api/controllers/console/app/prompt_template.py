from flask_restful import Resource, reqparse

from controllers.console import api
from controllers.console.app.wraps import get_app_model
from controllers.console.wraps import account_initialization_required, setup_required
from libs.login import login_required
from models.model import AppMode
from flask import request
import uuid
from datetime import datetime
import json
import os


class QueryByTabApi(Resource):
    @setup_required
    @login_required
    @account_initialization_required
    @get_app_model(mode=[AppMode.AGENT_CHAT])
    def get(self, app_model):
        """根据tab类型和状态查询模板"""
        parser = reqparse.RequestParser()
        # 输入参数：tab_type（必填）、status（可选，默认1）
        parser.add_argument("tab_type", type=str, required=True,
                           location="args", help="Tab类型为必填项")
        parser.add_argument("status", type=int, choices=(1, 2, 3),
                           default=1, location="args", help="状态值必须为1、2或3")
        args = parser.parse_args()

        tab_type = args["tab_type"]
        status = args["status"]

        # 模板文件路径（示例：按tab_type命名文件，如 fill_form_template.json）
        template_file = f"templates/{tab_type}_template.json"
        if not os.path.exists(template_file):
            return {
                "code": 404,
                "message": f"未找到{tab_type}对应的模板文件",
                "data": None
            }, 404

        try:
            # 读取模板文件内容
            with open(template_file, "r", encoding="utf-8") as f:
                template_data = json.load(f)
        except Exception as e:
            return {
                "code": 500,
                "message": f"读取模板文件失败：{str(e)}",
                "data": None
            }, 500

        # 生成唯一模板ID、构造基础信息
        template_id = str(uuid.uuid4())
        create_time = "2025-09-01 10:30:00"
        update_time = "2025-09-10 15:20:00"

        # 从模板文件中提取content和attribute_list（文件需包含这两个字段）
        content = template_data.get("content", [
            {
                "label": "role",
                "name": "##角色",
                "value": ""
            },
            {
                "label": "task",
                "name": "##任务",
                "value": ""
            },
            {
                "label": "output",
                "name": "##输出",
                "value": ""
            }
        ])
        attribute_list = template_data.get("attribute_list", [
            {
                "attr_name": "input",
                "data_type": "string",
                "business_rules": "输入内容的业务规则说明"
            },
            {
                "attr_name": "output",
                "data_type": "string",
                "business_rules": "输出内容的业务规则说明"
            }
        ])

        # 构造最终响应结构
        return {
            "data": {
                "templates": [
                    {
                        "template_id": template_id,
                        "tab_type": tab_type,
                        "base_info": {
                            "template_name": "填表模板",
                            "status": status,
                            "create_time": create_time,
                            "update_time": update_time,
                            "is_deleted": 0
                        },
                        "content": content,
                        "attribute_list": attribute_list
                    }
                ]
            }
        }


api.add_resource(QueryByTabApi, "/templates/query-by-tab")
