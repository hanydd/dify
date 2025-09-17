from flask_restful import Resource, reqparse

from controllers.console import api
from controllers.console.app.error import PromptTemplateError
from controllers.console.app.wraps import get_app_model
from controllers.console.wraps import account_initialization_required, setup_required
from libs.login import login_required
from models.model import AppMode
import uuid
import json
import os

class QueryByTabApi(Resource):
    @setup_required
    def get(self):
        """按tab_type查询模板, 对应的模版内容"""
        # 1. 解析请求参数
        parser = reqparse.RequestParser()
        parser.add_argument(
            "tab_type",
            type=str,
            required=True,
            location="args",
            help="tab类型为字符串类型，用于指定模板分类"
        )
        parser.add_argument(
            "status",
            type=int,
            default=1,
            location="args",
            help="提示词模版的状态，当前默认为1"
        )
        args = parser.parse_args()
        target_tab = args["tab_type"]
        request_status = args["status"]

        # 2. 读取模板文件
        current_code_path = os.path.abspath(__file__)
        current_code_dir = os.path.dirname(current_code_path)
        template_file = os.path.join(current_code_dir, "tab_prompt_template.json")
        if not os.path.exists(template_file):
            raise PromptTemplateError(f"模板文件不存在：{template_file}")

        try:
            with open(template_file, "r", encoding="utf-8") as f:
                all_templates = json.load(f)  # 整个文件内容
        except json.JSONDecodeError:
            raise PromptTemplateError("模板文件格式错误，无法解析JSON")
        except Exception as e:
            raise PromptTemplateError(f"读取模板文件失败：{str(e)}")

        # 3. 提取目标tab的模板（直接通过顶层键访问）
        if target_tab not in all_templates:
            raise PromptTemplateError(f"模板文件中未定义{target_tab}类型的模板")

        # 获取该tab下的templates数组（默认空数组避免报错）
        target_templates = all_templates[target_tab].get("templates", [])
        if not target_templates:
            raise PromptTemplateError(f"{target_tab}类型下无可用模板")

        # 4. 动态处理模板字段
        for tpl in target_templates:
            # 生成唯一template_id
            tpl["template_id"] = f"tpl_{uuid.uuid4().hex[:12]}"
            # 确保tab_type与请求一致
            tpl["tab_type"] = target_tab

        # 5. 按新结构返回
        return {
            target_tab: {  # 顶层键为tab_type
                "templates": target_templates
            }
        }


api.add_resource(QueryByTabApi, "/templates/query-by-tab")
