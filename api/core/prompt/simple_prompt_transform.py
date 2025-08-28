import enum
import json
import os
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Optional, cast, Dict

from extensions.ext_database import db
from core.app.app_config.entities import PromptTemplateEntity
from core.app.entities.app_invoke_entities import ModelConfigWithCredentialsEntity
from core.file import file_manager
from core.memory.token_buffer_memory import TokenBufferMemory
from core.model_runtime.entities.message_entities import (
    ImagePromptMessageContent,
    PromptMessage,
    PromptMessageContentUnionTypes,
    SystemPromptMessage,
    TextPromptMessageContent,
    UserPromptMessage,
)
from core.prompt.entities.advanced_prompt_entities import MemoryConfig
from core.prompt.prompt_transform import PromptTransform
from core.prompt.utils.prompt_template_parser import PromptTemplateParser, WITH_VARIABLE_TMPL_REGEX, REGEX
from models.enums import SceneType
from models.model import AppMode, App, AppModelConfig
from core.prompt.prompt_templates.fill_doc_prompt_template import FILL_DOC_PROMPT_TEMPLATE
from core.prompt.prompt_templates.fill_table_prompt_template import FILL_TABLE_PROMPT_TEMPLATE

if TYPE_CHECKING:
    from core.file.models import File


class ModelMode(enum.StrEnum):
    COMPLETION = "completion"
    CHAT = "chat"


prompt_file_contents: dict[str, Any] = {}


class SimplePromptTransform(PromptTransform):
    """
    Simple Prompt Transform for Chatbot App Basic Mode.
    """

    def get_prompt(
        self,
        app_mode: AppMode,
        prompt_template_entity: PromptTemplateEntity,
        inputs: Mapping[str, str],
        query: str,
        files: Sequence["File"],
        context: Optional[str],
        memory: Optional[TokenBufferMemory],
        model_config: ModelConfigWithCredentialsEntity,
        image_detail_config: Optional[ImagePromptMessageContent.DETAIL] = None,
    ) -> tuple[list[PromptMessage], Optional[list[str]]]:
        inputs = {key: str(value) for key, value in inputs.items()}
        model_mode = ModelMode(model_config.mode)
        if model_mode == ModelMode.CHAT:
            prompt_messages, stops = self._get_chat_model_prompt_messages(
                app_mode=app_mode,
                pre_prompt=prompt_template_entity.simple_prompt_template or "",
                inputs=inputs,
                query=query,
                files=files,
                context=context,
                memory=memory,
                model_config=model_config,
                image_detail_config=image_detail_config,
            )
        else:
            prompt_messages, stops = self._get_completion_model_prompt_messages(
                app_mode=app_mode,
                pre_prompt=prompt_template_entity.simple_prompt_template or "",
                inputs=inputs,
                query=query,
                files=files,
                context=context,
                memory=memory,
                model_config=model_config,
                image_detail_config=image_detail_config,
            )

        return prompt_messages, stops

    def _get_prompt_str_and_rules(
        self,
        app_mode: AppMode,
        model_config: ModelConfigWithCredentialsEntity,
        pre_prompt: str,
        inputs: dict,
        query: Optional[str] = None,
        context: Optional[str] = None,
        histories: Optional[str] = None,
    ) -> tuple[str, dict]:
        # get prompt template
        prompt_template_config = self.get_prompt_template(
            app_mode=app_mode,
            provider=model_config.provider,
            model=model_config.model,
            pre_prompt=pre_prompt,
            has_context=context is not None,
            query_in_prompt=query is not None,
            with_memory_prompt=histories is not None,
        )
        # print("_get_prompt_str_and_rules model_config:",model_config)
        # prompt_template_config = self.get_prompt_template_by_scene_type(
        #     app_mode=app_mode,
        #     scene_type=self.get_scene_type(model_config),
        #     inputs=inputs,
        #     provider=model_config.provider,
        #     model=model_config.model,
        #     pre_prompt=pre_prompt,
        #     has_context=context is not None,
        #     query_in_prompt=query is not None,
        #     with_memory_prompt=histories is not None,
        # )

        variables = {k: inputs[k] for k in prompt_template_config["custom_variable_keys"] if k in inputs}

        for v in prompt_template_config["special_variable_keys"]:
            # support #context#, #query# and #histories#
            if v == "#context#":
                variables["#context#"] = context or ""
            elif v == "#query#":
                variables["#query#"] = query or ""
            elif v == "#histories#":
                variables["#histories#"] = histories or ""

        prompt_template = prompt_template_config["prompt_template"]
        prompt = prompt_template.format(variables)

        return prompt, prompt_template_config["prompt_rules"]

    def get_prompt_template(
        self,
        app_mode: AppMode,
        provider: str,
        model: str,
        pre_prompt: str,
        has_context: bool,
        query_in_prompt: bool,
        with_memory_prompt: bool = False,
    ) -> dict:
        prompt_rules = self._get_prompt_rule(app_mode=app_mode, provider=provider, model=model)

        custom_variable_keys = []
        special_variable_keys = []

        prompt = ""
        for order in prompt_rules["system_prompt_orders"]:
            if order == "context_prompt" and has_context:
                prompt += prompt_rules["context_prompt"]
                special_variable_keys.append("#context#")
            elif order == "pre_prompt" and pre_prompt:
                prompt += pre_prompt + "\n"
                pre_prompt_template = PromptTemplateParser(template=pre_prompt)
                custom_variable_keys = pre_prompt_template.variable_keys
            elif order == "histories_prompt" and with_memory_prompt:
                prompt += prompt_rules["histories_prompt"]
                special_variable_keys.append("#histories#")

        if query_in_prompt:
            prompt += prompt_rules.get("query_prompt", "{{#query#}}")
            special_variable_keys.append("#query#")

        return {
            "prompt_template": PromptTemplateParser(template=prompt),
            "custom_variable_keys": custom_variable_keys,
            "special_variable_keys": special_variable_keys,
            "prompt_rules": prompt_rules,
        }

    def _get_chat_model_prompt_messages(
        self,
        app_mode: AppMode,
        pre_prompt: str,
        inputs: dict,
        query: str,
        context: Optional[str],
        files: Sequence["File"],
        memory: Optional[TokenBufferMemory],
        model_config: ModelConfigWithCredentialsEntity,
        image_detail_config: Optional[ImagePromptMessageContent.DETAIL] = None,
    ) -> tuple[list[PromptMessage], Optional[list[str]]]:
        prompt_messages: list[PromptMessage] = []

        # get prompt
        prompt, _ = self._get_prompt_str_and_rules(
            app_mode=app_mode,
            model_config=model_config,
            pre_prompt=pre_prompt,
            inputs=inputs,
            query=None,
            context=context,
        )

        if prompt and query:
            prompt_messages.append(SystemPromptMessage(content=prompt))

        if memory:
            prompt_messages = self._append_chat_histories(
                memory=memory,
                memory_config=MemoryConfig(
                    window=MemoryConfig.WindowConfig(
                        enabled=False,
                    )
                ),
                prompt_messages=prompt_messages,
                model_config=model_config,
            )

        if query:
            prompt_messages.append(self._get_last_user_message(query, files, image_detail_config))
        else:
            prompt_messages.append(self._get_last_user_message(prompt, files, image_detail_config))

        return prompt_messages, None

    def _get_completion_model_prompt_messages(
        self,
        app_mode: AppMode,
        pre_prompt: str,
        inputs: dict,
        query: str,
        context: Optional[str],
        files: Sequence["File"],
        memory: Optional[TokenBufferMemory],
        model_config: ModelConfigWithCredentialsEntity,
        image_detail_config: Optional[ImagePromptMessageContent.DETAIL] = None,
    ) -> tuple[list[PromptMessage], Optional[list[str]]]:
        # get prompt
        prompt, prompt_rules = self._get_prompt_str_and_rules(
            app_mode=app_mode,
            model_config=model_config,
            pre_prompt=pre_prompt,
            inputs=inputs,
            query=query,
            context=context,
        )

        if memory:
            tmp_human_message = UserPromptMessage(content=prompt)

            rest_tokens = self._calculate_rest_token([tmp_human_message], model_config)
            histories = self._get_history_messages_from_memory(
                memory=memory,
                memory_config=MemoryConfig(
                    window=MemoryConfig.WindowConfig(
                        enabled=False,
                    )
                ),
                max_token_limit=rest_tokens,
                human_prefix=prompt_rules.get("human_prefix", "Human"),
                ai_prefix=prompt_rules.get("assistant_prefix", "Assistant"),
            )

            # get prompt
            prompt, prompt_rules = self._get_prompt_str_and_rules(
                app_mode=app_mode,
                model_config=model_config,
                pre_prompt=pre_prompt,
                inputs=inputs,
                query=query,
                context=context,
                histories=histories,
            )

        stops = prompt_rules.get("stops")
        if stops is not None and len(stops) == 0:
            stops = None

        return [self._get_last_user_message(prompt, files, image_detail_config)], stops

    def _get_last_user_message(
        self,
        prompt: str,
        files: Sequence["File"],
        image_detail_config: Optional[ImagePromptMessageContent.DETAIL] = None,
    ) -> UserPromptMessage:
        if files:
            prompt_message_contents: list[PromptMessageContentUnionTypes] = []
            prompt_message_contents.append(TextPromptMessageContent(data=prompt))
            for file in files:
                prompt_message_contents.append(
                    file_manager.to_prompt_message_content(file, image_detail_config=image_detail_config)
                )

            prompt_message = UserPromptMessage(content=prompt_message_contents)
        else:
            prompt_message = UserPromptMessage(content=prompt)

        return prompt_message

    def _get_prompt_rule(self, app_mode: AppMode, provider: str, model: str) -> dict:
        """
        Get simple prompt rule.
        :param app_mode: app mode
        :param provider: model provider
        :param model: model name
        :return:
        """
        prompt_file_name = self._prompt_file_name(app_mode=app_mode, provider=provider, model=model)

        # Check if the prompt file is already loaded
        if prompt_file_name in prompt_file_contents:
            return cast(dict, prompt_file_contents[prompt_file_name])

        # Get the absolute path of the subdirectory
        prompt_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "prompt_templates")
        json_file_path = os.path.join(prompt_path, f"{prompt_file_name}.json")

        # Open the JSON file and read its content
        with open(json_file_path, encoding="utf-8") as json_file:
            content = json.load(json_file)

            # Store the content of the prompt file
            prompt_file_contents[prompt_file_name] = content

            return cast(dict, content)

    def _prompt_file_name(self, app_mode: AppMode, provider: str, model: str) -> str:
        # baichuan
        is_baichuan = False
        if provider == "baichuan":
            is_baichuan = True
        else:
            baichuan_supported_providers = ["huggingface_hub", "openllm", "xinference"]
            if provider in baichuan_supported_providers and "baichuan" in model.lower():
                is_baichuan = True

        if is_baichuan:
            if app_mode == AppMode.COMPLETION:
                return "baichuan_completion"
            else:
                return "baichuan_chat"

        # common
        if app_mode == AppMode.COMPLETION:
            return "common_completion"
        else:
            return "common_chat"

    def get_prompt_template_by_scene_type(
        self,
        app_mode: AppMode,
        app_record: App,
        #scene_type: SceneType,
        inputs: dict,
        provider: str,
        model: str,
        pre_prompt: str,
        has_context: bool,
        query_in_prompt: bool,
        with_memory_prompt: bool = False,
    ) -> dict:
        #print("get_prompt_template_by_scene_type scene_type:", scene_type)
        # 从配置中获取原始场景类型字符串（默认为空）
        original_app_model_config = (
            db.session.query(AppModelConfig).where(AppModelConfig.id == app_record.app_model_config_id).first()
        )
        configs_dict = original_app_model_config.configs_dict
        user_inputs = original_app_model_config.user_input_form_list
        scene_type=self.get_scene_type(configs_dict)

        # 1. 根据场景类型选择基础模板，外部传入的pre_prompt优先于默认模板
        base_template = ""
        if scene_type == SceneType.GENERATE_DOCUMENT:  # 文档生成场景
            base_template = FILL_DOC_PROMPT_TEMPLATE
        elif scene_type == SceneType.FILL_FORM:  # 表格生成场景
            base_template = FILL_TABLE_PROMPT_TEMPLATE
        else:
            base_template = ""
        print("base_template:", base_template)
        base_template = self.process_pre_prompt(base_template, user_inputs, inputs, False)


        # 2. 生成final_pre_prompt
        if pre_prompt:
            # 去除两端空行后拼接，避免多余空白
            final_pre_prompt = f"{pre_prompt.rstrip()}\n\n{base_template.lstrip()}"
        else:
            final_pre_prompt = base_template
        print("final_pre_prompt:", final_pre_prompt)

        # 3. 获取提示词规则（修复场景类型参数传递）
        prompt_rules = self._get_prompt_rule(
            app_mode=app_mode,
            provider=provider,
            model=model
        )


        custom_variable_keys = []
        special_variable_keys = []

        prompt = ""
        for order in prompt_rules["system_prompt_orders"]:
            if order == "context_prompt" and has_context:
                prompt += prompt_rules["context_prompt"]
                special_variable_keys.append("#context#")
            elif order == "pre_prompt" and final_pre_prompt:
                pre_prompt_template = PromptTemplateParser(template=pre_prompt)
                custom_variable_keys = pre_prompt_template.variable_keys
            elif order == "histories_prompt" and with_memory_prompt:
                prompt += prompt_rules["histories_prompt"]
                special_variable_keys.append("#histories#")

        if query_in_prompt:
            prompt += prompt_rules.get("query_prompt", "{{#query#}}")
            special_variable_keys.append("#query#")

        return {
            "prompt_template": PromptTemplateParser(template=prompt),
            "custom_variable_keys": custom_variable_keys,
            "special_variable_keys": special_variable_keys,
            "prompt_rules": prompt_rules,
        }


    # 结合预定的模版进行pre_prompt的处理
    def process_pre_prompt(self, template_str: str, user_inputs: list, inputs: dict, with_variable_tmpl: bool = False) -> str:
        """
        处理pre_prompt模板
        :return: 处理后的模板字符串 + 提取的占位符变量列表
        """
        import re

        print("process_pre_prompt  inputs:", inputs)

        # 1. 从inputs中提取以ctx_开头的键值对，构成input_key_values字典
        input_key_values = {
            key: value for key, value in inputs.items()
            if key.startswith('ctx_')
        }
        print("input_key_values:", input_key_values)

        # 2. 从inputs中提取以gen_开头的键值对，构成output_results字典
        output_results = {
            key: value for key, value in inputs.items()
            if key.startswith('gen_')
        }
        print("output_results:", output_results)

        #output_related_information: Dict[str, Any] = {}
        # for item in user_inputs:
        #     if isinstance(item, dict) and "sipoc_config" in item:
        #         output_related_information = item["sipoc_config"]
        #         break
        output_related_information = ""
        sipoc_config_str = inputs.get("sipoc_config")
        if not sipoc_config_str:
            output_related_information = sipoc_config_str
        #output_related_information = inputs.get("sipoc_config", {})
        combined_info = {
            "input_key_values": input_key_values,
            "output_results": output_results,
            "output_related_information": output_related_information
        }
        print("combined_info:", combined_info)

        # # 4. 复用已定义的正则表达式（与PromptTemplateParser保持一致）
        # pattern = WITH_VARIABLE_TMPL_REGEX if with_variable_tmpl else REGEX
        #
        # # 5. 定义替换函数：处理每个匹配到的占位符
        # def replace_placeholder(match: re.Match) -> str:
        #     var_content = match.group(1)  # 获取变量内容
        #     original_placeholder = match.group(0)  # 原始占位符
        #
        #     # 6. 处理特殊变量（带#的变量），去除#后作为key查找
        #     input_key = var_content.strip("#")
        #     if input_key in combined_info:
        #         return str(combined_info[input_key])  # 替换为实际值
        #     else:
        #         return original_placeholder  # 未找到则保留原始占位符
        #
        # # 7. 执行全局替换并统一格式
        # replaced_template = pattern.sub(replace_placeholder, template_str)
        result = template_str
        for key, value in combined_info.items():
            # 假设占位符格式为 ${key}，可根据实际情况修改
            placeholder = f"{{#{key}#}}"
            result = result.replace(placeholder, str(value))
        return result.rstrip("\n") + "\n"

    def get_scene_type(self, configs_dict: dict) -> SceneType:
        """
        从模型配置中解析并返回SceneType枚举值

        :param model_config: 模型配置对象
        :return: 转换后的SceneType枚举值（确保返回类型为SceneType）
        """

        # 从配置中获取原始场景类型字符串（默认为空）
        # original_app_model_config = (
        #     db.session.query(AppModelConfig).where(AppModelConfig.id == app_record.app_model_config_id).first()
        # )
        # configs_dict = original_app_model_config.configs_dict
        # print("app_record.app_model_config_id", app_record.app_model_config_id)
        #print("get_scene_type configs_dict", configs_dict)

        scene_type_str: Optional[str] = configs_dict.get("scene_type")
        print("get_scene_type configs_dict", configs_dict)

        # 处理空值情况
        if not scene_type_str:
            return SceneType.UNDEFINED

        normalized_str = scene_type_str.lower()

        # 尝试转换为SceneType枚举
        try:
            return SceneType(normalized_str)
        except ValueError:
            # 若字符串不在枚举范围内，返回未定义
            return SceneType.UNDEFINED

    def get_prompt_by_scene(
        self,
        app_mode: AppMode,
        app_record: App,
        prompt_template_entity: PromptTemplateEntity,
        inputs: Mapping[str, str],
        query: str,
        files: Sequence["File"],
        context: Optional[str],
        memory: Optional[TokenBufferMemory],
        model_config: ModelConfigWithCredentialsEntity,
        image_detail_config: Optional[ImagePromptMessageContent.DETAIL] = None,
    ) -> tuple[list[PromptMessage], Optional[list[str]]]:
        inputs = {key: str(value) for key, value in inputs.items()}
        model_mode = ModelMode(model_config.mode)
        if model_mode == ModelMode.CHAT:
            prompt_messages, stops = self._get_chat_model_prompt_messages_by_scene(
                app_mode=app_mode,
                app_record=app_record,
                pre_prompt=prompt_template_entity.simple_prompt_template or "",
                inputs=inputs,
                query=query,
                files=files,
                context=context,
                memory=memory,
                model_config=model_config,
                image_detail_config=image_detail_config,
            )
        else:
            prompt_messages, stops = self._get_completion_model_prompt_messages_by_scene(
                app_mode=app_mode,
                app_record=app_record,
                pre_prompt=prompt_template_entity.simple_prompt_template or "",
                inputs=inputs,
                query=query,
                files=files,
                context=context,
                memory=memory,
                model_config=model_config,
                image_detail_config=image_detail_config,
            )

        return prompt_messages, stops

    def _get_chat_model_prompt_messages_by_scene(
        self,
        app_mode: AppMode,
        app_record: App,
        pre_prompt: str,
        inputs: dict,
        query: str,
        context: Optional[str],
        files: Sequence["File"],
        memory: Optional[TokenBufferMemory],
        model_config: ModelConfigWithCredentialsEntity,
        image_detail_config: Optional[ImagePromptMessageContent.DETAIL] = None,
    ) -> tuple[list[PromptMessage], Optional[list[str]]]:
        prompt_messages: list[PromptMessage] = []

        # get prompt
        prompt, _ = self._get_prompt_str_and_rules_by_scene(
            app_mode=app_mode,
            app_record=app_record,
            model_config=model_config,
            pre_prompt=pre_prompt,
            inputs=inputs,
            query=None,
            context=context,
        )

        if prompt and query:
            prompt_messages.append(SystemPromptMessage(content=prompt))

        if memory:
            prompt_messages = self._append_chat_histories(
                memory=memory,
                memory_config=MemoryConfig(
                    window=MemoryConfig.WindowConfig(
                        enabled=False,
                    )
                ),
                prompt_messages=prompt_messages,
                model_config=model_config,
            )

        if query:
            prompt_messages.append(self._get_last_user_message(query, files, image_detail_config))
        else:
            prompt_messages.append(self._get_last_user_message(prompt, files, image_detail_config))

        return prompt_messages, None

    def _get_completion_model_prompt_messages_by_scene(
        self,
        app_mode: AppMode,
        app_record: App,
        pre_prompt: str,
        inputs: dict,
        query: str,
        context: Optional[str],
        files: Sequence["File"],
        memory: Optional[TokenBufferMemory],
        model_config: ModelConfigWithCredentialsEntity,
        image_detail_config: Optional[ImagePromptMessageContent.DETAIL] = None,
    ) -> tuple[list[PromptMessage], Optional[list[str]]]:
        # get prompt
        prompt, prompt_rules = self._get_prompt_str_and_rules_by_scene(
            app_mode=app_mode,
            app_record=app_record,
            model_config=model_config,
            pre_prompt=pre_prompt,
            inputs=inputs,
            query=query,
            context=context,
        )

        if memory:
            tmp_human_message = UserPromptMessage(content=prompt)

            rest_tokens = self._calculate_rest_token([tmp_human_message], model_config)
            histories = self._get_history_messages_from_memory(
                memory=memory,
                memory_config=MemoryConfig(
                    window=MemoryConfig.WindowConfig(
                        enabled=False,
                    )
                ),
                max_token_limit=rest_tokens,
                human_prefix=prompt_rules.get("human_prefix", "Human"),
                ai_prefix=prompt_rules.get("assistant_prefix", "Assistant"),
            )

            # get prompt
            prompt, prompt_rules = self._get_prompt_str_and_rules(
                app_mode=app_mode,
                app_record=app_record,
                model_config=model_config,
                pre_prompt=pre_prompt,
                inputs=inputs,
                query=query,
                context=context,
                histories=histories,
            )

        stops = prompt_rules.get("stops")
        if stops is not None and len(stops) == 0:
            stops = None

        return [self._get_last_user_message(prompt, files, image_detail_config)], stops

    def _get_prompt_str_and_rules_by_scene(
        self,
        app_mode: AppMode,
        app_record: App,
        model_config: ModelConfigWithCredentialsEntity,
        pre_prompt: str,
        inputs: dict,
        query: Optional[str] = None,
        context: Optional[str] = None,
        histories: Optional[str] = None,
    ) -> tuple[str, dict]:
        # get prompt template
        # prompt_template_config = self.get_prompt_template(
        #     app_mode=app_mode,
        #     provider=model_config.provider,
        #     model=model_config.model,
        #     pre_prompt=pre_prompt,
        #     has_context=context is not None,
        #     query_in_prompt=query is not None,
        #     with_memory_prompt=histories is not None,
        # )
        #print("_get_prompt_str_and_rules model_config:",model_config)
        prompt_template_config = self.get_prompt_template_by_scene_type(
            app_mode=app_mode,
            app_record=app_record,
            #scene_type=self.get_scene_type(app_record),
            inputs=inputs,
            provider=model_config.provider,
            model=model_config.model,
            pre_prompt=pre_prompt,
            has_context=context is not None,
            query_in_prompt=query is not None,
            with_memory_prompt=histories is not None,
        )

        variables = {k: inputs[k] for k in prompt_template_config["custom_variable_keys"] if k in inputs}

        for v in prompt_template_config["special_variable_keys"]:
            # support #context#, #query# and #histories#
            if v == "#context#":
                variables["#context#"] = context or ""
            elif v == "#query#":
                variables["#query#"] = query or ""
            elif v == "#histories#":
                variables["#histories#"] = histories or ""

        prompt_template = prompt_template_config["prompt_template"]
        prompt = prompt_template.format(variables)

        return prompt, prompt_template_config["prompt_rules"]


