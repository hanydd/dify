import ast
import base64
import hashlib
import json
from typing import Any, Tuple, Union
import json
from typing import Any, Tuple
from urllib import request
import requests
import boto3
from botocore.client import Config

import services
from common.sipoc_model import SipocModelConfig, NodeObject
from models import db, UploadFile, Document, AppModelConfig, Account, EndUser
from services.dataset_service import DocumentService
from services.entities.knowledge_entities.knowledge_entities import KnowledgeConfig
from services.file_service import FileService
from services.tag_service import TagService


class SipocService:
    def __init__(self, ):
        pass


    @staticmethod
    def generate_sipoc_kv(sipoc_config: SipocModelConfig, use_kv: bool = True) -> dict:
        """
        Generate sipoc kv from sipoc config，解析sipoc数据，转化为key，value字典
        :param sipoc_config: sipoc config
        :return:
        """
        if use_kv and sipoc_config.modelContextKV:
            return sipoc_config.modelContextKV
        sipoc_kv = {}
        iorcConfig = sipoc_config.modelContext
        if iorcConfig:
            if iorcConfig.inputNodes:
                for inputNode in iorcConfig.inputNodes:
                    #print("generate sipoc_kv inputNode", inputNode)
                    node_kv = SipocService.generate_node_kv(inputNode, 'ctx_input')
                    sipoc_kv.update(node_kv)
            if iorcConfig.outputNodes:
                for outputNode in iorcConfig.outputNodes:
                    #print("generate sipoc_kv outputNode", outputNode)
                    node_kv = SipocService.generate_node_kv(outputNode, 'ctx_output')
                    sipoc_kv.update(node_kv)
            if iorcConfig.controlNodes:
                for controlNode in iorcConfig.controlNodes:
                    #print("generate sipoc_kv controlNode", controlNode)
                    node_kv = SipocService.generate_node_kv(controlNode, 'ctx_control')
                    sipoc_kv.update(node_kv)

        return sipoc_kv

    @staticmethod
    def generate_sipoc_output_kv(sipoc_config: SipocModelConfig, use_kv: bool = True) -> dict:
        """
        Generate sipoc kv from sipoc config，解析sipoc数据，转化为key，value字典
        :param sipoc_config: sipoc config
        :return:
        """
        if use_kv and sipoc_config.modelGenerateKV:
            return sipoc_config.modelGenerateKV
        sipoc_kv = {}
        iorcConfig = sipoc_config.modelGenerate
        if iorcConfig:
            if iorcConfig.outputNodes:
                print("generate_sipoc_output_kv iorcConfig.outputNodes", iorcConfig.outputNodes)
                for outputNode in iorcConfig.outputNodes:
                    print("generate_sipoc_output_kv outputNode", outputNode)
                    node_kv = SipocService.generate_output_node_kv(outputNode, 'gen_output')
                    print("generate_sipoc_output_kv node_kv:", node_kv)
                    sipoc_kv.update(node_kv)
        print("generate_sipoc_output_kv sipoc_kv:", sipoc_kv)
        return sipoc_kv

    @staticmethod
    def fillup_sipoc_output_kv(sipoc_config: SipocModelConfig, output_kv: dict) -> SipocModelConfig:
        """
        Generate sipoc kv from sipoc config，解析sipoc数据，转化为key，value字典
        :param sipoc_config: sipoc config
        :return:
        """
        #  TODO
        if not output_kv or not sipoc_config.modelGenerate:
            return sipoc_config
        for outputNode in sipoc_config.modelGenerate.outputNodes:
            SipocService.fillup_node_kv(outputNode, 'gen_output', output_kv)
        return sipoc_config

    @staticmethod
    def convert_sipoc_output_kv(user_input_form: str, output_kv: str) -> str:
        """
        将sipoc的输出kv，填充到SipocModelConfig对象中
        """

        if not output_kv or not user_input_form:
            return ""

        def get_output_json(str):
            index = str.find("```json")
            if index != -1:
                str = str[index + 7:]
            index = str.find("```")
            if index != -1:
                str = str[:index]
            return str
        output_kv = get_output_json(output_kv)
        try:
            output_kv = json.loads(output_kv)
        except:
            print("convert_sipoc_output_kv output_kv:", output_kv)
            return ""
        user_input_form = json.loads(user_input_form)
        print("convert_sipoc_output_kv user_input_form:", user_input_form)

        sipoc_config = None
        for item in user_input_form:
            if 'sipoc_config' in item.keys():
                sipoc_config = SipocModelConfig(**item['sipoc_config'])
                break
        print("convert_sipoc_output_kv sipoc_config:", sipoc_config)
        if not sipoc_config or not sipoc_config.modelGenerate:
            return ""
        for outputNode in sipoc_config.modelGenerate.outputNodes:
            SipocService.fillup_node_kv(outputNode, 'gen_output', output_kv)
        return ", sipoc_config: " + sipoc_config.model_dump_json()


    @staticmethod
    def generate_node_kv(nodeObj: NodeObject, prefix: str) -> dict:

        sipoc_kv = {}
        key = prefix + ':##node##' + nodeObj.label
        if nodeObj.property:
            for prop in nodeObj.property:
                if not prop.name:
                    continue
                # input:##node##xx_label.##prop##xx_prop
                key1 = key + '.##prop##' + prop.name
                if prop.value:
                    sipoc_kv[key1] = prop.value
        if nodeObj.subNodes:
            for subNode in nodeObj.subNodes:
                key1 = key + '.##edge##' + subNode.relateEdge + '##' + subNode.label
                if subNode.property:
                    for prop in subNode.property:
                        if not prop.name:
                            continue
                        # input:##node##xx_label.##edge##xx_edge##xx_label.##prop##xx_prop
                        key2 = key1 + '.##prop##' + prop.name
                        if prop.value:
                            sipoc_kv[key2] = prop.value

        return sipoc_kv

    @staticmethod
    def generate_output_node_kv(nodeObj: NodeObject, prefix: str) -> dict:
        sipoc_kv = {}
        key = prefix + ':##node##' + nodeObj.label
        if nodeObj.property:
            for prop in nodeObj.property:
                if not prop.name:
                    continue
                # input:##node##xx_label.##prop##xx_prop
                key1 = key + '.##prop##' + prop.name
                sipoc_kv[key1] = ""
        if nodeObj.subNodes:
            for subNode in nodeObj.subNodes:
                key1 = key + '.##edge##' + subNode.relateEdge + '##' + subNode.label
                if subNode.property:
                    for prop in subNode.property:
                        if not prop.name:
                            continue
                        # input:##node##xx_label.##edge##xx_edge##xx_label.##prop##xx_prop
                        key2 = key1 + '.##prop##' + prop.name
                        sipoc_kv[key2] = ""

        return sipoc_kv

    @staticmethod
    def fillup_node_kv(nodeObj: NodeObject, prefix: str, output_kv: dict) -> NodeObject:
        key = prefix + ':##node##' + nodeObj.label
        if nodeObj.property:
            for prop in nodeObj.property:
                if not prop.name:
                    continue
                # input:##node##xx_label.##prop##xx_prop
                key1 = key + '.##prop##' + prop.name
                if key1 in output_kv:
                    prop.value = output_kv[key1]
        if nodeObj.subNodes:
            for subNode in nodeObj.subNodes:
                key1 = key + '.##edge##' + subNode.relateEdge + '##' + subNode.label
                if subNode.property:
                    for prop in subNode.property:
                        if not prop.name:
                            continue
                        # input:##node##xx_label.##edge##xx_edge##xx_label.##prop##xx_prop
                        key2 = key1 + '.##prop##' + prop.name
                        if key2 in output_kv:
                            prop.value = output_kv[key2]
        return nodeObj

    @staticmethod
    def is_file_kv(key: str, value: Any):
        """
        Check if the key is a sipoc file key，检查values是否是sipoc文件附件地址
        :param key:
        :param value: [{"name":"导出内容 (40).csv","url":"/cbrain-oss/oss-execute/20241118/%E5%AF%BC%E5%87%BA%E5%86%85%E5%AE%B9%20%2840%29-1731894328435.csv"}]
        :return:
        """
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and 'name' in item and 'url' in item:
                    return True, item['url']
        elif isinstance(value, str) and 'name' in value and 'url' in value:
            value = json.loads(value)
            for item in value:
                if isinstance(item, dict) and 'name' in item and 'url' in item:
                    return True, item['url']
        return False, ""

    @staticmethod
    def handle_sipoc_file(key: str, value: Any, app_config: dict, user: Union[Account, EndUser]) -> dict:
        """
        Handle sipoc file，处理sipoc文件附件，从C大脑下载文件，上传到dify文件存储，并且构建默认知识库，更新app_config
        :param key:
        :param value:
        :param app_config:
        :return:
        """

        # download file from cbrain minio
        file_content, filename, content_type, filehash, size = SipocService.download_file_from_cbrain_minio(value)

        # 判断下载的文件是否已经存在，如果存在，则不重复上传，并且判断文件是否已经被知识库引用，如果引用，也不再继续创建知识库
        upload_file = db.session.query(UploadFile).filter(UploadFile.hash == filehash).first()
        print(f"upload_file from db: {upload_file}")
        if not upload_file:
            # 如果找不到文件，则上传文件并创建知识库
            try:
                upload_file = FileService.upload_file(
                    filename=filename,
                    content=file_content,
                    mimetype=content_type,
                    user=user,
                    source="datasets",
                )
            except Exception as e:
                raise e

            knowledge_config = SipocService.generate_default_knowledge_config(upload_file.id)
            try:
                dataset, documents, batch = DocumentService.save_document_without_dataset_id(
                    tenant_id=user.current_tenant_id, knowledge_config=knowledge_config, account=user
                )
                dataset_id = dataset.id

            except Exception as ex:
                raise ex
        else:
            document = db.session.query(Document).filter(Document.data_source_info.ilike(f"%{upload_file.id}%")).first()
            if not document:
                # 如果文件没有被引用到知识库，则创建知识库
                knowledge_config = SipocService.generate_default_knowledge_config(upload_file.id)
                try:
                    dataset, documents, batch = DocumentService.save_document_without_dataset_id(
                        tenant_id=user.current_tenant_id, knowledge_config=knowledge_config,
                        account=user
                    )
                    dataset_id = dataset.id
                except Exception as ex:
                    raise ex
            else:
                # 如果文件已经被引用到知识库，则不创建知识库
                dataset_id = document.dataset_id

        app_config["dataset_configs"]["datasets"]["datasets"].append({
            "dataset": {
                "id": dataset_id,
                "enabled": True
            }
        })
        # 新增知识库后，需要绑定自动生成的标签
        TagService.bind_knowledge_autogen_tag(dataset_id, tenant_id=user.current_tenant_id)

        # 新增知识库后，需要更新app_config里面的pre_prompt，如果sipoc附件参数在pre_prompt中，进行替换，否则将使用知识库回答文件，加到提示词最后
        if key in app_config["pre_prompt"]:
            app_config["pre_prompt"] = app_config["pre_prompt"].replace(key, f"(你可以使用知识库来回答用户的问题, 知识库的id是：{dataset_id})")
        else:
            app_config["pre_prompt"] += f"(你可以使用知识库来回答用户的问题, 知识库的id是：{dataset_id})"
        print(f"app_config.pre_prompt: {app_config["pre_prompt"]}")
        return app_config
        # response = {"dataset": dataset, "documents": documents, "batch": batch}

    @staticmethod
    def is_sipoc_output(value: str) -> bool:
        if "gen_output" in value:
            return True
        return False

    @staticmethod
    def generate_default_knowledge_config(file_id: str) -> KnowledgeConfig:
        """
        Generate default knowledge config，生成默认的知识库配置
        :param file_id:
        :return:
        """

        args = {
            "indexing_technique": "high_quality",
            "embedding_model": "embedding",
            "embedding_model_provider": "langgenius/openai_api_compatible/openai_api_compatible",
            "data_source": {
                "type": "upload_file",
                "info_list": {
                    "data_source_type": "upload_file",
                    "file_info_list": {
                        "file_ids": [file_id]
                    }
                },
            },
            "process_rule": {
                "rules": {
                    "pre_processing_rules": [
                        {
                            "id": "remove_extra_spaces",
                            "enabled": True
                        }, {
                            "id": "remove_urls_emails",
                            "enabled": False
                        }
                    ],
                    "segmentation": {
                        "separator": "\n\n",
                        "max_tokens": 1024,
                        "chunk_overlap": 50
                    }
                },
                "mode": "custom"
            },
            "doc_form": "text_model",
            "doc_language": "Chinese Simplified",
            "retrieval_model": {
                "search_method": "semantic_search",    # 向量检索
                "reranking_enable": True,
                "reranking_model": {
                    "reranking_provider_name": "",
                    "reranking_model_name": ""
                },
                "top_k": 3,
                "score_threshold_enabled": False,
                "score_threshold": 0.5
            }
        }

        knowledge_config = KnowledgeConfig(**args)

        return knowledge_config


    @staticmethod
    def download_file_from_cbrain_minio(file_path: str) -> tuple[bytes, str, str | None, str | None, int | None]:
        """
        Download file from cbrain minio
        :param file_path:
        :return:
        """

        endpoint_test = "http://172.16.23.77:9000"
        access_key_test = "666e6cYxFod8Dr3QMnRx"
        secret_key_test = "F3xWGSfl2B6xqCo5EReTiUnjHG6fYEVFZ4LX8jh2"
        bucket_name_test = "cbrain"

        filename = file_path.split("/")[-1]

        s3 = boto3.client(
            's3',
            endpoint_url=endpoint_test,
            aws_access_key_id=access_key_test,
            aws_secret_access_key=secret_key_test,
            config=Config(signature_version='s3v4')
        )

        try:
            # # 下载文件
            # s3.download_file(
            #     Bucket=bucket_name_test,
            #     Key=file_path,
            #     Filename=local_file_path
            # )
            # print(f"文件下载成功: {minio_object_name} -> {local_file_path}")
            # 获取文件元数据
            obj_info = s3.head_object(Bucket=bucket_name_test, Key=file_path)
            print(obj_info)
            print(obj_info['ContentLength'])
            print(obj_info['ContentType'])
            print(obj_info['ETag'])
            content = s3.get_object(Bucket=bucket_name_test, Key=file_path)['Body'].read()
            filehash = hashlib.sha3_256(content).hexdigest()
            print(filehash)
            return content, filename, obj_info['ContentType'], filehash, obj_info['ContentLength']

        except Exception as e:
            print(f"下载失败: {str(e)}")
        pass


    @staticmethod
    def convert_file_to_text(file_content: bytes, file_name: str) -> tuple[bytes,str]:
        """
        Convert file content to text, 将包含图片的文件，通过ocr等技术转化成文本文件
        """
        try:
            file_flow_base64 = base64.b64encode(file_content).decode('utf-8')
            payload = {
                "file_flow": file_flow_base64,
                "file_name": file_name
            }

            response = requests.post("http://172.16.23.103:5551/handle_files", json=payload)
            response.raise_for_status()  # 检查请求是否成功

            # 解析响应
            response_data = response.json()
            file_content_data = response_data.get("file_content")
            base64_bytes = file_content_data.encode('utf-8')
            decoded_bytes = base64_bytes.b64decode(base64_bytes)
            returned_file_name = response_data.get("file_name")
            return decoded_bytes, returned_file_name
        except Exception as e:
            print(f"转换失败: {str(e)}")

