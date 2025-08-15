import hashlib
from typing import Any, Tuple
from minio import Minio

import services
from common.sipoc_model import SipocModelConfig, NodeObject
from controllers.console.app.error import ProviderNotInitializeError, ProviderQuotaExceededError
from controllers.service_api.app.error import ProviderModelCurrentlyNotSupportError
from core.errors.error import ProviderTokenNotInitError, QuotaExceededError, ModelCurrentlyNotSupportError
from models import db, UploadFile, Document
from services.dataset_service import DocumentService
from services.entities.knowledge_entities.knowledge_entities import KnowledgeConfig
from services.errors.file import FileTooLargeError, UnsupportedFileTypeError
from services.file_service import FileService

from flask_login import current_user


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
                    node_kv = SipocService.generate_node_kv(inputNode, 'input')
                    sipoc_kv.update(node_kv)
            if iorcConfig.outputNodes:
                for outputNode in iorcConfig.outputNodes:
                    node_kv = SipocService.generate_node_kv(outputNode, 'output')
                    sipoc_kv.update(node_kv)
            if iorcConfig.controlNodes:
                for controlNode in iorcConfig.controlNodes:
                    node_kv = SipocService.generate_node_kv(controlNode, 'control')
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
                for outputNode in iorcConfig.outputNodes:
                    node_kv = SipocService.generate_node_kv(outputNode, 'output')
                    sipoc_kv.update(node_kv)

        return sipoc_kv

    @staticmethod
    def generate_node_kv(nodeObj: NodeObject, prefix: str) -> dict:

        sipoc_kv = {}
        key = prefix + ':##node##' + nodeObj.label
        if nodeObj.serviceProperty:
            for serviceProperty in nodeObj.serviceProperty:
                if not serviceProperty.name:
                    continue
                # input:##node##xx_label.##prop##xx_prop
                key1 = key + '.##prop##' + serviceProperty.name
                if serviceProperty.value:
                    sipoc_kv[key1] = serviceProperty.value
                else:
                    sipoc_kv[key1] = serviceProperty.defaultValue
        if nodeObj.subNodes:
            for subNode in nodeObj.subNodes:
                key1 = key + '.##edge##' + subNode.relateEdge + '##' + subNode.label
                if subNode.serviceProperty:
                    for serviceProperty in subNode.serviceProperty:
                        if not serviceProperty.name:
                            continue
                        # input:##node##xx_label.##edge##xx_edge##xx_label.##prop##xx_prop
                        key2 = key1 + '.##prop##' + serviceProperty.name
                        if serviceProperty.value:
                            sipoc_kv[key2] = serviceProperty.value
                        else:
                            sipoc_kv[key2] = serviceProperty.defaultValue

        return sipoc_kv


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
        return False, ""

    @staticmethod
    def handle_sipoc_file(key: str, value: Any, app_config: dict) -> dict:
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


        if not upload_file:
            # 如果找不到文件，则上传文件并创建知识库
            try:
                upload_file = FileService.upload_file(
                    filename=filename,
                    content=file_content,
                    mimetype=content_type,
                    user=current_user,
                    source="datasets",
                )
            except Exception as e:
                raise e

            knowledge_config = SipocService.generate_default_knowledge_config(upload_file.id)
            try:
                dataset, documents, batch = DocumentService.save_document_without_dataset_id(
                    tenant_id=current_user.current_tenant_id, knowledge_config=knowledge_config, account=current_user
                )
                dataset_id = dataset.id
            except Exception as ex:
                raise ex
        else:
            document = db.session.query(Document).filter(Document.file_id == upload_file.id).first()
            if not document:
                # 如果文件没有被引用到知识库，则创建知识库
                knowledge_config = SipocService.generate_default_knowledge_config(upload_file.id)
                try:
                    dataset, documents, batch = DocumentService.save_document_without_dataset_id(
                        tenant_id=current_user.current_tenant_id, knowledge_config=knowledge_config,
                        account=current_user
                    )
                    dataset_id = dataset.id
                except Exception as ex:
                    raise ex
            else:
                # 如果文件已经被引用到知识库，则不创建知识库
                dataset_id = document.dataset_id

        # dataset_configs.datasets.datasets里面新增知识库{"dataset": {"id": "dataset_id", "enabled": True}}
        app_config["dataset_configs"]["datasets"]["datasets"].append({
            "dataset": {
                "id": dataset_id,
                "enabled": True
            }
        })
        # 新增知识库后，需要更新app_config里面的pre_prompt，如果sipoc附件参数在pre_prompt中，进行替换，否则将使用知识库回答文件，加到提示词最后
        if key in app_config["pre_prompt"]:
            app_config["pre_prompt"] = app_config["pre_prompt"].replace(key, f"(你可以使用知识库来回答用户的问题, 知识库的id是：{dataset_id})")
        else:
            app_config["pre_prompt"] += f"(你可以使用知识库来回答用户的问题, 知识库的id是：{dataset_id})"

        return app_config
        # response = {"dataset": dataset, "documents": documents, "batch": batch}

    @staticmethod
    def generate_default_knowledge_config(file_id: str) -> KnowledgeConfig:
        """
        Generate default knowledge config，生成默认的知识库配置
        :param file_id:
        :return:
        """

        args = {
            "indexing_technique": "high_quality",
            "embedding_model": "netease-youdao/bce-embedding-base_v1",
            "embedding_model_provider": "langgenius/siliconflow/siliconflow",
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
                    "reranking_provider_name": "langgenius/siliconflow/siliconflow",
                    "reranking_model_name": "netease-youdao/bce-reranker-base_v1"
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

        endpoint_test = "172.16.23.77:9000"
        access_key_test = "666e6cYxFod8Dr3QMnRx"
        secret_key_test = "F3xWGSfl2B6xqCo5EReTiUnjHG6fYEVFZ4LX8jh2"
        bucket_name_test = "cbrain-evolve"

        client = Minio(endpoint_test, access_key=access_key_test, secret_key=secret_key_test, secure=False)

        filename = file_path.split("/")[-1]

        try:
            # get file info
            obj_info = client.stat_object(bucket_name_test, file_path)
            print(obj_info)

            print(obj_info.size)
            print(obj_info.content_type)
            print(obj_info.last_modified)
            print(obj_info.etag)
            response = client.get_object(bucket_name=bucket_name_test, object_name=file_path)
            filehash = hashlib.sha3_256(response.data).hexdigest()
            return response.data, filename, obj_info.content_type, filehash, obj_info.size

        except Exception as e:
            raise e
        pass


    @staticmethod
    def convert_file_to_text(file_content: bytes) -> str:
        """
        Convert file content to text, 将包含图片的文件，通过ocr等技术转化成文本文件
        :param file_content:
        :return:
        """

