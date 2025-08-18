#!/bin/bash

# 设置默认版本标签
BASE_IMAGE_TAG="lastest"
REGISTRY_HOST="192.168.6.210"
IMAGE_NAME="library/dify/dify-api-base"
FULL_IMAGE_NAME="192.168.6.210/library/dify/dify-api-base:lastest"

echo "正在构建基础镜像: ${FULL_IMAGE_NAME}"

# 构建基础镜像
docker build -f Base.Dockerfile -t ${FULL_IMAGE_NAME} .

if [ $? -eq 0 ]; then
    echo "基础镜像构建成功: ${FULL_IMAGE_NAME}"
else
    echo "基础镜像构建失败"
    exit 1
fi
