# 基础镜像 - 包含所有系统依赖和 Python 环境
FROM 192.168.6.210/library/python:3.12-slim-bookworm

WORKDIR /app/api

# Install uv
ENV UV_VERSION=0.7.11
RUN pip install --no-cache-dir uv==${UV_VERSION}

# if you located in China, you can use aliyun mirror to speed up
#RUN sed -i 's@deb.debian.org@mirrors.aliyun.com@g' /etc/apt/sources.list.d/debian.sources

# Install build dependencies and runtime dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        # Build dependencies for Python packages
        gcc g++ libc-dev libffi-dev libgmp-dev libmpfr-dev libmpc-dev \
        # Runtime dependencies
        curl nodejs libgmp-dev libmpfr-dev libmpc-dev \
        # For Security
        expat libldap-2.5-0 perl libsqlite3-0 zlib1g \
        # install fonts to support the use of tools like pypdfium2
        fonts-noto-cjk \
        # install a package to improve the accuracy of guessing mime type and file extension
        media-types \
        # install libmagic to support the use of python-magic guess MIMETYPE
        libmagic1 \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV FLASK_APP=app.py
ENV EDITION=SELF_HOSTED
ENV DEPLOY_ENV=PRODUCTION
ENV CONSOLE_API_URL=http://127.0.0.1:5001
ENV CONSOLE_WEB_URL=http://127.0.0.1:3000
ENV SERVICE_API_URL=http://127.0.0.1:5001
ENV APP_WEB_URL=http://127.0.0.1:3000

# set timezone
ENV TZ=UTC

# Set UTF-8 locale
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV PYTHONIOENCODING=utf-8

# Set up Python environment path
ENV VIRTUAL_ENV=/app/api/.venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# 预安装 Python 依赖（需要将 pyproject.toml 和 uv.lock 复制到构建上下文）
# 注意：构建基础镜像时需要确保这些文件在构建上下文中
#ENV UV_DEFAULT_INDEX="https://pypi.tuna.tsinghua.edu.cn/simple"
COPY pyproject.toml uv.lock ./
RUN uv sync --locked

# Download commonly used NLTK data
RUN python -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger')"

# Set up tiktoken cache
ENV TIKTOKEN_CACHE_DIR=/app/api/.tiktoken_cache
RUN python -c "import tiktoken; tiktoken.encoding_for_model('gpt2')"

EXPOSE 5001
