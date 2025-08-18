FROM 192.168.6.210/library/dify/dify-api-base:lastest

WORKDIR /app/api



EXPOSE 5001


# Set up Python environment path
ENV VIRTUAL_ENV=/app/api/.venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# Copy source code
COPY . /app/api/

# Copy entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG COMMIT_SHA
ENV COMMIT_SHA=${COMMIT_SHA}

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
