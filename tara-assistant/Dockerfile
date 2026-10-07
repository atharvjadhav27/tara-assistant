FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 TARA_DATA_DIR=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
# Optional BGE embeddings: docker build --build-arg WITH_BGE=1 .
ARG WITH_BGE=0
COPY requirements-bge.txt .
RUN if [ "$WITH_BGE" = "1" ]; then pip install -r requirements-bge.txt; fi
COPY app ./app
COPY ui ./ui
COPY data/sample ./data/sample
COPY .streamlit ./.streamlit
RUN useradd -m tara && mkdir /data && chown tara /data
USER tara
VOLUME /data
EXPOSE 8000 8501
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
