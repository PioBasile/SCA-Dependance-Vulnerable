FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app

WORKDIR $APP_HOME

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    gcc \
    curl \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p cvss_prediction/model

RUN if [ ! -f cvss_prediction/model/cvss_model.pt ]; then \
    echo "Model not found, resolving download from https://urlix.me/cvss-models..." && \
    FINAL_URL=$(curl -sL -o /dev/null -w %{url_effective} https://urlix.me/cvss-models) && \
    FILE_ID=$(echo $FINAL_URL | sed -r 's/.*\/d\/([a-zA-Z0-9_-]+).*/\1/') && \
    CONFIRM=$(curl -sL -c /tmp/cookies.txt "https://docs.google.com/uc?export=download&id=${FILE_ID}" | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1/p') && \
    curl -L -b /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=${CONFIRM}&id=${FILE_ID}" -o cvss_prediction/model/cvss_model.pt && \
    rm /tmp/cookies.txt; \
    fi

RUN ls -lh cvss_prediction/model/cvss_model.pt

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
