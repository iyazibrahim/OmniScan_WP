FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV GOBIN=/usr/local/bin
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:/usr/local/bin:${PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    build-essential \
    ruby \
    ruby-dev \
    perl \
    default-jre \
    dirb \
    nikto \
    sqlmap \
    whatweb \
    wapiti \
    nuclei \
    subfinder \
    ffuf \
    wpscan \
    joomscan \
    feroxbuster \
    arjun \
    getallurls \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt /tmp/requirements.txt

RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt && \
    python3 -m pip install --no-cache-dir \
    sslyze \
    arjun \
    gunicorn

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest

RUN git clone --depth 1 https://github.com/dionach/CMSmap.git /opt/tools/CMSmap && \
    if [ -f /opt/tools/CMSmap/requirements.txt ]; then python3 -m pip install --no-cache-dir -r /opt/tools/CMSmap/requirements.txt; fi && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/CMSmap/cmsmap.py "$@"\n' >/usr/local/bin/cmsmap && \
    chmod +x /usr/local/bin/cmsmap

RUN git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/tools/Corsy && \
    if [ -f /opt/tools/Corsy/requirements.txt ]; then python3 -m pip install --no-cache-dir -r /opt/tools/Corsy/requirements.txt; fi && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/Corsy/corsy.py "$@"\n' >/usr/local/bin/corsy && \
    chmod +x /usr/local/bin/corsy

RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/tools/commix && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/commix/commix.py "$@"\n' >/usr/local/bin/commix && \
    chmod +x /usr/local/bin/commix

RUN if [ -x /usr/bin/getallurls ] && [ ! -e /usr/local/bin/gau ]; then ln -s /usr/bin/getallurls /usr/local/bin/gau; fi

COPY . /app

RUN chmod +x /app/docker/entrypoint.sh && \
    find /app -maxdepth 1 -name "*.sh" -exec sed -i 's/\r$//' {} \; && \
    sed -i 's/\r$//' /app/docker/entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["app"]
