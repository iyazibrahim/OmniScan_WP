# ── Stage 1: Go binary builder ─────────────────────────────────────────────────
# Compiles httpx, dalfox, and katana in an isolated stage so the Go toolchain
# is NOT present in the final runtime image, shrinking it by ~600 MB.
FROM golang:1.25-bookworm AS gobuilder

ENV GOBIN=/go/bin
ENV GOOS=linux

RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    CGO_ENABLED=0 go install -v github.com/hahwul/dalfox/v2@latest && \
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# ── Stage 2: Runtime image ─────────────────────────────────────────────────────
FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:/usr/local/bin:${PATH}"

WORKDIR /app

# Install all security tools and Python runtime. golang-go is intentionally
# omitted because Go binaries are copied from the builder stage above.
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
    && rm -rf /var/lib/apt/lists/*

# Copy pre-compiled Go binaries from builder — no Go toolchain in final image
COPY --from=gobuilder /go/bin/httpx    /usr/local/bin/httpx
COPY --from=gobuilder /go/bin/dalfox   /usr/local/bin/dalfox
COPY --from=gobuilder /go/bin/katana   /usr/local/bin/katana

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt /tmp/requirements.txt

RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt && \
    /opt/venv/bin/pip install --no-cache-dir sslyze arjun

RUN git clone --depth 1 https://github.com/dionach/CMSmap.git /opt/tools/CMSmap && \
    if [ -f /opt/tools/CMSmap/requirements.txt ]; then \
        /opt/venv/bin/pip install --no-cache-dir -r /opt/tools/CMSmap/requirements.txt; fi && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/CMSmap/cmsmap.py "$@"\n' >/usr/local/bin/cmsmap && \
    chmod +x /usr/local/bin/cmsmap

RUN git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/tools/Corsy && \
    if [ -f /opt/tools/Corsy/requirements.txt ]; then \
        /opt/venv/bin/pip install --no-cache-dir -r /opt/tools/Corsy/requirements.txt; fi && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/Corsy/corsy.py "$@"\n' >/usr/local/bin/corsy && \
    chmod +x /usr/local/bin/corsy

RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/tools/commix && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/commix/commix.py "$@"\n' >/usr/local/bin/commix && \
    chmod +x /usr/local/bin/commix

RUN if [ -x /usr/bin/getallurls ] && [ ! -e /usr/local/bin/gau ]; then \
        ln -s /usr/bin/getallurls /usr/local/bin/gau; fi

COPY . /app

RUN chmod +x /app/docker/entrypoint.sh && \
    find /app -maxdepth 1 -name "*.sh" -exec sed -i 's/\r$//' {} \; && \
    sed -i 's/\r$//' /app/docker/entrypoint.sh

EXPOSE 5000

# Docker health-check: verifies the Flask/Gunicorn app is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["app"]
