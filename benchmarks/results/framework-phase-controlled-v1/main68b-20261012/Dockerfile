FROM test-ast-runtime-phase-15508bc@sha256:8c2d95773208aab2a4391316ba4bd6446ac6d896ba581420545053822d9f24e4
USER 0:0
RUN rm -rf /usr/local/lib/python3.11/site-packages/fastapi_endpoint_detector /opt/detector-provenance/producer-source-manifest.json
COPY src/fastapi_endpoint_detector/ /usr/local/lib/python3.11/site-packages/fastapi_endpoint_detector/
COPY provenance/source-overlay-manifest.json /opt/detector-provenance/gh104-source-overlay-manifest.json
COPY provenance/requirements.lock /opt/detector-provenance/requirements.lock
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
USER 65532:65532
COPY provenance/pyproject.toml /opt/detector-provenance/source-pyproject.toml
