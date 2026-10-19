# Build only during an owner-approved environment preparation step.
# BASE_IMAGE MUST be a tested linux/amd64 Python image pinned by @sha256.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY --chmod=0755 orc-runner /usr/local/bin/orc-runner
ENV HOME=/tmp PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8
USER 1000:1000
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/orc-runner"]
