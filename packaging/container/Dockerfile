# The FlowSight image: the static flowsightd, the CA certificates it needs
# for its feeds, and the directories it writes. Built FROM scratch, so there
# is no shell, no package manager and nothing else to patch, and building it
# pulls nothing. Built by build-image.sh, which stages the context.
FROM scratch
ARG TARGETARCH
ARG VERSION=dev
LABEL org.opencontainers.image.title="FlowSight" \
      org.opencontainers.image.description="L7 visibility, policy and enforcement" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/grioghar/flowsight" \
      org.opencontainers.image.licenses="Apache-2.0"
# Root-owned: the user database and the CA bundle.
COPY rootfs-root/ /
# FlowSight's own directories, writable by the unprivileged user it runs as.
COPY --chown=65532:65532 rootfs-user/ /
COPY --chmod=755 flowsightd-linux-${TARGETARCH} /usr/local/sbin/flowsightd
USER 65532:65532
ENV HOME=/var/lib/flowsight
EXPOSE 8080
# Everything that must persist (configuration, token, CA, store) is on this
# one volume: /etc/flowsight is a link to /var/lib/flowsight/etc.
VOLUME ["/var/lib/flowsight"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/sbin/flowsightd", "health"]
# Settle the configuration (a token from FLOWSIGHT_API_TOKEN, or a new one
# shown once in the log), then become the daemon as process 1.
ENTRYPOINT ["/usr/local/sbin/flowsightd", "container"]
