# Build the reverse proxy and put it in a small image.
#
# Build:  docker build -t reverse-proxy .
#
# The image has no certificates, keys or policy. Mount them at run time. The
# paths below are the defaults for the settings of the `proxy` mode.

FROM rust:1-slim AS build
WORKDIR /src

# Copy only the files that the build needs. This keeps `target/` and the dev
# certificates out of the build.
COPY Cargo.toml Cargo.lock policy-schema.yaml ./
COPY src ./src

RUN cargo build --release --locked

# The runtime image has no shell and no package manager. It runs as a user that
# is not root.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /src/target/release/reverse-proxy /usr/local/bin/reverse-proxy

# The container listens on all addresses. The address of the upstream
# (`SERVER_ADDR`) has no default here. Set it when you run the container.
ENV PROXY_ADDR=0.0.0.0:8443 \
    PROXY_TLS_CERT=/etc/reverse-proxy/tls/server.pem \
    PROXY_TLS_KEY=/etc/reverse-proxy/tls/server.key \
    PROXY_CLIENT_CA=/etc/reverse-proxy/trust/ca.pem \
    PROXY_POLICY_FILE=/etc/reverse-proxy/policies.yaml

EXPOSE 8443

# The default mode is `proxy`. Use `server` to run the test upstream.
ENTRYPOINT ["/usr/local/bin/reverse-proxy"]
CMD ["proxy"]
