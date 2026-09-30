FROM rust@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src

ARG ZDX_RELEASE_ID
RUN test -n "$ZDX_RELEASE_ID"
ENV AXIOMATIC_COMPILED_RELEASE_ID=$ZDX_RELEASE_ID

COPY native/Cargo.toml native/Cargo.lock ./
COPY native/src ./src

RUN cargo build --release --locked --features "marketplace,dynamodb-claims" \
      --bin axiomatic-runtime-native \
      --bin axiomatic-adapter \
      --bin approve-gate \
      --bin axiomatic-keygen \
      --bin verify-envelope \
    && strip \
      target/release/axiomatic-runtime-native \
      target/release/axiomatic-adapter \
      target/release/approve-gate \
      target/release/axiomatic-keygen \
      target/release/verify-envelope

FROM gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
WORKDIR /app

COPY --from=build /src/target/release/axiomatic-runtime-native /app/axiomatic-runtime
COPY --from=build /src/target/release/axiomatic-adapter /app/axiomatic-adapter
COPY --from=build /src/target/release/approve-gate /app/approve-gate
COPY --from=build /src/target/release/axiomatic-keygen /app/axiomatic-keygen
COPY --from=build /src/target/release/verify-envelope /app/verify-envelope
COPY profiles/zdx-validated-baseline-v1.json /app/profiles/zdx-validated-baseline-v1.json

ENV AXIOMATIC_PROFILE=/app/profiles/zdx-validated-baseline-v1.json \
    AXIOMATIC_AUDIENCE=zdx-executor \
    PORT=8080

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/axiomatic-runtime","serve"]