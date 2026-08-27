FROM ubuntu:24.04

ARG VERUS_REF=main
ARG RUST_TOOLCHAIN=1.97.1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl git ca-certificates unzip python3 pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "${RUST_TOOLCHAIN}" --profile minimal
ENV PATH=/root/.cargo/bin:$PATH
RUN rustup component add rust-src --toolchain "${RUST_TOOLCHAIN}"

WORKDIR /opt
RUN git clone --depth 1 --branch "${VERUS_REF}" https://github.com/verus-lang/verus verus
WORKDIR /opt/verus/source
RUN bash ./tools/get-z3.sh && ./z3 --version
RUN bash -c '. ../tools/activate && vargo build --release' 

ENV VERUS_BIN=/opt/verus/source/target-verus/release
ENV PATH=$VERUS_BIN:$PATH

COPY verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh
ENTRYPOINT ["/usr/local/bin/verify.sh"]
