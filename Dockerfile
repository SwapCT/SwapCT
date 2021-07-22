FROM rust:1.52

WORKDIR /usr/src/swapct

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y texlive-latex-base texlive-pictures

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin
RUN mkdir bin
RUN echo "fn main() {}" > src/bin/plots.rs
RUN cargo install --bin plots --path .

COPY . .
RUN touch src/bin/plots.rs

RUN cargo install --bin plots --path .

RUN chmod +x entry.sh
ENTRYPOINT ["./entry.sh"]
