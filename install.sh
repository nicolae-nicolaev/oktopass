#!/bin/sh

cargo build --release
sudo cp ./target/release/oktopass /usr/local/bin
