B=/tmp/an0/open-humanity-ref/target/release
M=/Users/drakestapleton/aienet0
export RUN=$B/aienet0-run SERVE="ssh -o BatchMode=yes macbook $M/bin/aienet0-serve" LISTEN=192.168.1.108:14323 CONNECT=192.168.1.108:14323
export KEYS=/tmp/an0/keys PINS=/tmp/an0/pins-mac ROGUE_KEYS=/tmp/an0/keys-rogue
export RECOMPUTE=/tmp/an0/bin/matmul_u32_recompute RECOMPUTE_SHA256=d2cd7382e0dc64e49498ae3b1ceffc73f1ddcbd3ddcf93e6d607498ccd58ea12
export WKEYS=$M/keys WPINS=$M/pins WSTATE=$M/state
export WKEYS_ROGUE_EXEC=$M/keys-rogue-exec WKEYS_ROGUE_TRANSPORT=$M/keys-rogue-transport
export OUT=/tmp/an0/out
