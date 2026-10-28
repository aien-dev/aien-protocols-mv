# Aienet-0 comparison baseline

This is an immutable comparison baseline, not a new execution receipt. The
Spark to MacBook Air M2 LAN session is **EXERCISED**; single-host replay and
mutation checks are **HOST_TESTED**, not hardware qualification. TUR denotes
prefunded test credits in a local journal, not currency. No historical evidence
file was edited during the integration reshuffle.

## Canonical integration order

1. [protocols #53](https://github.com/aien-dev/aien-protocols-mv/pull/53):
   MJB1/MJR1 and DCP1, original commits `33e28b9` and `c1ffa42`; resolved
   against main `361a2b58d9840d96a31de7023144b212b38605c5` at
   `2b566c83159e124349315226f282ac68b8577284`. Both P-256 low-S and signed-grant
   boundary-substitution tests are retained. MJB1/DCP1 vectors stay unchanged.
2. The Aienet-only stacked replacement of
   [protocols #64](https://github.com/aien-dev/aien-protocols-mv/pull/64), based
   on that resolved #53 branch. It carries the six Aienet commits listed below,
   this baseline, and a behavior-preserving `BundleParts` tuple alias required
   by the current Clippy `type_complexity` gate. Do not merge the old #64
   independently. After #53 lands, retarget the replacement to main and retain
   this diff; if #53 is squash-merged, rebase the Aienet-only commits onto its
   resulting main head.
   [#63](https://github.com/aien-dev/aien-protocols-mv/pull/63)'s P0 profile is
   already present in the resolved main base; this stack does not replace it.
3. [open-humanity #44](https://github.com/aien-dev/open-humanity/pull/44) is
   already merged at `e5a5e6a71e3413968e2910e436f9ea37bbac2d4a`, head
   `946ea8b29aa77e2805b9618b1ec4a2220a7306ef`. Its workspace dependency pins
   `aien-microjob` to `a82a8f8b8d2f1edab8ada5d995ae96449fa7302e`. That original
   revision remains reachable through the retained `feat/aienet0-jobpath`
   branch, but is not an ancestor of this cherry-picked stack. Do not delete
   the original ref before consumers move. After the canonical Aienet PR lands,
   update Open Humanity's `Cargo.toml` rev and `Cargo.lock` together to the
   resulting protocols main commit, and rerun carrier controls/mutants and
   receipt checks; do not silently change the old pin or historical receipt.

## Source revisions

Original #64 merge base before its Aienet-only commits: `f048f19`.
Preserved source head: `df5fbc6cbd2b02f7186753984afc99815327bac8`.
Evidence was recorded at `f04d3f8` and `9ed6a03`; `df5fbc6` is the subsequent
CodeQL test-nonce correction, not a new two-machine execution.

```text
df5fbc6cbd2b02f7186753984afc99815327bac8 aien-microjob: derive aienet0 test nonces instead of hard-coding [9; 16]
9ed6a033a2c6a81aecda11e100b3d2279d9965c7 aienet0: escrow settlement evidence Spark->MacBook (settle once, tampered receipt refunds); profile escrow order
51c5c397da4c527f191dff2f163a34e62ee604ec aienet0: rustfmt aienet0.rs (PROTO-FMT); mutants drop whole wrapped guard statements
f04d3f8238de9e8e32bf862d5735c6c41a0de54f aienet0: job path profile spec and two-machine evidence (HOST_TESTED + EXERCISED Spark->MacBook)
a82a8f8b8d2f1edab8ada5d995ae96449fa7302e aienet0: countersignature covers 172 bytes (doc fix)
1fbf500129e8f4b955ad6133058a1e00018d4af2 aienet0: matmul_u32 job path profile over MJB1/MJR1, Omega recompute, guard mutants
```

Core #662 numerical oracle: `3606d0411991d65304e17124343e52b669e9bb82`,
`task.rs` SHA-256 `2d6eb73672474e28c9a908ec8f417fe871634b65a7d8450d57f32cae69a69ab7`.
Core #792 ledger source: `2cdc9249` as reported in the coordinator receipt;
ledger binary SHA-256 `6ea978c7f0ae080c6bb0d0254f9fa56b78da2e74d577c092a98cd50bd945be4a`.
Pinned omc SHA-256 `2c82480596bbdc50cda9626866209ef662d5834f278f839ff4ce0250c495029f`.
Omega SHA unit source `55845e707dac0d09bf22b5e16970a73c0a989a8c`,
`om/sha256/sha256-om2.om` SHA-256 `dbf002dd6aa36585632b9d01d98ac3f0bd2fa0f0475082940de53638847994bb`.
Recompute binary SHA-256 `d2cd7382e0dc64e49498ae3b1ceffc73f1ddcbd3ddcf93e6d607498ccd58ea12`.

## Recorded commands and expectations

The [coordinator's independent receipt](https://github.com/aien-dev/aien-protocols-mv/pull/64#issuecomment-6459841467)
records settlement-journal auditing, receipt binding, offline receipt checks,
11/11 host controls and killed=5 survived=0 carrier mutants. The
[operator review](https://github.com/aien-dev/aien-protocols-mv/pull/64#issuecomment-6466131237)
records the integration gate and the bounded P0 trust limitations. Those limits
remain: this baseline does not authorize federation or arbitrary remote jobs.
The coordinator comment names commands but does not retain every invocation's
arguments; the committed `.cmd` and settlement transcripts below preserve the
exact original invocations. Do not invent missing receipt arguments.

Run future reproductions in a disposable clone and fresh output directories.
`host-checks.sh` writes its logs alongside itself, so never rerun it in the
preserved evidence tree. Use bash for controls and mutants.

```sh
# Original host-check entry point; OMC/OMEGA_MV/OH_TREE/CORE_TREE use the pins above.
bash evidence/aienet0-20261028/host-checks.sh OMC OMEGA_MV OH_TREE CORE_TREE
# Open Humanity #44; environment variables are documented in each script.
bash scripts/aienet0/controls.sh FRESH_CONTROL_DIR
bash scripts/aienet0/mutants.sh FRESH_MUTANT_DIR
# Original settlement runner, with the documented RUN/SERVE/LEDGER/etc environment.
sh evidence/aienet0-20261028/settlement/settle-run.sh.at-run FRESH_SETTLEMENT_DIR honest
sh evidence/aienet0-20261028/settlement/settle-run.sh.at-run FRESH_SETTLEMENT_DIR tampered-receipt
# Read-only integrity checks, from their respective directories.
(cd evidence/aienet0-20261028 && sha256sum -c SHA256SUMS)
(cd evidence/aienet0-20261028/settlement/honest && sha256sum -c SHA256SUMS)
(cd evidence/aienet0-20261028/settlement/tampered-receipt && sha256sum -c SHA256SUMS)
```

Exact two-machine baseline commands from `exercised/baseline.cmd`:

```text
serve: ssh -o BatchMode=yes macbook /Users/drakestapleton/aienet0/bin/aienet0-serve  --connect 192.168.1.108:14323 --keys /Users/drakestapleton/aienet0/keys --pins /Users/drakestapleton/aienet0/pins --state /Users/drakestapleton/aienet0/state --connect-timeout 60
run:   /tmp/an0/open-humanity-ref/target/release/aienet0-run run  --listen 192.168.1.108:14323 --keys /tmp/an0/keys --pins /tmp/an0/pins-mac --out /tmp/an0/out --recompute /tmp/an0/bin/matmul_u32_recompute --recompute-sha256 d2cd7382e0dc64e49498ae3b1ceffc73f1ddcbd3ddcf93e6d607498ccd58ea12 --m 64 --k 64 --n 64 --seed 2716205057 --accept-timeout 90
```

Exact settlement steps, stdout, status and worker invocation are in
`settlement/honest/transcript.txt` and
`settlement/tampered-receipt/transcript.txt`; their hashes are included below.
Expected historical outcomes: exercised and host-tested `summary.tsv` each
11/11 MATCH, Core/Rust/Omega digest agreement 6/6, protocol mutants 13 killed
and 0 survived, carrier mutants 5 killed and 0 survived. Honest settlement has
one settled job, no escrow remaining, balances requester/provider/verifier
70/27/3; repeating settlement leaves the journal unchanged. A tampered receipt
is refused with `MJB_FORGED_RECEIPT` (exit 12), refunded, and never settled.
The settled receipt SHA-256 is
`3a44a44ed9a72125f0f1f59de4aaad96bc8dfe5baa3a619e5f57c531f61845d6`.
These are recorded measurements, not claims of a new network run.

## SHA-256 manifest

All 187 files under `evidence/aienet0-20261028/` were hashed at original source
head `df5fbc6` and compared after cherry-picking; every hash is identical,
including all 107 files under `exercised/` and `settlement/`. Paths below are
repository-relative. Future results belong in a different evidence directory;
compare outcomes and bindings against this manifest without rewriting it.

```text
e43051aa5b267abb36a29390b1055e9bcd493c0c78bffc851c3573adc82c816d  evidence/aienet0-20261028/SHA256SUMS
29d2835cd9a48d5e345cf1a3afd632aa5fbd838bd69f05eb7db9f317d38f1d7e  evidence/aienet0-20261028/build.log
9b4c188692922fb935cae541e61069a8bfb56939897c2778975084f54c0618ce  evidence/aienet0-20261028/exercised/artifacts/aadc3775d32303b9e697c1c092b5628e9333f012a2ac4c1390f04da113c494cb.an0b
3306d180de1885a2759b324618d11eca523ef4d7aa22c4144813d71187014855  evidence/aienet0-20261028/exercised/artifacts/aadc3775d32303b9e697c1c092b5628e9333f012a2ac4c1390f04da113c494cb.mjr1
cdaa816e285216c90a6cf511edc31769ed93aafd0eac4f96bf8ec2ccc3622711  evidence/aienet0-20261028/exercised/artifacts/aadc3775d32303b9e697c1c092b5628e9333f012a2ac4c1390f04da113c494cb.mjv
0188dd20516560c5f4d13f056853c7266ef6165a5087dc61fe243f4ed7919629  evidence/aienet0-20261028/exercised/baseline.artifacts.sha256
2181a433851206382357012c98e44befc16f3c05ab1765271b36af78020409ee  evidence/aienet0-20261028/exercised/baseline.check.out
d922dbce4a1a8b711cb6c92ee6d9c73710e99ba66ed0b5bf558e04964b464d0d  evidence/aienet0-20261028/exercised/baseline.cmd
6d0904a33c9c4e207bbf5641c0d1fefb3caafc4bc4289f65243125bf2ae71cec  evidence/aienet0-20261028/exercised/baseline.run.err
ae1ba78a9297e082d2c66538c0b16a13c0af5bcd0928804527a88d18da76d906  evidence/aienet0-20261028/exercised/baseline.run.out
eb8764bebbe5826d704eb55a8369f58692cb440a5aee9d2a6043e75b011e7392  evidence/aienet0-20261028/exercised/baseline.serve.err
1cb00af1abb4a0934451dd18d8d93a456bc6f7adbdd4747c299693b72f9c056b  evidence/aienet0-20261028/exercised/baseline.serve.out
23fdc84ff54359fd04a4c253ddfd6179de24156b79700647123d179f57c42765  evidence/aienet0-20261028/exercised/machines.txt
23063e3b3931c1a9d655b88ab0f9e56d69456631d9c9eeb3fe2fd96a3c2050f8  evidence/aienet0-20261028/exercised/not-allowlisted-kind.cmd
26504e83e3e452b65b39d247f94b8eb25111244bcceb24a15ad2375c880bbf89  evidence/aienet0-20261028/exercised/not-allowlisted-kind.run.err
62f55038ae10b30a223727a46d408f7a566d6abae6e9ad86f7205aab61e323ba  evidence/aienet0-20261028/exercised/not-allowlisted-kind.run.out
9cb374a266800e5eb48ab039d6c84a53578301d4093371f50b9b46b17cb2aaae  evidence/aienet0-20261028/exercised/not-allowlisted-kind.serve.err
049fa35d58b697bc4d5b21f994502c20beb3eeac139d4ef063d1c6f9cf503aa7  evidence/aienet0-20261028/exercised/not-allowlisted-kind.serve.out
5a52bd99e301ccd2bc58cc1053edade47cb360c2e19dddb790f91716a5abf02e  evidence/aienet0-20261028/exercised/not-allowlisted-op.cmd
9c99a9f86b3dca836aa7e336e2bb55b7829c5fad2b75fbaa58e3efc0921de0c1  evidence/aienet0-20261028/exercised/not-allowlisted-op.run.err
0e5c988fc0447914a1c3c67a60c916b78791dfbaaab5fdaa7c25a31deaffd4b7  evidence/aienet0-20261028/exercised/not-allowlisted-op.run.out
fec5a62ea163749565fff20bee0f43c605121befdd2d128bd014bc2d9ea74a50  evidence/aienet0-20261028/exercised/not-allowlisted-op.serve.err
a06ea26655c3be241e71fbf0d2aee00e4b342a5e6d82f9a809ed5cc1bf46b237  evidence/aienet0-20261028/exercised/not-allowlisted-op.serve.out
c1205a0251fcfb8fc943ddcc928274776692672046d2c6fcc4502ab25a337612  evidence/aienet0-20261028/exercised/over-budget.cmd
9b59cb338207eefee9ef40efd8052ea2ed3a2e4a005dd8c36957c6b956955306  evidence/aienet0-20261028/exercised/over-budget.run.err
ba494c526fbf445c9d06abca5b790ee569770fd420aaf6e805bf953248553633  evidence/aienet0-20261028/exercised/over-budget.run.out
87796a322b5fc58c6719c55a3001230edc96ad1c6bb80760052c9f6a47ee6320  evidence/aienet0-20261028/exercised/over-budget.serve.err
fb1f0e648028c6c49b22cc902bc5e78f2148773ca2ef0851698fbba7c7897d64  evidence/aienet0-20261028/exercised/over-budget.serve.out
25bedfa34d7d9fb2dcc6592cbc01fd93c7d50bbbf5da0d7b7a57f81c90a49a8f  evidence/aienet0-20261028/exercised/replay.cmd
8d89185d7a0ffe7c3350ea4f004ca7dc38c70e689963bafeadc9776d883599eb  evidence/aienet0-20261028/exercised/replay.run.err
e8f8660d7dc95d840ac20f151aa8efe7faca1df8a77af768fad4794a03133386  evidence/aienet0-20261028/exercised/replay.run.out
97e99884f63db191999388f7776af21e43c2a26b1f87efc25c438e299dd9aefe  evidence/aienet0-20261028/exercised/replay.serve.err
11debd7a5f2e6efd66c0c519268d62063d96e80817262f70a79c4ce2eb386b2f  evidence/aienet0-20261028/exercised/replay.serve.out
ec216dbe7737b9ec8888caa62b19c73c3bb7427e120925662f31d6ce8e5793c7  evidence/aienet0-20261028/exercised/summary.tsv
2d23c5feaf896a5ab2ce527e1161e1202866bb7b01195166342636c44680aae3  evidence/aienet0-20261028/exercised/tampered-receipt.cmd
808d79e40a7f23b0a32f5d24e05eb93ecefc59985c742858e1317d74459f6ab5  evidence/aienet0-20261028/exercised/tampered-receipt.run.err
482f760da5f38d1ad4f5a35c55c307f9416abb787a449929e75aa2a1e8e1e559  evidence/aienet0-20261028/exercised/tampered-receipt.run.out
82a7bdf580d1669a6198c44ec3134feb01f794fc1341c51583d4bd547be56472  evidence/aienet0-20261028/exercised/tampered-receipt.serve.err
0a08b0b951a64376619c4563bb9b207d9b7441c0b875ef783c841548107b7445  evidence/aienet0-20261028/exercised/tampered-receipt.serve.out
24469ece6e7e5870e26971a636db8d12de77e0c06260e42405c18f72fcd5337e  evidence/aienet0-20261028/exercised/unpinned-executor.cmd
ab4d759b334b47c1cb81b56df183fa27611dc1bba726927ef80fe84a59c64cb5  evidence/aienet0-20261028/exercised/unpinned-executor.run.err
482f760da5f38d1ad4f5a35c55c307f9416abb787a449929e75aa2a1e8e1e559  evidence/aienet0-20261028/exercised/unpinned-executor.run.out
a0ed65554276058ae7100bbc14a19e9af4acecd80aa06811701449e77f9e6a05  evidence/aienet0-20261028/exercised/unpinned-executor.serve.err
3390f125e7216fe1362422f787441131fee681ab65b431586dab7930856d2c49  evidence/aienet0-20261028/exercised/unpinned-executor.serve.out
7295083981386777d0194cbad4f1cf4681b4cb25e0de308f489bc39fee59772f  evidence/aienet0-20261028/exercised/unpinned-recompute.cmd
4dfe56390f126919b6978480dfd085191c8d21a2ba2e234799a0b66a09ac52a6  evidence/aienet0-20261028/exercised/unpinned-recompute.run.err
6b6bc4513859f612f20e14c7fca3ff1d3efe02ecc6ec115c98d4c1ff3dcabb9c  evidence/aienet0-20261028/exercised/unpinned-recompute.run.out
9fde01dabd0dc95e31b055d71ee7392e2c3871dd93f1393b580cab0f764f7e24  evidence/aienet0-20261028/exercised/unpinned-recompute.serve.err
3c8f9d49427bb02b76979dc35a4dd1fc710b63a675b60d47fa0813be533215bd  evidence/aienet0-20261028/exercised/unpinned-recompute.serve.out
23b7588e583de0d933bfb7434d7689a99e56005ae3df3b0a87227fb5aa90067e  evidence/aienet0-20261028/exercised/unpinned-volunteer.cmd
e5c2574a6cd7873c346cbae48a7605d7e69b9571867eb12faf12bb44060bf28b  evidence/aienet0-20261028/exercised/unpinned-volunteer.run.err
f2b5c6c40233fab9b813f13c9f9b17eef8094e84bc0958a90987698a78229db1  evidence/aienet0-20261028/exercised/unpinned-volunteer.run.out
ff4c3874a121c666563835f79c6ca0284bd562d49507c670af6d9912962f8f7b  evidence/aienet0-20261028/exercised/unpinned-volunteer.serve.err
ca669b503970af4dbab4764aba9c1664d1854ca4016eb1320038cb7f7c354ca7  evidence/aienet0-20261028/exercised/unpinned-volunteer.serve.out
128c43ca4520538bb83054fc632c5052082fef7f193859b4fcb16c3522dc9725  evidence/aienet0-20261028/exercised/wrong-coordinator-key.cmd
8dff09e933f1f99db0320a3c12ecd64b94915797ede95bc0e74340653e7c4899  evidence/aienet0-20261028/exercised/wrong-coordinator-key.run.err
fddf66fb50a9bda72e39bde06128faba303dfae6fe86b8ace00e1fe15608c2c9  evidence/aienet0-20261028/exercised/wrong-coordinator-key.run.out
b808154e103979a0ba1273d1c556a58971ff0c029f826cb01a12fc7fca821692  evidence/aienet0-20261028/exercised/wrong-coordinator-key.serve.err
2a0e1e8273371d7ea46f8eee13809a31ac28ce48f20781399e55610b0fe48aa5  evidence/aienet0-20261028/exercised/wrong-coordinator-key.serve.out
65410f5728ba39c8bd7c6d08de045cad640b778b4f3c0cb860d7921d072e0801  evidence/aienet0-20261028/exercised/wrong-output.cmd
e9f79215a4c3bc03e722b597898221a89896b961b30cfd645a65fc4eda45cfd6  evidence/aienet0-20261028/exercised/wrong-output.run.err
88fce8b3cf7b599a7d5d29d25644920a16d7c18fb5d1a90e8c1bb53220de996d  evidence/aienet0-20261028/exercised/wrong-output.run.out
077b9f84f57a517b76654568979886ec9d6c8d1f02e865fef0014c1dd7d23ac0  evidence/aienet0-20261028/exercised/wrong-output.serve.err
6a93ff99eaf36205c5e52e8cfc2dbf61ace419be5c04ff758c4f1541041aeb50  evidence/aienet0-20261028/exercised/wrong-output.serve.out
5c79a2880f3fdc6c0ee0f6093cef633507d3712dd47e04010e363c9496f97ff0  evidence/aienet0-20261028/host-checks.rc
2bc46c4dda593dab20763868cef4b5f635786f0880edfe710a42b3989541d00c  evidence/aienet0-20261028/host-checks.sh
538b759264c50671e3b9806677ef6d97a74b2ec7c3383daa1d6a38a78f1075ae  evidence/aienet0-20261028/host-tested/baseline.artifacts.sha256
4864b1e5f101aee97dc0192933a1f969f2e8115bc241c104eb1bdf555e4cf6f6  evidence/aienet0-20261028/host-tested/baseline.check.out
af6daed97d69cc25f202a04b7f6e17ff079c96d5ee3264dc5b9d85ae008c8f05  evidence/aienet0-20261028/host-tested/baseline.cmd
a386efd41af92a6d7ce20a22c23f52b5fdf6fe016b0c3e2dd8f5f3d759fb07f3  evidence/aienet0-20261028/host-tested/baseline.run.err
2a1c86519784a884cb53698b231620d276f0e8565b9e672ccdb5195e0f2a3568  evidence/aienet0-20261028/host-tested/baseline.run.out
8df3a02175a1ec4575a74e528d0009771cc3ecc06fa1416daa211029ae11069f  evidence/aienet0-20261028/host-tested/baseline.serve.err
9a027bf792e5d4670356be1723f59e5e5f55e852ac797ded9e8b941941f70787  evidence/aienet0-20261028/host-tested/baseline.serve.out
626f5a1b944d5450f235936360e8be84021fce425522dbe3dd3838e56f20eeea  evidence/aienet0-20261028/host-tested/not-allowlisted-kind.cmd
48ba88e9bcb7b433daa7435f6fbf7a4fb83fc3fe9d7a6c72cb5e75040dc6bce8  evidence/aienet0-20261028/host-tested/not-allowlisted-kind.run.err
1c8e7a45f527f139fe9087a1592bd90c8c6cb4ee1746ab36b4609cc7096fb385  evidence/aienet0-20261028/host-tested/not-allowlisted-kind.run.out
e5ad894324b01076557c66c470eae0a4da99328ed864428e4e5eb083457a9616  evidence/aienet0-20261028/host-tested/not-allowlisted-kind.serve.err
73393bff3bb31f60e6c9c760952aa6db455b38643f712dc61f515d487db8af2c  evidence/aienet0-20261028/host-tested/not-allowlisted-kind.serve.out
a8356a19545c755ea8834b76a48ef577e44d24eaf307fffe069fcaeb3e276dfc  evidence/aienet0-20261028/host-tested/not-allowlisted-op.cmd
a96697764ed85abca058f05d191fd18c6d1b52694a8ce1a3df9eef71db0d29b1  evidence/aienet0-20261028/host-tested/not-allowlisted-op.run.err
4cc56268e6bdb25f677b217c3c9e9e784576798e54a7d1b1b840c50e4658317a  evidence/aienet0-20261028/host-tested/not-allowlisted-op.run.out
32cb46f61ec5a83b701d93fee5ad6090c32f65de07579f200a9060bf3f2c37ea  evidence/aienet0-20261028/host-tested/not-allowlisted-op.serve.err
ba86d9986a7a061040cad45af9124a8756e4ffceda92e983c9d425a9051aef8c  evidence/aienet0-20261028/host-tested/not-allowlisted-op.serve.out
785a13a0de2452cebb12facd30bc9724648f85385fc06e5a0b97e2387878799b  evidence/aienet0-20261028/host-tested/over-budget.cmd
11eeef4e3f29b9c92576efe59f3c6bfe53f9a33798fdaed11cf9268fe1cb2adc  evidence/aienet0-20261028/host-tested/over-budget.run.err
a8f0bb0a4bcd2d7eb2bad6bca9702c0e2a2aebe5b3823d567e715cc636417c29  evidence/aienet0-20261028/host-tested/over-budget.run.out
141dde7d48682855d631dea39a710ac50d6a667e8eb6b2f2ed100891b93a8870  evidence/aienet0-20261028/host-tested/over-budget.serve.err
d3ab265bbef03ea1be2d512e2635f6deb9f26370a9f74c282613dfb800f682ef  evidence/aienet0-20261028/host-tested/over-budget.serve.out
30f333ce54e2e955af9bf2dde152e91841c4d1ca0bcfceb2943f0b1b04411f61  evidence/aienet0-20261028/host-tested/replay.cmd
c62f0c406e1cd7c84df2f576069c6722e01522bb89f61085fb73ad0b13beeba7  evidence/aienet0-20261028/host-tested/replay.run.err
99fee9a494869565580cd649584f271dbf093b26af612ad4c0f15521e477d1bd  evidence/aienet0-20261028/host-tested/replay.run.out
d3dfaab1c5d1eca29f62ceb495557df0cfe1e8451dabbf72f992b350f1839c54  evidence/aienet0-20261028/host-tested/replay.serve.err
d05cb826398d8c0cb816a8b436a5b3349688327081ead933c01f77711b8ecf01  evidence/aienet0-20261028/host-tested/replay.serve.out
ec216dbe7737b9ec8888caa62b19c73c3bb7427e120925662f31d6ce8e5793c7  evidence/aienet0-20261028/host-tested/summary.tsv
db46d4fbf07073437677594c4d58eafe26a1ddd712a0ce5fbfcb386d0cb4e821  evidence/aienet0-20261028/host-tested/tampered-receipt.cmd
a9bc3ea2afd6c6b327785c245a5b5aa1a2ba46b418cefda97fff27ee9d083b03  evidence/aienet0-20261028/host-tested/tampered-receipt.run.err
482f760da5f38d1ad4f5a35c55c307f9416abb787a449929e75aa2a1e8e1e559  evidence/aienet0-20261028/host-tested/tampered-receipt.run.out
d04f9a9c9559adbc92f385341bc4a3495ddf599504975b74a7fa6c2550b26e0f  evidence/aienet0-20261028/host-tested/tampered-receipt.serve.err
52f629d7e99b5b9127fcaaac10b8a2315468ec39648c951c70fd164ecb951d12  evidence/aienet0-20261028/host-tested/tampered-receipt.serve.out
d2c7140d616ccaa7916ea7c7ea5267be3990fdb8fbad1b60d7171510f78878b0  evidence/aienet0-20261028/host-tested/unpinned-executor.cmd
ddb3ede5a3a6cd01c9523be61c92998bab2c0eaf77fe9d318b151d480e0fcf4a  evidence/aienet0-20261028/host-tested/unpinned-executor.run.err
482f760da5f38d1ad4f5a35c55c307f9416abb787a449929e75aa2a1e8e1e559  evidence/aienet0-20261028/host-tested/unpinned-executor.run.out
0bc137b811e0dc926123fcbb0bbcae6c9b56407df9051fe6617f4a3b23494831  evidence/aienet0-20261028/host-tested/unpinned-executor.serve.err
cf5967c6103dacd2b0f54eecfc3859c44d39149181e39923807effedb10a7998  evidence/aienet0-20261028/host-tested/unpinned-executor.serve.out
c7a63b21d99014e8b9a2180cc8e8bcc70a3bf706ef5d7a2a011217fd399ce3ba  evidence/aienet0-20261028/host-tested/unpinned-recompute.cmd
4e5cd9ef3b2689975963a12dbe712c47a8c89cd67a514ead528d22884bc43ed1  evidence/aienet0-20261028/host-tested/unpinned-recompute.run.err
6b6bc4513859f612f20e14c7fca3ff1d3efe02ecc6ec115c98d4c1ff3dcabb9c  evidence/aienet0-20261028/host-tested/unpinned-recompute.run.out
72e353d5546450d0b9960b41814a77af5599137932850fcb46a73c73a0120a61  evidence/aienet0-20261028/host-tested/unpinned-recompute.serve.err
4f9425970ea1ec12fe27ea6fd411b02467fb69fd1d11976e832e0a0b9869a940  evidence/aienet0-20261028/host-tested/unpinned-recompute.serve.out
3bd29a74123b83fa2a86d3ec98f943c9d94c063922b37dbb618439a01e333444  evidence/aienet0-20261028/host-tested/unpinned-volunteer.cmd
c3f2b677277a0887adab06ef4fcd81726406a66b97212e64c112753d7b7d9354  evidence/aienet0-20261028/host-tested/unpinned-volunteer.run.err
39c72a344250f1f263ae0c597c3cb1e2cf25c149e12a1814fd18db4a5cdb3588  evidence/aienet0-20261028/host-tested/unpinned-volunteer.run.out
ff4c3874a121c666563835f79c6ca0284bd562d49507c670af6d9912962f8f7b  evidence/aienet0-20261028/host-tested/unpinned-volunteer.serve.err
ca669b503970af4dbab4764aba9c1664d1854ca4016eb1320038cb7f7c354ca7  evidence/aienet0-20261028/host-tested/unpinned-volunteer.serve.out
f1ad235612e8b01363cb9435b6a7e8366b60df1658417f33b08fac9fa774fd40  evidence/aienet0-20261028/host-tested/wrong-coordinator-key.cmd
b53406140ae99b31da941bbcaf37c16e935bcd85188bd1fc1b880bbfe687c231  evidence/aienet0-20261028/host-tested/wrong-coordinator-key.run.err
c6ef29f7d95a440ed375c3612cc2d5aa583ff8d61f76e4fc53d1f558d63efca0  evidence/aienet0-20261028/host-tested/wrong-coordinator-key.run.out
b808154e103979a0ba1273d1c556a58971ff0c029f826cb01a12fc7fca821692  evidence/aienet0-20261028/host-tested/wrong-coordinator-key.serve.err
2a0e1e8273371d7ea46f8eee13809a31ac28ce48f20781399e55610b0fe48aa5  evidence/aienet0-20261028/host-tested/wrong-coordinator-key.serve.out
7aa52c7c0f7ae7acc74f05e049e5af81b2c5c9b06568ab60acff780ea18d4aec  evidence/aienet0-20261028/host-tested/wrong-output.cmd
609166ae5a95a307d2ec61100910e87ba461aaf50847bfd98d3800d817300c64  evidence/aienet0-20261028/host-tested/wrong-output.run.err
88fce8b3cf7b599a7d5d29d25644920a16d7c18fb5d1a90e8c1bb53220de996d  evidence/aienet0-20261028/host-tested/wrong-output.run.out
d17cf65c8361785b2ca70bab4bc7b092f88e403a5f59c7e8601c1fd5224fba80  evidence/aienet0-20261028/host-tested/wrong-output.serve.err
5f57b60f1401ee813f1138f63641b5e8f76a164590644243e9063b9378aac7bb  evidence/aienet0-20261028/host-tested/wrong-output.serve.out
708348aa43fed9be5d7566c9b4f041d870f6c7eb1f7dd2eb6f495625155d70ef  evidence/aienet0-20261028/macbook-public-keys.txt
5ab2f8ce854c24d63c392c6c7350cec0ed431edb5da7c62c899d3aeaadebf2f9  evidence/aienet0-20261028/mutants-open-humanity.log
de16242ba5d6a3cca14a6daa27bb3e443acdadac361f1d1fc06b618677af803a  evidence/aienet0-20261028/mutants-open-humanity/baseline.controls.summary.tsv
5d89e77858b104a58833cc8cdf2293649a5da5ad1b0627b5070b14a8bf64d1c6  evidence/aienet0-20261028/mutants-open-humanity/carrier-bound.diff
610c65514c6b869558e1cd3e09ff272ab8c8e9a5389d3aa742f20a24e175285f  evidence/aienet0-20261028/mutants-open-humanity/coordinator-pin.diff
a24538a65a08c9c9679c75bb7bdab551b2e6249ad0f232df5e266ef8cbd8ad9f  evidence/aienet0-20261028/mutants-open-humanity/recompute-pin.controls.summary.tsv
72134dcbf15be050512e8e751eed78332403dd5e3d269331163fcf5125b6877b  evidence/aienet0-20261028/mutants-open-humanity/recompute-pin.diff
db77ef5d6d3ae8c727326d873b4e329ef35bfe7d441a492c446c43a9897e2a91  evidence/aienet0-20261028/mutants-open-humanity/replay.controls.summary.tsv
7590639e8b02a1e38da0c03667096c88ed7133ddcc5871f34b143ebcd0051993  evidence/aienet0-20261028/mutants-open-humanity/replay.diff
63a716fe64c89045544426712791a6bd7c128b0e59531c1a31947c36e8303fd8  evidence/aienet0-20261028/mutants-open-humanity/volunteer-pin.diff
f4dc65090b30897a8e65f827d497682ea7a6ed798154fe75cd90ff1522d0d75e  evidence/aienet0-20261028/mutants-protocols.log
f5eac6c3177d4b379fe1b539df5b3035527a6c3f873392ba62bf5505446c57da  evidence/aienet0-20261028/parity.log
283c0d6e4baaee5eef3813e69023f3cd2690d61990812f768cc5e9e5fda886cc  evidence/aienet0-20261028/recompute.sha256
363a28b002d8e120188dd8336b0a1dc637c1d7d8338bcad868f4df777a518bce  evidence/aienet0-20261028/settlement/binaries.txt
03149ec70ca239d7cf9db1040e844cf8d3ff5991a923fe4f59bf82755765ceb4  evidence/aienet0-20261028/settlement/env-mac.sh
d1dd3f93d0d646f970db7158befdbb87237b5aad38ae45ef9166fb2181d9cd29  evidence/aienet0-20261028/settlement/honest.rc
c9b41c44a42bd1e0043389c238b7ce0a8ff4d034a50fe2614da777cd80730f57  evidence/aienet0-20261028/settlement/honest.stdout
b1cad0e54bec8a1980b5babeef600721bff5ce4edb6340ce366ade08ec6481dd  evidence/aienet0-20261028/settlement/honest/SHA256SUMS
fb2daa49cdf18216f6961857789a36bfc9b5cf8cd32a720bdadb3ea09b79391b  evidence/aienet0-20261028/settlement/honest/audit.out
bbb58b9e034721df3a747fe219be610a9c76dc3ecca13f676276ed9941573e9c  evidence/aienet0-20261028/settlement/honest/balance-provider.out
a91fcb9ad55158707c17b592d6e68cfd23ccda405c54ea5ee793a82cb41abfd3  evidence/aienet0-20261028/settlement/honest/balance-requester.out
8299615ad573de92edd685db5f54facc62e36f97702ce04bf705705f5741a9f8  evidence/aienet0-20261028/settlement/honest/balance-verifier.out
5f1e49fd053df4d3060bb663def98b8decf7d0fa266a5a94a7cd16e5adc5a539  evidence/aienet0-20261028/settlement/honest/bundle.out
54cf08863d4775f603b6bd400dc4e8267043102f0220a7a9808d8c0bf9fa96dc  evidence/aienet0-20261028/settlement/honest/journal/journal
c372a73963942fb4b7e2d765e1a193638438f2d5081ae954529dc335759e7dcd  evidence/aienet0-20261028/settlement/honest/out/ad32bc5bdf9e9fd644f886cf1a9429b8e14e3817c2f37ba2f401c9eb61190d22.an0b
3a44a44ed9a72125f0f1f59de4aaad96bc8dfe5baa3a619e5f57c531f61845d6  evidence/aienet0-20261028/settlement/honest/out/ad32bc5bdf9e9fd644f886cf1a9429b8e14e3817c2f37ba2f401c9eb61190d22.mjr1
8a108bb6b0e117a41912a8c947c59f9d41bf2a50d15af652c5524e6febdca5ff  evidence/aienet0-20261028/settlement/honest/out/ad32bc5bdf9e9fd644f886cf1a9429b8e14e3817c2f37ba2f401c9eb61190d22.mjv
c372a73963942fb4b7e2d765e1a193638438f2d5081ae954529dc335759e7dcd  evidence/aienet0-20261028/settlement/honest/out/job.an0b
9a5075623315a0564dbc44945916947eed53499f8fd314e2310699a28f8a09e5  evidence/aienet0-20261028/settlement/honest/prefund.out
d334f1000699ce54455b2eef0d4ebd8b7fdb9336a18944dd4a98fd44dea0a93e  evidence/aienet0-20261028/settlement/honest/reserve.out
744e2edca80c8dc0478b4aa83a88bf81fcd55424b8741039321bc54df1c7b0b1  evidence/aienet0-20261028/settlement/honest/run.out
28bdb816e9dfa899ba169e5a9fc18828a6caad00bf79c97a7698dbe7ee691bb1  evidence/aienet0-20261028/settlement/honest/serve.err
559576b13b4e15f728966ab916e7f883327ef15449b2e583b9e22a316462dd01  evidence/aienet0-20261028/settlement/honest/serve.out
e9714f58bfd7204389c401a8fe500f08c7a3cf04eef9de00c1b9331a897cb9ed  evidence/aienet0-20261028/settlement/honest/settle-again.out
8dacddfe4ad65cd20bca5b8aa454c4aa41ea9437956e8f737bd9e6857755a199  evidence/aienet0-20261028/settlement/honest/settle.out
34e2d16f3ee735826ec2abc66844ed4c17f6959f4611dca7cda8eb35e946ce69  evidence/aienet0-20261028/settlement/honest/show.out
7cab10c749e99f63cad5ccb30fa9a1feb5f0e4f5acf98f5e114751dba8249701  evidence/aienet0-20261028/settlement/honest/transcript.txt
ab810f96109308bb6fa1892ebfba7c13877d2651b571162102784500015b554e  evidence/aienet0-20261028/settlement/mac-pgrep.txt
fc2f07e12a973a4496cb3f8b24f3a0c7d4ff04232e5c8f74efd3680dee7a1ef9  evidence/aienet0-20261028/settlement/settle-run.sh.at-run
f702632795073453a3ff10039f9af987c0e275d4c349892176f8aafbfdd9154e  evidence/aienet0-20261028/settlement/tampered-receipt.rc
7344832d2ee9e6a68e100eef07bc760960df5d1b316176ac7ad42a565f4f2907  evidence/aienet0-20261028/settlement/tampered-receipt.stdout
d256929ea121e92b636e6f0aaba63e30f9fed0d5c5f6dd560fc8d97877b31978  evidence/aienet0-20261028/settlement/tampered-receipt/SHA256SUMS
8074fea4d83aaa469ee0e005383e9b372624851290c5b74ad59691531541d409  evidence/aienet0-20261028/settlement/tampered-receipt/audit.out
ef084bdc419015e7cb600def5bcce99790a6d0f08f6eff82292756a7a50ea0a9  evidence/aienet0-20261028/settlement/tampered-receipt/balance-provider.out
ca85432ec0d96bf92be9c0a919a919c6ce712322ace70b955a2c386c53d4b829  evidence/aienet0-20261028/settlement/tampered-receipt/balance-requester.out
b3ab3d2d450aaecaaefc4caa4ce5d14b69b0af6eb8c26eb49afb3392f9c9cf98  evidence/aienet0-20261028/settlement/tampered-receipt/balance-verifier.out
6a0c95b44c51eddf0796d0d1b0fed93ca94e852b5ef5933e5ef778dc3e74f5c6  evidence/aienet0-20261028/settlement/tampered-receipt/bundle.out
2e3b77831c22284d7a721acb5a031d8dd4f94fe5c145acbd4e4de3a88db2acdf  evidence/aienet0-20261028/settlement/tampered-receipt/journal/journal
54d711496778d6a3cebc4520c4dc61db1239c5e07b01dbef0bc2f31c3113ce09  evidence/aienet0-20261028/settlement/tampered-receipt/out/4279462c72caa5282424bb92ff09f4bd134b914f573439b714110d2dd4090924.an0b
54d711496778d6a3cebc4520c4dc61db1239c5e07b01dbef0bc2f31c3113ce09  evidence/aienet0-20261028/settlement/tampered-receipt/out/job.an0b
9a5075623315a0564dbc44945916947eed53499f8fd314e2310699a28f8a09e5  evidence/aienet0-20261028/settlement/tampered-receipt/prefund.out
0ad51c693b7f36a11226a894c2d262379349c57a423f869ff66f54723b01231f  evidence/aienet0-20261028/settlement/tampered-receipt/refund.out
acc84f96d0749aae4f42924ff43cf9aba6d711a5b8e5c6a187c23bb542754fb8  evidence/aienet0-20261028/settlement/tampered-receipt/reserve.out
730557f9a058d5f12e530a408c6cc4cac6f31ce2a0d99c71d7743988c545c77e  evidence/aienet0-20261028/settlement/tampered-receipt/run.out
fb4d821d3b7fc4c1d78a9efd880aec472204d000a017eceff5cdcceb35a17c3d  evidence/aienet0-20261028/settlement/tampered-receipt/serve.err
869a6fedf5513555342ac72ae72009cc19becfb1805c2136c19f63453b995438  evidence/aienet0-20261028/settlement/tampered-receipt/serve.out
df9a8c00cc1c2fcd32d0738ad1ede3f540847967b2922f33ba22a98be708a934  evidence/aienet0-20261028/settlement/tampered-receipt/show.out
7feb882a028c09f2624622c03465ac3bc032b8c3b71061583d5a3372d0ff2ccc  evidence/aienet0-20261028/settlement/tampered-receipt/transcript.txt
98aa662853484a09a0742911a28bd26ee02469f43a79c390609c1fc6f7fe3f55  evidence/aienet0-20261028/spark-public-keys.txt
510deb80185b91fa750cb2af26b2f679afb413cbd20cb55b40a2d6a4ebcf2ec9  evidence/aienet0-20261028/xcheck662.log
9b740b11dc511bfb511ee6e426721aac81eb03591ae70a478cd698922447f3e5  evidence/aienet0-20261028/xcheck662.pins
6185ff7e72d3f80ffb946bc7d6478425838656bbfc7f323eb65a6ed4c9910fe8  evidence/aienet0-20261028/xcheck662/Cargo.toml
d963234867db4f8b3f895e99766f591c4a254fc3e23a61a0165f5be4aa0cbf33  evidence/aienet0-20261028/xcheck662/main.rs
```
