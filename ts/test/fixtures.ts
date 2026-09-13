/** Named conformance fixtures — mirror tests/fixtures.py exactly so both
 * languages hash and sign identically (spec §15.2 public test seed). */

import { actionHash, tokenSignMessage } from "../src/hashing.ts";
import { sign } from "../src/ed25519.ts";

export const R = "lwr_000000000000000000001";
export const Q = "lwq_000000000000000000001";
export const C = "lwc_000000000000000000001";
export const A = "lwa_000000000000000000001";
export const T = "lwt_000000000000000000001";
export const P = "lwp_000000000000000000001";
export const K = "lwk_000000000000000000001";
export const Z = "0".repeat(64);

export const M = {
  id: "dense-small",
  kind: "dense-v1",
  parameters: "1000",
  layers: 1,
  hidden: 10,
  tokenizer_hash: "d79684d992c6150eea853d790cdef25f804d994cfe3a9198a5b012132dc46ec6",
  artifact_hash: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  safety_milli: 1100,
};

export const W = { model_id: "dense-small", input_tokens: "2", max_output_tokens: "3", batch: 1 };

export const EST = {
  estimator: "dense-v1",
  base_flops: "10000",
  attention_flops: "400",
  charged_flops: "11440",
  coverage: "cooperative_estimate",
};

export const B = {
  max_flops: "20000",
  max_energy_uj: "1000000",
  spawns: 1,
  max_wall_us: "10000000",
};

export const ACT = { kind: "spawn", exec: { argv: ["/usr/bin/true"], cwd: "/work", env: {} } };

export const SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
export const SEED = Buffer.from(SEED_HEX, "hex");
export const PUB = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

export const TOKEN_BODY = {
  v: 1,
  key_id: K,
  token_id: T,
  run_id: R,
  channel_id: P,
  action_hash: actionHash(ACT),
  issued_us: "0",
  expires_us: "1000000",
  issue_seq: "4",
};

export const TOKEN = {
  body: TOKEN_BODY,
  sig: Buffer.from(sign(new Uint8Array(SEED), tokenSignMessage(TOKEN_BODY))).toString("base64url"),
};

export const E1 = {
  body: {
    v: 1,
    run_id: R,
    event_id: "lwe_000000000000000000001",
    key_id: K,
    seq: "1",
    prev_hash: Z,
    t_us: "0",
    kind: "RunCreated",
    data: {
      config_hash: "0587b9faaf456ac6b84a092d6c73261269f82ce2b40bf972d7f0e0fba671b3dd",
    },
  },
  hash: "8289323c2e35432dd855b87a9e38b9890d74b9b476c439e19d48cfb55a499c1f",
  sig: "l34fqScQFAVOMVFMQBwh3CzD87c90R8dFoQKuBOKaBWl2sOZQIApvVu_6PHofB_fiT7kMrdO45Uxs3LMoG4TBw",
};

export const E2 = {
  body: {
    v: 1,
    run_id: R,
    event_id: "lwe_000000000000000000002",
    key_id: K,
    seq: "2",
    prev_hash: "8289323c2e35432dd855b87a9e38b9890d74b9b476c439e19d48cfb55a499c1f",
    t_us: "1",
    kind: "RunRejected",
    data: { code: "SENSOR_UNAVAILABLE" },
  },
  hash: "19c47ef3490cf77f7df075b58ec06009191f74830080a3aefd1ad7a299f776ed",
  sig: "D0gESWxAizRsoEtGHf0U2meKDoMHk44NwK1nQ-kZZk6UXiRQt4wTsZQ7Y49XJQ9bRwCaQPYQduMUQI5NeqWQCw",
};
