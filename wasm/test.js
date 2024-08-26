import * as signal from "../out/zkgroup.js"
import * as signal2 from "../out/zkgroup_bg.js"
import fs from "fs"
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const wasm = fs.readFileSync(__dirname + "/../out/zkgroup_bg.wasm")

signal.initSync(wasm)

console.log(signal2)
const start = performance.now()

for (let i = 0; i < 100; i++) {
	var secret_params = signal.group_secret_params_derive_from_master_key(Buffer.alloc(32))
}

console.log(performance.now() - start)

// console.log(secret_params)

// console.log(signal.group_secret_params_get_public_params(secret_params))
