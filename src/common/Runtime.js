import Utils from "./Utils.js";

import yargs from "yargs/yargs";
import { hideBin } from "yargs/helpers";

/**
 * Extra puede ser un array de objetos con la siguiente estructura:
 *
 * {
 *  "key": "c",
 *  "alias": "config",
 *  "describe": "Configuración",
 *  "fn": function(argv) { },
 *  "nargs": 0,
 *  "required": true
 * }
 * @param {*} extra
 * @returns
 */
export default async function Runtime(extra) {
    const cfg = yargs(hideBin(process.argv))
        .usage(
            `Como usar: 
            node $0 [options] 
            
            ** Si no se especifican parámetros el servidor arrancará normalmente. **`
        )
        .alias("g", "generateKeys")
        .describe("g", "Genera unas claves para la aplicación")
        .alias("c", "encrypt")
        .describe("c", "Codifica el String proporcionado en base a la contraseña de .env")
        .nargs("c", 1)
        .help("h")
        .alias("h", "help");

    let demand = [];
    if (extra) {
        for (const param of extra) {
            cfg.alias(param.key, param.alias);
            if (param.describe) {
                cfg.describe(param.key, param.describe);
            }
            if (param.nargs !== 0) {
                cfg.nargs(param.key, param.nargs);
            }
            if (param.boolean) {
                cfg.boolean(param.key);
            }
            if (param.choices) {
                cfg.choices(param.key, param.choices);
            }
            if (param.required) {
                demand.push(param.key);
            }
        }
    }

    if (demand.length !== 0) {
        cfg.demandOption(demand);
    }

    const argv = cfg.argv;
    //Parámetro para no arrancar el servidor y generar las claves JWT
    if (argv.generateKeys) {
        console.log("Generando claves para encriptación:");
        console.log(Utils.generateKeys());
        return process.exit(1);
    }

    if (argv.encrypt) {
        console.log("Resultado encryptación:");
        console.log(Utils.encrypt(String(argv.encrypt)));
        return process.exit(1);
    }

    if (extra) {
        for (const param of extra) {
            if (argv[param.key]) {
                await param.fn(argv);
                return process.exit(1);
            }
        }
    }
}
