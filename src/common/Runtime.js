import Utils from "./Utils.js";

import yargs from "yargs/yargs";
import { hideBin } from "yargs/helpers";
export default function Runtime() {
    const argv = yargs(hideBin(process.argv))
        .usage(
            `Como usar: 
            node execute.js [--generateKeys , --encrypt xxx] 
            
            ---> Si no se especifican parámetros el servidor arrancará normalmente.`
        )
        .alias('g', 'generateKeys')
        .describe('g', 'Genera unas claves para la aplicación')
        .alias('c', 'encrypt')
        .describe('c', 'Codifica el String proporcionado en base a la contraseña de .env')
        .nargs('c', 1)
        .help("h")
        .alias("h", "help").argv;

    //Parámetro para no arrancar el servidor y generar las claves JWT
    if (argv.generateKeys) {
        console.log("Generando claves para encriptación:");
        console.log(Utils.generateKeys());
        return process.exit(1);
    }

    if (argv.encrypt) {
        console.log("Resultado encryptación:");
        console.log(Utils.encrypt(argv.encrypt));
        return process.exit(1);
    }
}
