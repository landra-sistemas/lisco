import Utils from "./Utils";

import _optimist from "optimist";
export default function Runtime() {
    const optimist = _optimist.usage(
        "Como usar: \n node execute.js [--generateKeys , --encrypt xxx] \n\n Opciones:\n --generateKeys: Genera unas claves para la aplicación\n --encrypt String: Codifica el String proporcionado en base a la contraseña de .env \n\n ---> Si no se especifican parámetros el servidor arrancará normalmente."
    );
    const argv = optimist.argv;
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

    if (argv.h || argv.help) {
        console.log(optimist.help());
        return process.exit(1);
    }
}
