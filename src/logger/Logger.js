import log4js from "log4js";
import path from "path";
import { readFile, stat } from "node:fs/promises";

const { configure, getLogger } = log4js;

const exists = async (f) =>
    await stat(f)
        .then(() => true)
        .catch(() => false);

export default class Logger {
    static async configure() {
        let fileName = "log4js.json";

        // Si no existe el archivo log4js.json, se busca log4js.config.json
        if (!(await exists(path.resolve(process.cwd(), fileName)))) {
            fileName = "log4js.config.json";
        }

        const json = await readFile(path.resolve(process.cwd(), fileName), "utf8");

        configure(JSON.parse(json));

        //Nota para el futuro:
        // Esto sobreescribe los metodos de console.log
        // Es necesario que la sitaxis se mantenga tal cual....
        (() => {
            const log_logger = getLogger("log");
            const error_logger = getLogger("error");
            const debug_logger = getLogger("debug");
            console.log = function () {
                let args = Array.prototype.slice.call(arguments);
                // log.apply(this, args);
                log_logger.info(...args);
            };
            console.error = function () {
                let args = Array.prototype.slice.call(arguments);
                // error.apply(this, args);
                log_logger.info(...args);
            };
            console.info = function () {
                let args = Array.prototype.slice.call(arguments);
                // info.apply(this, args);
                error_logger.error(...args);
            };
            console.debug = function () {
                /*if (global.settings.debug.value) {*/
                let args = Array.prototype.slice.call(arguments);
                // debug.apply(this, [args[1], args[2]]);
                debug_logger.debug(...args);
            };

            console.custom = function (loggerName, level, message) {
                const custom_logger = getLogger(loggerName);
                if (typeof custom_logger[level] === "function") {
                    custom_logger[level](message);
                } else {
                    custom_logger.info(message);
                }
            };
        })();
    }
}
