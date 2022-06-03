import log4js from "log4js";
import path from "path";
import fs from "fs";
import util from "util";

const { configure, getLogger } = log4js;

export default class Logger {
    static async configure() {
        const readfile = util.promisify(fs.readFile);

        const json = await readfile(path.resolve(process.cwd(), "./log4js.json"), "utf8");

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
                log_logger.log("info", args[0]);
            };
            console.error = function () {
                let args = Array.prototype.slice.call(arguments);
                // error.apply(this, args);
                error_logger.log("error", args[0]);
            };
            console.info = function () {
                let args = Array.prototype.slice.call(arguments);
                // info.apply(this, args);
                log_logger.log("info", args[0]);
            };
            console.debug = function () {
                /*if (global.settings.debug.value) {*/
                let args = Array.prototype.slice.call(arguments);
                // debug.apply(this, [args[1], args[2]]);
                debug_logger.log("debug", args[0]);
            };

            console.custom = function (logger, level, message) {
                const custom_logger = getLogger(logger);
                custom_logger.log(level, message);
            };
        })();
    }
}
