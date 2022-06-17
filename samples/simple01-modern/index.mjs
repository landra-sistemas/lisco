import { config } from "dotenv-defaults";
import { App } from "../../dist/lisco.esm.js";//from "@landra_sistemas/lisco"
import HomeController from "./controllers/HomeController.mjs";

//Configure dotenv
config();

const main = async () => {
    App.runtime();

    App.statics = {
        "/temp": "/temp",
    };
    App.routes = [new HomeController()];

    await App.init({
        socketio: false,
    });

    App.start();
    App.server.on("listening", () => {
        console.log("listening");
    });
};

//Launch!
main();

//Capturar errores perdidos
process.on("uncaughtException", (err) => {
    // handle the error safely
    console.error(`Error: ${err || err.stack || err.message}`);
});
//Capturar promises perdidos
process.on("unhandledPromiseException", (err) => {
    // handle the error safely
    console.error(`Error: ${err || err.stack || err.message}`);
});
