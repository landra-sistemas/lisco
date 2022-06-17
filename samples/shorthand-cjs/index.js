const { config } = require("dotenv-defaults");
const { App } = require("../../");//require("@landra_sistemas/lisco")
const HomeController = require("./controllers/HomeController");

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

    await App.start();
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
