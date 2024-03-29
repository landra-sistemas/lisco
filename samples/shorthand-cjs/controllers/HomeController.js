const { BaseController, Utils } = require("../../../"); //require("@landra_sistemas/lisco")

class HomeController extends BaseController {
    routes = {
        "/": {
            get: this.home.bind(this),
        },
    };

    // Si el linter utilizado no soporta attributos de clase
    // constructor() {
    //     super();
    //     this.routes = {
    //         "/": {
    //             get: this.home.bind(this),
    //         },
    //     };
    // }

    home(req, res) {
        res.send("Hello world!");
    }
}

module.exports = HomeController;
