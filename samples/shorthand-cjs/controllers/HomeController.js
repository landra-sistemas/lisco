const { BaseController, Utils } = require("../../../"); //require("@landra_sistemas/lisco")

class HomeController extends BaseController {
    constructor() {
        super();

        //Shorthand for defining routes
        this.routes = {
            "/": {
                get: this.home.bind(this),
            },
        };
    }

    home(req, res) {
        res.send("Hello world!");
    }
}

module.exports = HomeController;
