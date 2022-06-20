const { BaseController, Utils } = require("../../../"); //require("@landra_sistemas/lisco")

const { UserService } = null; //require("../services/UserService");

class HomeController extends BaseController {
    entity = "user";
    service = UserService;
    table = "user";

    // Si el linter utilizado no soporta attributos de clase
    // constructor() {
    //     super();
    //     this.entity = "user";
    //     this.service = UserService;
    //     this.table = "user";
    // }

    home(req, res) {
        res.send("Hello world!");
    }
}

module.exports = HomeController;
