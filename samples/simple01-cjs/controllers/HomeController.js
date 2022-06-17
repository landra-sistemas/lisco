const { BaseController, Utils } = require("../../../"); //require("@landra_sistemas/lisco")

class HomeController extends BaseController {
    configure() {
        const exAsync = Utils.expressHandler();
        this.router.get(
            "/",
            exAsync((...args) => this.home(...args))
        );

        return this.router;
    }

    home(req, res) {
        res.send("Hello world!");
    }
}

module.exports = HomeController;
