import { BaseController, Utils } from "../../../dist/lisco.esm.js"; //from "@landra_sistemas/lisco"

export default class HomeController extends BaseController {
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
