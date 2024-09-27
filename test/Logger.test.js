import { expect } from "chai";
import path from "path";
import fs from "fs";
import util from "util";
import { Logger, Utils } from "../src/index.js";

describe("Logger", () => {
    it("#log()", async () => {
        const fs_readfile = util.promisify(fs.readFile);

        await Logger.configure();
        console.log("adf");
        console.error("err");
        console.info("info");
        console.debug("debug");
        console.custom("perf", "message");
        await Utils.sleep(300); //Let file write

        const content = await fs_readfile(path.resolve(process.cwd(), "./logs/default.log"), "utf-8");
        expect(content).not.to.be.null;
        expect(content).to.contain("[INFO] log - adf");
        expect(content).to.contain("[ERROR] error - err");
    });
});
