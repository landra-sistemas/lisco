import { expect } from "chai";

import { Utils } from "../src";

describe("Utils", () => {
    it("#arrayToLower()", async () => {
        let result = Utils.arrayToLower(["BANANA"]);

        expect(result).to.contain("banana");
    });

    it("#replaceAll()", async () => {
        let result = Utils.replaceAll("foo|boo|poo", "oo", "aaa");

        expect(result).to.eq("faaa|baaa|paaa");
    });

    it("#encrypts()", async () => {
        let result = Utils.encrypt("asdfasdf");
        expect(result).to.eq("51c4a40ef83b83d21c3ed98e6e661448");
    });

    it("#decrypt()", async () => {
        let result = Utils.decrypt("51c4a40ef83b83d21c3ed98e6e661448");
        expect(result).to.eq("asdfasdf");
    });

    it("#generateKeys()", async () => {
        let result = Utils.generateKeys();
        console.log(result);
        expect(result).to.be.an("object");
        expect(result).to.have.property("key");
        expect(result).to.have.property("iv");
    });
});
