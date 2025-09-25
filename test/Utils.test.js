import { expect } from "chai";

import { Utils } from "../src/index.js";

describe("Utils", () => {
    it("#arrayToLower()", async () => {
        const result = Utils.arrayToLower(["BANANA"]);

        expect(result).to.contain("banana");
    });

    it("#replaceAll()", async () => {
        const result = Utils.replaceAll("foo|boo|poo", "oo", "aaa");

        expect(result).to.eq("faaa|baaa|paaa");
    });

    it("#encrypts()", async () => {
        const result = Utils.encrypt("asdfasdf");
        const decrypted = Utils.decrypt(result);
        expect(decrypted).to.eq('asdfasdf');
    });

    it("#decrypt()", async () => {
        const result = Utils.decrypt('XKhioljx3J29rT50QkbeudX3c+i5zQth');
        expect(result).to.eq("asdfasdf");
    });

    it("#generateKeys()", async () => {
        const result = Utils.generateKeys();
        console.log(result);
        expect(result).to.be.an("object");
        expect(result).to.have.property("key");
    });
});
