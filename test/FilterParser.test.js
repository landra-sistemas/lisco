import { expect } from "chai";
import knex from "knex";
import { KnexConnector, KnexFilterParser } from "../src/db/index.js";

describe("KnexFilterParser", () => {
    it("#parseFiltersSimple()", async () => {
        let filters = {
            value: "test",
        };
        let query = knex("test")
            .from("test")
            .where((builder) => KnexFilterParser.parseFilters(builder, filters))
            .toSQL();

        expect(query).not.to.be.null;
        expect(query).to.have.property("sql");
        expect(query).to.have.property("bindings");
        expect(query.bindings).to.deep.eq(["test"]);
    });
    it("#parseFiltersExact()", async () => {
        let filters = {
            value: {
                type: "exact",
                value: "test",
            },
        };
        let query = knex("test")
            .from("test")
            .where((builder) => KnexFilterParser.parseFilters(builder, filters))
            .toSQL();

        expect(query).not.to.be.null;
        // expect(query).to.have.property('sql')
        // expect(query).to.have.property('bindings')
        // expect(query.bindings).to.deep.eq(['test'])
    });

    it("#parseFiltersBetween()", async () => {
        let filters = {
            value: {
                type: "between",
                start: "1",
                end: "10",
            },
        };
        let query = knex("test")
            .from("test")
            .where((builder) => KnexFilterParser.parseFilters(builder, filters))
            .toSQL();

        console.log(query);
        expect(query).not.to.be.null;
        expect(query).to.have.property("sql");
        expect(query.sql).to.contains("between");
        expect(query).to.have.property("bindings");
        // expect(query.bindings).to.deep.eq(['1', '10'])
    });
    it("#parseFiltersIn()", async () => {
        let filters = {
            value: {
                type: "in",
                value: [1, 2, 3],
            },
        };
        let query = knex("test")
            .from("test")
            .where((builder) => KnexFilterParser.parseFilters(builder, filters))
            .toSQL();

        console.log(query);
        expect(query).not.to.be.null;
        expect(query).to.have.property("sql");
        expect(query.sql).to.contains("in");
        expect(query).to.have.property("bindings");
        // expect(query.bindings).to.deep.eq([1, 2, 3])
    });

    it("#parseFiltersMultiple()", async () => {
        let filters = {
            value: {
                type: "in",
                value: [1, 2, 3],
            },
            value2: {
                type: "less",
                value: 3,
            },
            value3:{
                type: "any",
                value: "photos",
            }
        };
        let query = knex("test")
            .from("test")
            .where((builder) => KnexFilterParser.parseFilters(builder, filters))
            .toSQL();

        console.log(query);
        expect(query).not.to.be.null;
        expect(query).to.have.property("sql");
        expect(query.sql).to.contains("in");
        expect(query.sql).to.contains("<");
        expect(query).to.have.property('bindings')
        expect(query.bindings).to.deep.eq([1, 2, 3, 3, 'photos', 'value3'])
    });

    it("#parseSort()", async () => {
        let sort = {
            field: "test",
            direction: "ascend",
        };
        let sorts = KnexFilterParser.parseSort(sort);

        expect(sorts).not.to.be.null;
        expect(sorts).to.eq("test ASC");
    });

    it("#parseQueryString()", async () => {
        KnexConnector.setColumnAliases({
            test: {
                photos: "ANY(photos)",
            },
        });
        let string = "from:hi@retrace.io,foo@gmail.com to:me subject:vacations date:[1/10/2013 TO 15/04/2014] photos:beach";
        let query = knex("test")
            .from("test")
            .where((builder) => KnexFilterParser.parseQueryString(builder, string, "test"))
            .toSQL();
        console.log(query);

        expect(query).not.to.be.null;
        expect(query).to.have.property("sql");
    });
});
