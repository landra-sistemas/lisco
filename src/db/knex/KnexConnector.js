import Knex from 'knex'

class KnexConnector {


    init(config) {

        /**
         * References the current connection of the app
         * @type {Knex}
         * @public
         */
        this.connection = Knex(config)
    }

    /**
     * Configura de forma global los aliases de las columnas para utilizar en FQL.
     * 
     * La estructura es 
     * {
            "table1": {
                "alias1": "column1",
                "alias2": "column2"
            },
            "table2": {
                "alias1": "column1"
            }
        }
     *
     * @param {*} aliases 
     */
    setColumnAliases(aliases) {
        this.columnAliases = aliases;
    }
    


    test() {
        return this.connection.raw('select 1+1 as result');
    }
}


export default new KnexConnector();