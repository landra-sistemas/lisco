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


    test() {
        return this.connection.raw('select 1+1 as result');
    }
}


export default new KnexConnector();