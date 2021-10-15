class KnexConnector {

    init(config) {
        this.connection = require('knex')(config)
    }


    test() {
        return this.connection.raw('select 1+1 as result');
    }
}


export default new KnexConnector();