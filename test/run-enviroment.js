
before(function (done) {
    //Esto sirve para poder iniciar la app y hacer pruebas de la API. 
    //De momento no se usa pero en un futuro es una posibilidad

    // console.log('Starting test env');
    // this.timeout(30 * 1000);
    // require('../loadapp.js')(false).then(() => {
    //     console.log('started')
    //     setTimeout(done, 300);
    // }).catch(done);
    done();
})