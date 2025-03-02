const banner = `
Created With LISCO!
          @              @@@@           @@@ @@@@   
         @@@@          @@@@@@@         @@@@@@@@    
      @@@   @@@@@@@@@@@@    @@@@@@@@     @@@@      
     @@@                         @@@@@  @@@@       
    @@@@   @@              @@      @@@@@@@@        
    @@@   @@@              @@@       @@@@          
   @@@@       @@@@@@@@@@@             @@@          
   @@@     @@@@  @@ @@@  @@@          @@@         
    @@@    @@@  @@@@@@@  @@@         @@@          
     @@@@     @@@@@@@@@            @@@@            
       @@@@@@               @@@@@@@@               
            @@@@@@@@@@@@@@@@  @@@@                 
            @@@   @@@   @@@@  @@@@                 
            @@@   @@@   @@@@  @@@@                 
`;

export const showBanner = () => {

    //TODO evitar lanzar el banner en modo cluster en los nodos hijos
    if (process.env.DISABLE_BANNER != "true") {
        console.log(banner);
    }
};
