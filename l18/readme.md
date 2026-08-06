[Automatic approach]

step1 -> sudo chmod +x setup.sh

step2 -> sudo ./setup.sh


#############################################################

[Manual approach]

sudo apt install nlohmann-json3-dev

sudo apt install libpugixml-dev

[1st step]
        -> git clone https://github.com/axboe/liburing.git   (owner had already given how to make and install  
           do all the steps, after sucess you will see liburing and liburing.h inside /usr/include/

[2nd step]
        -> git clone https://github.com/cameron314/concurrentqueue.git 
        -> copy concurrentqueue.h inside /usr/include/ and /usr/local/include/ both dir

[3rd step]

   -> sudo mkdir -p /usr/share/shiv && sudo cp mac-vendor.txt ports.txt services /usr/share/shiv/

[4th step]
 
 -> sudo make install


#################################################################


[For clean and uninstall]

-> sudo make clean

-> sudo make uninstall

 














