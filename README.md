PyDatapath
==========

Instructions for installing pydatapath on the Mininet VM using VirualBox.

1. Download the [official Mininet VM](https://github.com/mininet/mininet/wiki/Mininet-VM-Images) 
(instructions tested using mininet-2.1.0p2-140718-ubuntu-14.04-server amd64 and i386 images).

2. Import into Virtual Box, in "Settings->Basic" set "Name" appropriately.

3. Checkout the latest POX branch 'carp'.
         
        $ cd ~/pox
        $ git pull
        $ git checkout -b carp origin/carp 
   
4. Install 'pxpcap' located under the POX folder.

         $ cd ~/pox/pox/lib/pxpcap/pxpcap_c
         $ ./build_linux
    This usually fails at the first run, not sure why, but passes on the second run. 
    So, run this once more to install correctly.
         
         $ ./build_linux
         
5. Install 'bitstring' 
        
         $ sudo easy_install bitstring
   
5. Clone the pydatapath repository to your home directory.
         
         $ cd ~   
         $ git clone https://github.com/NetASM/Pydatapath.git
         
6. Setup your environment variables by adding the following lines to end of .profile:

         export PATH=$PATH:$HOME/pydatapath:$HOME/pyretic:$HOME/pox   
         export PYTHONPATH=$HOME/pydatapath:$HOME/pyretic:$HOME/mininet:$HOME/pox

7. pydatapath needs sudo access to run. However, sudo doesn't preserve the PYTHONPATH environment variable.
In order to preserve the variable, create an alias for sudo named 'sudopy' as follows:

         $ alias sudopy='sudo PYTHONPATH=$PYTHONPATH'
    You can also add this to the end of .profile to automatically create an alias whenever you login the machine.
     
8. Finally, run pydatapath.
         
         $ sudopy pydatapath.py pydatapath.datapath
         
9. Test this by running an example mininet script in a separate terminal window.

         $ sudopy python pydatapath/pydatapath/examples/single_switch.py
         
Enjoy!
         
Contact: Muhammad Shahbaz 

Email: lastname (at) cc (dot) gatech (dot) edu
         
    

         
   

