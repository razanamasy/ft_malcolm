Launch two VM with : vagrant up </br>
check IP address of both VM in network shared with host (you can also check in the vagrantfile) </br>
Check ARP cache : ip neigh show
Delete ARP cache if needed sudo ip neigh flush all dev enp0s8 </br>
