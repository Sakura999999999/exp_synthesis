![alt text](acc332d9fb779e41f9e96f75262fc7a4.jpg)
![alt text](f1dac62402925902a4ce4a841ffb5312.jpg)

所以目前，对于cve-2022-32250，uaf.c（内核模块）里有vul1,vic1的定义，以及对应api，exp.c中有m1_uaf_to_unlink，选取vul，vic，mode复用就好。