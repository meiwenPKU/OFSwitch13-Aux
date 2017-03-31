This module is an extension of ofswitch13 for ns3 simulation(<https://bitbucket.org/ljerezchaves/ofswitch13-module>). It aims to support multiple auxiliary connections in the simulation. Currently, it supports multiple tcp/udp auxiliary connections. To use the module, just follow the instructions provided by <http://www.lrc.ic.unicamp.br/ofswitch13/> except for 
1) download [OfSoftSwitch-Aux module][ofsoft-aux] instead of [ofsoftswitch13][ofsoft13]
2) download this module instead of the original one in <https://bitbucket.org/ljerezchaves/ofswitch13-module>

After installing these two modules, you can test two examples: one is for simulating linear network, by
```
$ ./waf --run linear-auxConn
```
The other one is to simulate campus network, by
```
$ ./waf --run campus-auxConn
```
[ofsoft-aux]:https://github.com/meiwenPKU/OfSoftSwitch-Aux.git
[ofsoft13]: https://github.com/CPqD/ofsoftswitch13.git
