# tracert-as   
Таск по протоколам интернет. Автор - Слабиков Павел, КБ-201

## Справка по аргументам
```
usage: tracert_as [-h] [--ttl TTL] hostname

positional arguments:
  hostname    Hostname to trace

optional arguments:
  -h, --help  show this help message and exit
  --ttl TTL   Max hops count

```
## Пример запуска 
    
    sudo python3 -m tracert_as vk.com --ttl 20
