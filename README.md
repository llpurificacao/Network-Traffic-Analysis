# TrafficAnalyzer

TrafficAnalyzer é um script Python que captura pacotes de rede de uma interface especificada e exibe estatísticas básicas sobre o tráfego. As estatísticas incluem o número total de pacotes capturados, a distribuição de protocolos, os top 5 IPs de origem e os top 5 IPs de destino.


### Pré-requisitos
 * Python 3
 * scapy


### Como configurar:

Ubuntu:
```
apt install python3 
pip install scapy 
na linha 80 em interface = "eth0" defina para a sua placa de rede.
```

### execução:
```
Como root execute: 
python3 -m venv venv
source venv/bin/activate
python3 traffic_analyzer.py
```
![337447690-dc34bb73-bca3-4931-a855-8b101de27c5a](https://github.com/llpurificacao/Network-Traffic-Analysis/assets/107150941/4319d354-00ac-420d-80c0-9aea62c0d278)

  
