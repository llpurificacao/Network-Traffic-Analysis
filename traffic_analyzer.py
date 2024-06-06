from scapy.all import sniff, IP
from typing import List, Tuple
from collections import defaultdict
from operator import itemgetter

# Dicionário para mapear números de protocolos aos seus nomes
PROTOCOLS = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

class TrafficAnalyzer:
    def __init__(self, interface: str, count: int):
        self.interface = interface
        self.count = count

    def capture_packets(self) -> List[IP]:
        """
        Captura pacotes da interface de rede especificada.

        Returns:
        - Uma lista de objetos IP representando os pacotes capturados.
        """
        packets = sniff(iface=self.interface, count=self.count)
        return packets

    def analyze_traffic(self, packets: List[IP]) -> Tuple[int, dict, List[Tuple[str, int]], List[Tuple[str, int]]]:
        """
        Analisa os pacotes capturados e calcula estatísticas básicas sobre o tráfego.

        Args:
        - packets: Uma lista de objetos IP representando os pacotes capturados.

        Returns:
        - Uma tupla contendo o número total de pacotes, a distribuição de protocolos,
          os top 5 IPs de origem com mais tráfego e os top 5 IPs de destino com mais tráfego.
        """
        total_packets = len(packets)
        
        protocols = defaultdict(int)
        src_ips = defaultdict(int)
        dst_ips = defaultdict(int)
        
        for packet in packets:
            proto = packet[IP].proto
            protocols[proto] += 1
            src_ips[packet[IP].src] += 1
            dst_ips[packet[IP].dst] += 1
        
        top_src_ips = sorted(src_ips.items(), key=itemgetter(1), reverse=True)[:5]
        top_dst_ips = sorted(dst_ips.items(), key=itemgetter(1), reverse=True)[:5]
        
        return total_packets, protocols, top_src_ips, top_dst_ips

    def print_statistics(self, total_packets: int, protocols: dict, top_src_ips: List[Tuple[str, int]], top_dst_ips: List[Tuple[str, int]]):
        """
        Exibe estatísticas básicas sobre o tráfego capturado.

        Args:
        - total_packets: O número total de pacotes capturados.
        - protocols: Um dicionário com a distribuição de protocolos.
        - top_src_ips: Uma lista de tuplas com os top 5 IPs de origem com mais tráfego.
        - top_dst_ips: Uma lista de tuplas com os top 5 IPs de destino com mais tráfego.
        """
        print("---------- Estatísticas ----------")
        print(f"Total de pacotes capturados: {total_packets}")
        
        print("\nDistribuição de protocolos:")
        for protocol, count in protocols.items():
            protocol_name = PROTOCOLS.get(protocol, f"Desconhecido ({protocol})")
            print(f" - {protocol_name}: {count} pacotes")
        
        print("\nTop 5 IPs de origem:")
        for ip, count in top_src_ips:
            print(f" - {ip}: {count} pacotes")
        
        print("\nTop 5 IPs de destino:")
        for ip, count in top_dst_ips:
            print(f" - {ip}: {count} pacotes")

def main():
    # Interface de rede e quantidade de pacotes a serem capturados
    interface = "eth0"
    count = 10

    # Instância da classe TrafficAnalyzer
    analyzer = TrafficAnalyzer(interface, count)

    # Captura de pacotes e análise de tráfego
    packets = analyzer.capture_packets()
    total_packets, protocols, top_src_ips, top_dst_ips = analyzer.analyze_traffic(packets)

    # Exibição das estatísticas
    analyzer.print_statistics(total_packets, protocols, top_src_ips, top_dst_ips)

if __name__ == "__main__":
    main()
