from scapy.all import IP, TCP, UDP
from utils import log_abnormal_activity # 비정상 활동 로그 기록 함수

class PacketAnalyzer: #클래스는 IoT 장치 정보, 정상 IP 범위, 정상 포트, 최대 패킷 크기를 받아서 패킷을 분석합니다.
    def __init__(self, iot_devices=None, normal_ip_ranges=None, normal_ports=None, max_packet_size=None):
        self.iot_devices = iot_devices or {}
        self.normal_ip_ranges = normal_ip_ranges or []
        self.normal_ports = normal_ports or []
        self.max_packet_size = max_packet_size or 1500

    def set_iot_devices(self, iot_devices):
        self.iot_devices = iot_devices

    def analyze_packet(self, packet):#메서드는 IP, TCP, UDP 패킷을 분석하고, 패킷의 출발지 IP, 목적지 IP, 포트, 프로토콜, 크기 등을 기록합니다.
        # IP, TCP, UDP 패킷을 분석하는 메서드
        if Ether in packet:  # Ether 레이어가 존재하는지 확인
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
        else:
            src_mac = dst_mac = None  # Ether 레이어가 없으면 None으로 설정

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_size = len(packet)

            # 포트 정보 추출
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                src_port = dst_port = None

            # IoT 디바이스 정보 가져오기
            device_name = self.iot_devices.get(src_ip, self.iot_devices.get(dst_ip, "Unknown Device"))
            print(f"Analyzing packet: src_ip={src_ip}, dst_ip={dst_ip}, device_name={device_name}, src_mac={src_mac}, dst_mac={dst_mac}") # 디버깅 출력

            # 비정상 트래픽 판단
            is_abnormal, reason = self.is_abnormal_traffic(dst_ip, dst_port, packet_size)#메서드는 IP 범위, 포트, 패킷 크기를 기준으로 비정상적인 트래픽을 판단합니다.
            
            # 비정상 트래픽 로그 기록 (이 함수는 utils.py에서 정의되어야 함)
            if is_abnormal:
                log_abnormal_activity(src_ip, dst_ip, reason)

            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_mac': src_mac,  # MAC 주소 추가
                'dst_mac': dst_mac,  # MAC 주소 추가
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'size': packet_size,
                'is_abnormal': is_abnormal,
                'device_name': device_name
            }
        return None

    def is_abnormal_traffic(self, dst_ip, dst_port, packet_size):
        """비정상 트래픽을 판단하는 함수"""
        if dst_ip not in self.normal_ip_ranges:
            return True, "IP 범위 오류"
        if dst_port not in self.normal_ports:
            return True, "포트 오류"
        if packet_size > self.max_packet_size:
            return True, "패킷 크기 초과"
        return False, ""