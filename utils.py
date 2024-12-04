import json
import os

# config.json 파일 경로
CONFIG_FILE = 'config.json'

# 기본 설정 값
default_config = {
    "NORMAL_IP_RANGES": ["192.168.1.0/24", "10.0.0.0/8"],
    "NORMAL_PORTS": [80, 443, 1883, 8883, 5683],
    "MAX_PACKET_SIZE": 1500,
    #"IOT_DEVICES": {}
}

# config.json 읽기 함수
def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config)  # config.json 파일이 없으면 기본값 저장
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

# config.json 쓰기 함수
def save_config(config_data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

# 설정 값 불러오기
config = load_config()

# 설정 값 변수들 정의 (다른 모듈에서 사용 가능)
NORMAL_IP_RANGES = config["NORMAL_IP_RANGES"]
NORMAL_PORTS = config["NORMAL_PORTS"]
MAX_PACKET_SIZE = config["MAX_PACKET_SIZE"]
IOT_DEVICES = config["IOT_DEVICES"]

# 이상 트래픽 판별 함수 (packet_analyzer.py에서 호출됨)
def is_abnormal_traffic(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if ip_src not in NORMAL_IP_RANGES or ip_dst not in NORMAL_IP_RANGES:
            return True
    
    return False

# 비정상 활동 로그 기록 함수 (packet_analyzer.py에서 호출됨)
def log_abnormal_activity(src_ip, dst_ip, reason):
    with open("abnormal_activity.log", "a") as log_file:
        log_file.write(f"Abnormal activity detected: src={src_ip}, dst={dst_ip}, reason={reason}\n")