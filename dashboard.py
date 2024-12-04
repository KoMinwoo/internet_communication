import streamlit as st
import pandas as pd
from scapy.all import sniff
from packet_analyzer import PacketAnalyzer
from visualizer import Visualizer
import threading
import json
import datetime
import socket
import ipaddress
import os

# 설정을 로드하고 저장하는 함수들
def load_config():
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_config(config):
    with open('config.json', 'w') as file:
        json.dump(config, file, indent=4)

# IoT 모니터링 클래스
class UnifiedMonitor:
    def __init__(self, iot_devices, normal_ip_ranges, normal_ports, max_packet_size):
        self.iot_devices = iot_devices
        self.normal_ip_ranges = normal_ip_ranges
        self.normal_ports = normal_ports
        self.max_packet_size = max_packet_size
        self.packet_analyzer = PacketAnalyzer(self.iot_devices, self.normal_ip_ranges, self.normal_ports, self.max_packet_size)
        self.is_monitoring = False
        self.monitoring_thread = None
        self.visualizer = Visualizer(self.iot_devices)

    def update_settings(self, new_iot_devices, new_ip_ranges, new_ports, new_max_size):
        self.iot_devices = new_iot_devices
        self.normal_ip_ranges = new_ip_ranges
        self.normal_ports = new_ports
        self.max_packet_size = new_max_size
        self.packet_analyzer.set_iot_devices(self.iot_devices)
        self.packet_analyzer.normal_ip_ranges = self.normal_ip_ranges
        self.packet_analyzer.normal_ports = self.normal_ports
        self.packet_analyzer.max_packet_size = self.max_packet_size
        self.visualizer.set_iot_devices(self.iot_devices)

    def process_packet(self, packet):
        if self.is_monitoring:
            packet_info = self.packet_analyzer.analyze_packet(packet)
            if packet_info:
                self.visualizer.add_data(packet_info)
                # MAC 주소 포함하여 패킷 정보 출력
                st.write(f"Packet Info: {packet_info}")
                st.write(f"출발지 MAC: {packet_info['src_mac']}")
                st.write(f"목적지 MAC: {packet_info['dst_mac']}")

    def start_monitoring(self, interface="en0"):
        if not self.is_monitoring:
            self.is_monitoring = True
            st.info("Starting unified IoT security monitoring...")
            self.monitoring_thread = threading.Thread(target=self._sniff, args=(interface,))
            self.monitoring_thread.daemon = True  # 앱 종료 시 스레드 자동 종료
            self.monitoring_thread.start()
    
    def create_traffic_chart(self):
        self.visualizer.create_traffic_chart()

    def create_device_summary(self):
        return self.visualizer.create_device_summary()

    def stop_monitoring(self):
        if self.is_monitoring:
            self.is_monitoring = False
            st.info("Stopping IoT security monitoring...")
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=2)  # 최대 2초 대기
                self.monitoring_thread = None  # 스레드 초기화
            st.success("Monitoring stopped successfully.")

    def _sniff(self, interface):
        sniff(iface=interface, prn=self.process_packet, store=0, stop_filter=lambda _: not self.is_monitoring)

    def clear_collected_data(self):
        self.visualizer.clear_data()
        st.success("Collected data has been cleared.")

    def create_device_summary(self):
        summary = {}
        for ip, name in self.iot_devices.items():
            summary[name] = {
                "IP": ip,
                "Status": "Active",
                "Last Seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        return summary

# 세션 상태 초기화
if 'monitor' not in st.session_state:
    config = load_config()
    st.session_state['monitor'] = UnifiedMonitor(
        config.get("IOT_DEVICES", {}),
        config.get("NORMAL_IP_RANGES", []),
        config.get("NORMAL_PORTS", []),
        config.get("MAX_PACKET_SIZE", 1500)
    )

if 'login' not in st.session_state:
    st.session_state['login'] = ''

if 'show_dashboard' not in st.session_state:
    st.session_state['show_dashboard'] = False

# 커스텀 CSS 스타일
st.markdown("""
<style>
.stTextInput > div > div > input {
    background-color: #f0f2f6;
}
.stButton > button {
    width: 100%;
    background-color: #4CAF50;
    color: white;
    height: 3em;
}
.stButton > button:hover {
    background-color: #45a049;
}
.login-container {
    background-color: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}
.centered {
    display: flex;
    justify-content: center;
    align-items: center;
    flex-direction: column;
    height: 100%;
}
.title {
    text-align: center;
    margin-bottom: 20px;
}
</style>
""", unsafe_allow_html=True)

# 사이드바 설정
if st.session_state.login != '':
    if st.sidebar.button('IoT 모니터링 대시보드'):
        st.session_state.show_dashboard = True
        st.rerun()
    if st.sidebar.button('로그오프'):
        st.session_state.login = ''
        st.session_state.show_dashboard = False
        st.rerun()

# 메인 화면 레이아웃
st.markdown('<div class="centered">', unsafe_allow_html=True)
st.markdown('<h1 class="title">IoT Monitoring System</h1>', unsafe_allow_html=True)

col1, col2 = st.columns(2)
with col1:
    st.image('./images/Designer.jpeg', use_container_width=True)
with col2:
    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    if st.session_state.get('login', '') == '':
        tab1, tab2 = st.tabs(['Login', 'Register'])
        with tab1:
            with st.form('loginform'):
                userid = st.text_input('ID', key='luserid')
                passwd = st.text_input('Password', type='password', key='lpasswd')
                if st.form_submit_button('Login'):
                    if all([userid, passwd]):
                        df = pd.read_csv('./users.csv', encoding='utf-8')
                        idlist = list(df.iloc[:, 1])
                        passwdlist = list(df.iloc[:, 2])
                        if userid in idlist and passwd in passwdlist:
                            st.session_state['login'] = userid
                            st.success(f'{userid}님의 로그인이 성공했습니다.')
                            st.rerun()
                        else:
                            st.error('🚫등록된 사용자가 아닙니다.')
                    else:
                        st.error('🚫모든 정보를 입력해야 합니다.')
        with tab2:
            with st.form('register'):
                name = st.text_input('Name', key='name')
                userid = st.text_input('ID', key='ruserid')
                passwd = st.text_input('Password', type='password', key='rpasswd')
                if st.form_submit_button('Register'):
                    if all([name, userid, passwd]):
                        with open('./users.csv', 'a') as f:
                            inputtxt = f'{name},{userid},{passwd}\n'
                            f.write(inputtxt)
                        st.success('등록 성공')
                    else:
                        st.error('🚫모든 정보를 입력해야 합니다.🚫')
    else:
        # 현재 시간 가져오기
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 호스트 IP 주소 가져오기
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        # HTML을 사용하여 고급스럽게 스타일링된 메시지 생성
        welcome_message = f"""
        <div style='display: flex; align-items: center; background-color: #e6f7e6; color: #155724; padding: 20px; border-radius: 10px; border: 1px solid #c3e6cb; height: 200px;'>
            <div style='flex: 1;'>
                <h4 style='margin-bottom: 10px;'>{st.session_state['login']}님 환영합니다! 🔓</h2>
                <p style='font-size: 16px; margin-bottom: 20px;'>모니터링 시스템 접속이 확인되었습니다.<br>지금부터 모든 활동이 기록됩니다.</p>
                <hr style='border-top: 1px solid #c3e6cb; margin-bottom: 15px;'>
                <p style='font-size: 14px;'><strong>접속 IP:</strong> {host_ip} | <strong>접속 시간:</strong> {current_time}</p>
            </div>
        """
        # HTML을 사용하여 메시지 표시
        st.markdown(welcome_message, unsafe_allow_html=True)

# IoT 모니터링 대시보드
if st.session_state.show_dashboard and st.session_state.login != '':
    st.title("IoT Monitoring Dashboard")

    # IoT 디바이스 관리
    st.header("IoT Device Management")
    new_device_ip = st.text_input("Enter new device IP")
    new_device_name = st.text_input("Enter new device name")
    new_device_mac = st.text_input("Enter new device MAC address")  # 새로운 MAC 주소 입력

    if st.button("Add Device"):
        try:
            ipaddress.ip_address(new_device_ip)

            st.session_state.monitor.iot_devices[new_device_ip] = {
                "name": new_device_name,
                "mac": new_device_mac
                }
            st.success(f"Device {new_device_name} ({new_device_ip}, {new_device_mac}) added successfully!")
            save_config({
                "IOT_DEVICES": st.session_state.monitor.iot_devices,
                "NORMAL_IP_RANGES": st.session_state.monitor.normal_ip_ranges,
                "NORMAL_PORTS": st.session_state.monitor.normal_ports,
                "MAX_PACKET_SIZE": st.session_state.monitor.max_packet_size
            })
        except ValueError:
            st.error("Invalid IP address")

    # 현재 등록된 IoT 디바이스 목록
    st.subheader("Registered IoT Devices")
    device_df = pd.DataFrame(list(st.session_state.monitor.iot_devices.items()), columns=['IP Address', 'Device Name'])
    st.table(device_df)

    # 네트워크 설정
    st.header("Network Settings")
    new_ip_range = st.text_input("Enter new normal IP range (e.g., 192.168.1.0/24)")
    if st.button("Add IP Range"):
        try:
            ipaddress.ip_network(new_ip_range)
            st.session_state.monitor.normal_ip_ranges.append(new_ip_range)
            st.success(f"IP range {new_ip_range} added successfully!")
            save_config({
                "IOT_DEVICES": st.session_state.monitor.iot_devices,
                "NORMAL_IP_RANGES": st.session_state.monitor.normal_ip_ranges,
                "NORMAL_PORTS": st.session_state.monitor.normal_ports,
                "MAX_PACKET_SIZE": st.session_state.monitor.max_packet_size
            })
        except ValueError:
            st.error("Invalid IP range")

    new_port = st.number_input("Enter new normal port", min_value=1, max_value=65535)
    if st.button("Add Port"):
        if new_port not in st.session_state.monitor.normal_ports:
            st.session_state.monitor.normal_ports.append(new_port)
            st.success(f"Port {new_port} added successfully!")
            save_config({
                "IOT_DEVICES": st.session_state.monitor.iot_devices,
                "NORMAL_IP_RANGES": st.session_state.monitor.normal_ip_ranges,
                "NORMAL_PORTS": st.session_state.monitor.normal_ports,
                "MAX_PACKET_SIZE": st.session_state.monitor.max_packet_size
            })
        else:
            st.warning(f"Port {new_port} is already in the list of normal ports.")

    # 현재 네트워크 설정 표시
    st.subheader("Current Network Settings")
    st.write(f"Normal IP Ranges: {', '.join(st.session_state.monitor.normal_ip_ranges)}")
    st.write(f"Normal Ports: {', '.join(map(str, st.session_state.monitor.normal_ports))}")
    st.write(f"Max Packet Size: {st.session_state.monitor.max_packet_size} bytes")

    # IoT 디바이스 삭제 섹션
    st.subheader("IoT 디바이스 삭제")

    device_to_delete = st.selectbox(
    "삭제할 디바이스 선택", 
    [(ip, data) for ip, data in st.session_state['monitor'].iot_devices.items()]
    )

    if st.button("디바이스 삭제"):
        if device_to_delete[0] in st.session_state['monitor'].iot_devices:
            del st.session_state['monitor'].iot_devices[device_to_delete[0]]
            st.success(f"{device_to_delete[1]} ({device_to_delete[0]}) 디바이스가 삭제되었습니다.")
            
            # 설정 업데이트 및 저장
            new_config = {
                "IOT_DEVICES": st.session_state.monitor.iot_devices,
                "NORMAL_IP_RANGES": st.session_state.monitor.normal_ip_ranges,
                "NORMAL_PORTS": st.session_state.monitor.normal_ports,
                "MAX_PACKET_SIZE": st.session_state.monitor.max_packet_size
            }
            save_config(new_config)
        else:
            st.error("선택한 디바이스를 찾을 수 없습니다.")
    
    #모니터링 시작 맟 중지
    st.subheader("모니터링 제어")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("모니터링 시작"):
            monitoring_thread = threading.Thread(target=st.session_state.monitor.start_monitoring)
            monitoring_thread.start()

            # 디바이스 요약 정보 표시
            st.header("Device Summary")
            device_summary = [
                {"IP Address": ip, "Device Name": data, "MAC Address": "Unknown"}  # data는 이미 디바이스 이름임
                for ip, data in st.session_state['monitor'].iot_devices.items()
            ]

            if device_summary:
                st.table(pd.DataFrame(device_summary))
            else:
                st.write("No device summary available.")

            # 트래픽 차트 표시
            st.header("Traffic Chart")
            st.session_state.monitor.visualizer.create_traffic_chart()
            chart_path = './static/traffic_chart.png'
            if os.path.exists(chart_path):
                st.image(chart_path)
            else:
                st.write("No traffic chart available.")

    with col2:
        if st.button("모니터링 중지"):
            st.session_state.monitor.stop_monitoring()
            st.success("모니터링이 중지되었습니다.")

# 저작권 정보
st.markdown(
    """
    <style>
        .copyright {
            font-size: 12px;
            color: #666;
            text-align: center;
            margin-top: 10px;
            padding: 10px;
            background-color: transparent;
            font-family: 'Arial', sans-serif;
            border-top: 1px solid #d1d1d1;
        }
    </style>
    <div class="copyright">
        &copy; 2024 All rights reserved. Powered by KO-Minwoo | Kongju National Universiry |<br>
        | Information and Communication Engineering & Computer Education |<br>
        | radsky336@smail.kongju.ac.kr |
    </div>
    """,
    unsafe_allow_html=True
)