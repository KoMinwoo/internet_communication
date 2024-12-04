#config.json 파일에서 설정을 로드하고 업데이트하는 기능을 담당합니다. 사용자가 IoT 장치 정보를 입력하면 이를 config.json에 반영합니다.
import streamlit as st
import pandas as pd
from config_manager import load_config, update_iot_devices

# config.json 파일에서 설정 정보를 읽어와 config 변수에 저장
config = load_config()

# 입력 필드 생성(사용자가 입력한 IoT 장치의 IP 주소와 이름을 저장하는 공간.)
device_ip = st.text_input("Enter Device IP Address")
device_name = st.text_input("Enter Device Name")

# 기존 IOT_DEVICES에서 가져온 데이터
iot_devices = config.get("IOT_DEVICES", {})

# 입력값을 기존 iot_devices에 추가
if device_ip and device_name:
    iot_devices[device_ip] = device_name
    # 업데이트된 값으로 config.json을 업데이트
    update_iot_devices(iot_devices)

# 화면에 출력
st.write("Current IoT Devices:")
st.write(iot_devices)

# 예시로 device_summary 데이터를 만들어 IP와 장치명을 매핑
device_summary = pd.DataFrame({
    'src_ip': ['10.2.3.4', '192.168.1.5', '192.168.1.6']  # IP 주소 추가
})

# src_ip를 iot_devices 딕셔너리로 매핑하여 device_name 컬럼을 생성
device_summary['device_name'] = device_summary['src_ip'].map(iot_devices).fillna('Unknown')

# 결과 출력
st.write(device_summary)