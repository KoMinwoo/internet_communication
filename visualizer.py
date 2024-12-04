import os
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

class Visualizer:
    def __init__(self, iot_devices=None):
        self.data = []  # 패킷 정보를 저장할 빈 리스트
        self.iot_devices = iot_devices or {}  # IoT 디바이스 정보를 저장할 딕셔너리

    def set_iot_devices(self, iot_devices):
        self.iot_devices = iot_devices  # 외부에서 IoT 디바이스 정보를 업데이트

    def add_data(self, packet_info):
        if packet_info and 'src_ip' in packet_info:
            self.data.append(packet_info)

    def create_traffic_chart(self):
        if not self.data:
            print("No data to display.")
            return

        df = pd.DataFrame(self.data)
        if df.empty:
            print("DataFrame is empty.")
            return

        # 중복된 src_ip를 제거하고, 첫 번째로 등장한 것만 사용합니다.
        df_cleaned = df.drop_duplicates(subset=['src_ip'])

        # IP 주소를 범주형 데이터로 변환하여 시각적으로 깔끔하게 표시
        df_cleaned['src_ip'] = pd.Categorical(df_cleaned['src_ip'])
        df_cleaned['src_ip'] = df_cleaned['src_ip'].cat.codes

        plt.figure(figsize=(12, 6))
        sns.lineplot(data=df_cleaned, x='src_ip', y='size', hue='is_abnormal', marker='o')
        plt.title('IoT Traffic Analysis')
        plt.xlabel('Source IP')
        plt.ylabel('Packet Size (bytes)')
        
        plt.figure(figsize=(12, 6))
        sns.lineplot(data=df, x='src_ip', y='size', hue='is_abnormal', marker='o')
        plt.title('IoT Traffic Analysis')
        plt.xlabel('Source IP')
        plt.ylabel('Packet Size (bytes)')
        plt.xticks(rotation=45)
        plt.tight_layout()

        static_folder = os.path.join(os.getcwd(), 'static')
        if not os.path.exists(static_folder):
            os.makedirs(static_folder)

        plt.savefig(os.path.join(static_folder, 'traffic_chart.png'))
        print("Chart saved to static/traffic_chart.png")
        plt.close()

    def create_device_summary(self):
        df = pd.DataFrame(self.data)
        if not df.empty and 'src_ip' in df.columns:
            device_summary = df.groupby('src_ip').agg({
                'size': 'sum',
                'is_abnormal': 'sum'
            }).reset_index()
            device_summary['device_name'] = device_summary['src_ip'].map(self.iot_devices).fillna('Unknown')
            return device_summary.to_dict('records')
        else:
            return []

    def clear_data(self):
        self.data = []
        print("All collected data has been cleared.")