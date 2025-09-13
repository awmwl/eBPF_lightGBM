import re
import pandas as pd
import joblib   # 用于加载 pkl 模型
import lightgbm as lgb

# 解析日志文件
def parse_features(log_file):
    features = []
    with open(log_file, "r") as f:
        record = {}
        for line in f:
            if "Dst Port" in line:
                record["dst_port"] = int(line.split(":")[1])
            elif "Fwd Packet Length Max" in line:
                record["fwd_pkt_len_max"] = int(line.split(":")[1])
            elif "Total Fwd Length" in line:
                record["total_fwd_len"] = int(line.split(":")[1])
            elif "Fwd Packet Length Min" in line:
                record["fwd_pkt_len_min"] = int(line.split(":")[1])
            elif "Fwd Header Length" in line:
                record["fwd_hdr_len"] = int(line.split(":")[1])
            elif "Fwd IAT Min" in line:
                record["fwd_iat_min"] = int(line.split(":")[1])
            elif line.strip() == "---":
                if record:
                    features.append(record)
                    record = {}
    return pd.DataFrame(features)

# 解析日志
df = parse_features("features.log")
print("Parsed Features:")
print(df.head())

# 加载训练好的 LightGBM 模型
model = joblib.load("lgb_model.pkl")

# 预测
y_pred = model.predict(df)
print("Prediction Results:")
print(y_pred)
