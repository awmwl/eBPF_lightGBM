# # #!/usr/bin/env python3
# # # -*- coding: utf-8 -*-

# # import pandas as pd
# # import joblib
# # from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# # # -------------------------------
# # # 配置
# # # -------------------------------
# # DATA_FILE = "merged_cleaned.csv"          # 原始数据 CSV 文件路径
# # MODEL_FILE = "lgb_sklearn_model.pkl"     # 已训练的模型文件

# # # eBPF 兼容特征
# # ebpf_compatible_features = [
# #     'Destination_Port',
# #     'Fwd_Packet_Length_Max',
# #     'Total_Length_of_Fwd_Packets',
# #     'Fwd_Packet_Length_Min',
# #     'Fwd_Header_Length',
# #     'Fwd_IAT_Min'
# # ]

# # # -------------------------------
# # # 1. 读取数据
# # # -------------------------------
# # df = pd.read_csv(DATA_FILE)
# # df.columns = df.columns.str.strip().str.replace(' ', '_')  # 空格改下划线

# # # 检查缺失列
# # missing_cols = [col for col in ebpf_compatible_features if col not in df.columns]
# # if missing_cols:
# #     print(f"⚠️ 以下特征列在数据中不存在，将无法预测: {missing_cols}")
# #     ebpf_compatible_features = [col for col in ebpf_compatible_features if col in df.columns]

# # # -------------------------------
# # # 2. 标签处理（二分类）
# # # -------------------------------
# # if 'Label' not in df.columns:
# #     raise ValueError("原始数据中必须包含 'Label' 列")
# # df['BinaryLabel'] = df['Label'].apply(lambda x: 0 if x.upper() == 'BENIGN' else 1)
# # y_true = df['BinaryLabel']

# # # -------------------------------
# # # 3. 提取特征
# # # -------------------------------
# # X = df[ebpf_compatible_features].copy()

# # # -------------------------------
# # # 4. 加载模型
# # # -------------------------------
# # model = joblib.load(MODEL_FILE)

# # # -------------------------------
# # # 5. 预测
# # # -------------------------------
# # y_pred = model.predict(X)
# # y_prob = model.predict_proba(X)[:, 1]  # 正样本概率

# # # -------------------------------
# # # 6. 输出评估指标
# # # -------------------------------
# # acc = accuracy_score(y_true, y_pred)
# # prec = precision_score(y_true, y_pred)
# # rec = recall_score(y_true, y_pred)
# # f1 = f1_score(y_true, y_pred)
# # auc = roc_auc_score(y_true, y_prob)

# # print("\n📊 模型预测评估结果:")
# # print(f"Accuracy : {acc:.4f}")
# # print(f"Precision: {prec:.4f}")
# # print(f"Recall   : {rec:.4f}")
# # print(f"F1 Score : {f1:.4f}")
# # print(f"AUC      : {auc:.4f}")

# # # -------------------------------
# # # 7. 输出前 10 条预测结果
# # # -------------------------------
# # result_df = df[ebpf_compatible_features].copy()
# # result_df['Label'] = y_true
# # result_df['Predicted'] = y_pred
# # result_df['Prob_Positive'] = y_prob
# # print("\n前 10 条预测示例:")
# # print(result_df.head(10))


# import pandas as pd
# import joblib
# import time
# import numpy as np

# # -------------------------------
# # 配置
# # -------------------------------
# MODEL_FILE = "lgb_sklearn_model.pkl"

# # eBPF特征顺序
# ebpf_compatible_features = [
#     'Destination_Port',
#     'Fwd_Packet_Length_Max',
#     'Total_Length_of_Fwd_Packets',
#     'Fwd_Packet_Length_Min',
#     'Fwd_Header_Length',
#     'Fwd_IAT_Min'
# ]

# # -------------------------------
# # 1. 构造单条流特征示例
# # -------------------------------
# flow_feature = {
#     'Destination_Port': 20756,
#     'Fwd_Packet_Length_Max': 1480,
#     'Total_Length_of_Fwd_Packets': 13489,
#     'Fwd_Packet_Length_Min': 32,
#     'Fwd_Header_Length': 3048,
#     'Fwd_IAT_Min': 238
# }

# X_row = pd.DataFrame([flow_feature], columns=ebpf_compatible_features)

# # -------------------------------
# # 2. 加载模型
# # -------------------------------
# model = joblib.load(MODEL_FILE)

# # -------------------------------
# # 3. 测量预测耗时
# # -------------------------------
# start_ns = time.perf_counter_ns()
# y_pred = model.predict(X_row)
# y_prob = model.predict_proba(X_row)[:, 1]
# end_ns = time.perf_counter_ns()

# elapsed_ns = end_ns - start_ns
# print(f"单条流预测耗时: {elapsed_ns} ns (~{elapsed_ns/1e6:.3f} ms)")

# # -------------------------------
# # 4. 输出预测结果
# # -------------------------------
# print(f"Predicted label: {y_pred[0]}")
# print(f"Predicted probability: {y_prob[0]:.6f}")


import pandas as pd
import joblib
import time

# -------------------------------
# 配置
# -------------------------------
model_files = {
    'LightGBM': 'lgb_sklearn_model.pkl',
    'DecisionTree': 'tmp_DT.pkl',
    'XGBoost': 'tmp_XGBoost.pkl'
}

ebpf_compatible_features = [
    'Destination_Port',
    'Fwd_Packet_Length_Max',
    'Total_Length_of_Fwd_Packets',
    'Fwd_Packet_Length_Min',
    'Fwd_Header_Length',
    'Fwd_IAT_Min'
]

# 单条流特征示例
flow_feature = {
    'Destination_Port': 20756,
    'Fwd_Packet_Length_Max': 148780,
    'Total_Length_of_Fwd_Packets': 1349,
    'Fwd_Packet_Length_Min': 32,
    'Fwd_Header_Length': 3048789,
    'Fwd_IAT_Min': 238
}

X_row = pd.DataFrame([flow_feature], columns=ebpf_compatible_features)

# -------------------------------
# 对比每个模型单条流预测耗时
# -------------------------------
results = {}

for model_name, model_file in model_files.items():
    # 加载模型
    model = joblib.load(model_file)
    
    # 计时预测
    start_ns = time.perf_counter_ns()
    y_pred = model.predict(X_row)
    y_prob = model.predict_proba(X_row)[:, 1] if hasattr(model, 'predict_proba') else None
    end_ns = time.perf_counter_ns()
    
    elapsed_ns = end_ns - start_ns
    results[model_name] = elapsed_ns
    
    print(f"Model: {model_name}")
    print(f"  Predicted label      : {y_pred[0]}")
    if y_prob is not None:
        print(f"  Predicted probability: {y_prob[0]:.6f}")
    print(f"  Prediction time      : {elapsed_ns} ns (~{elapsed_ns/1e6:.3f} ms)\n")

# -------------------------------
# 总结对比
# -------------------------------
print("📊 三模型单条流预测耗时对比 (ns):")
for model_name, t_ns in results.items():
    print(f"{model_name}: {t_ns} ns (~{t_ns/1e6:.3f} ms)")
