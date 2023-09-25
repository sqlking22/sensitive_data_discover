import os
import pandas as pd
import re
import shutil
import time
import base64

# from cryptography.fernet import Fernet  # 用于加密和解密敏感信息的库

# 定义敏感信息的正则表达式模式
email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
phone_pattern = r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'
address_pattern = r'\d+\s\w+\s\w+,\s\w+\s\d+'

# 指定包含Excel文件的文件夹路径
folder_path = './output_excel_files'

# 指定保存敏感信息的Excel文件路径
sensitive_info_excel_path = 'sensitive_info.xlsx'

# 创建一个源文件夹名加上"_backup"后缀的新文件夹
backup_folder_path = folder_path + '_backup'
os.makedirs(backup_folder_path, exist_ok=True)

# 创建一个DataFrame来保存敏感信息
sensitive_info_df = pd.DataFrame(columns=['File', 'Sheet', 'Column', 'Sensitive Info'])

# 选择是否进行敏感信息加密
encrypt_sensitive_info = input("Do you want to encrypt sensitive information? (yes/no): ").strip().lower() == 'yes'


# 遍历文件夹中的Excel文件
for root, dirs, files in os.walk(folder_path):
    for file in files:
        if file.endswith('.xlsx') or file.endswith('.xls'):
            file_path = os.path.join(root, file)
            try:
                # 创建备份文件
                backup_file_path = os.path.join(backup_folder_path, file)
                shutil.copy2(file_path, backup_file_path)

                # 使用pd.ExcelFile打开Excel文件
                xls = pd.ExcelFile(file_path)
                sensitive_columns = []

                # 遍历每个sheet页
                for sheet_name in xls.sheet_names:
                    df = xls.parse(sheet_name)

                    # 遍历所有列
                    for column in df.columns:
                        # 检查每一列是否包含敏感信息
                        sensitive_info = []

                        for index, cell in enumerate(df[column]):
                            if isinstance(cell, str):
                                if re.search(email_pattern, cell):
                                    sensitive_info.append(f'Email in row {index + 1}')
                                    sensitive_info_df = sensitive_info_df.append(
                                        {'File': file_path, 'Sheet': sheet_name, 'Column': column,
                                         'Sensitive Info': 'Email'}, ignore_index=True)
                                if re.search(phone_pattern, cell):
                                    sensitive_info.append(f'Phone in row {index + 1}')
                                    sensitive_info_df = sensitive_info_df.append(
                                        {'File': file_path, 'Sheet': sheet_name, 'Column': column,
                                         'Sensitive Info': 'Phone'}, ignore_index=True)
                                if re.search(address_pattern, cell):
                                    sensitive_info.append(f'Address in row {index + 1}')
                                    sensitive_info_df = sensitive_info_df.append(
                                        {'File': file_path, 'Sheet': sheet_name, 'Column': column,
                                         'Sensitive Info': 'Address'}, ignore_index=True)

                        if sensitive_info:
                            sensitive_columns.append(
                                {'sheet_name': sheet_name, 'column_name': column, 'sensitive_info': sensitive_info})

                # 如果有敏感信息，记录并处理源文件
                if sensitive_columns:
                    # 输出敏感信息记录
                    print(f"File: {file_path}")
                    for column_info in sensitive_columns:
                        print(
                            f"  - Sheet '{column_info['sheet_name']}', Column '{column_info['column_name']}' contains sensitive info: {', '.join(column_info['sensitive_info'])}")

                    # 处理源文件，根据选择执行不同操作
                    with pd.ExcelWriter(file_path, engine='xlsxwriter') as writer:
                        for sheet_name in xls.sheet_names:
                            df = xls.parse(sheet_name)
                            for column_info in sensitive_columns:
                                if column_info['sheet_name'] == sheet_name:
                                    if encrypt_sensitive_info:
                                        # 加密敏感信息并存储
                                        df[column_info['column_name']] = df[column_info['column_name']].apply(
                                            lambda x: base64.b64encode(x.encode()) if isinstance(x, str) else x)
                                    else:
                                        # 删除包含敏感信息的列
                                        df[column_info['column_name']] = ''
                            df.to_excel(writer, sheet_name=sheet_name, index=False)

            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")

# 去除敏感信息记录中的重复行
sensitive_info_df = sensitive_info_df.drop_duplicates()

# 将敏感信息保存到指定的Excel文件
sensitive_info_df.to_excel(sensitive_info_excel_path, index=False)

# 打印完成消息
print("Sensitive information has been recorded and processed.")

