# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# ****************************************************************#
# @Time    : 2023/9/27 12:03
# @Author  : HeJun
# @File    : sensitive_data_scan_mysql.py
# @Function :
# @Use desc :
# ****************************************************************#
import re
import pymysql
import base64

# 数据库连接配置
db_config = {
    "host": "decs.pcl.ac.cn",
    "port": 1346,
    "user": "root",
    "password": "jonHe6377..",
    "database": "test",
    "charset": 'utf8'
}

# 敏感信息识别的正则表达式
sensitive_info_regex = {
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b',
    "ip_address": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    "id_card": r'[1-9]\d{5}(19|20)\d{9}[0-9Xx]$',
    "bank_account": r'(([13-79]\d{3})|(2[1-9]\d{2})|(20[3-9]\d)|(8[01-79]\d{2}))\s?\d{4}\s?\d{4}\s?\d{4}(\s?\d{3})?$',
    "chinese_address": r'[\u53bf\u9547\u8def\u680b\u6751\u5e62\u8857]',
    # "english_address": r'\b[A-Za-z0-9\s,.-]+\b',
    "telephone": r'((((010)|(0[2-9]\d{1,2}))[-\s]?)[1-9]\d{6,7}$)|((\+?0?86\-?)?1[3|4|5|7|8][0-9]\d{8}$)',
}


def create_monitor_table(connection, db_name):
    # 创建用于记录敏感信息的表
    sensitive_info_table = f"""
    CREATE TABLE IF NOT EXISTS {db_name}.monitor_table_sensitive_info (
        id INT AUTO_INCREMENT PRIMARY KEY,
        database_name VARCHAR(255),
        table_name VARCHAR(255),
        column_name VARCHAR(255),
        sensitive_info_type VARCHAR(255)
    )"""
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(sensitive_info_table)
            connection.commit()

        except Exception as e:
            print(f"执行建表时出错: {e}")
        finally:
            cursor.close()


def get_connection():
    return pymysql.connect(**db_config)


def get_check_tables(connection, db_name, include_table, exclude_table):
    # 存储表名
    tables_to_query = []
    cursor = connection.cursor()
    cursor.execute(f"SHOW TABLES in {db_name}")
    tables = cursor.fetchall()
    # 遍历表名，将符合条件的表名添加到列表中
    for (table_name,) in tables:
        if table_name in include_table and table_name not in exclude_table:
            tables_to_query.append(table_name)

    cursor.close()
    return tables_to_query


def get_table_column_and_datatype(connection, db_name, table_name):
    # 只查询字段类型是字符串的字段
    column_query = f"SELECT lower(column_name)as column_name " \
                   f" FROM INFORMATION_SCHEMA.COLUMNS WHERE lower(TABLE_SCHEMA)=lower('{db_name}')  " \
                   f" AND lower(TABLE_NAME) = lower('{table_name}') " \
                   f" AND lower(data_type) = 'varchar' " \
                   f" AND lower(column_name) not like '%id' " \
                   f"ORDER BY ORDINAL_POSITION"
    cursor = connection.cursor()
    cursor.execute(column_query)
    columns = [column[0] for column in cursor.fetchall()]
    cursor.close()
    return columns


def scan_sensitive_data(connection, database_name, table_name, scan_row_limit=10):
    cursor = connection.cursor()
    results = []
    column_list = get_table_column_and_datatype(connection, database_name, table_name)
    table_result = {
        'database_name': database_name,
        'table_name': table_name,
        'columns_with_sensitive_data': []
    }

    for column_name in column_list:
        sql = f"SELECT TRIM(`{column_name}`) FROM `{database_name}`.`{table_name}` " \
              f"WHERE TRIM(`{column_name}`) IS NOT NULL " \
              f"AND TRIM(`{column_name}`) <> '0' " \
              f"AND TRIM(`{column_name}`) <> '' " \
              f"LIMIT {scan_row_limit}"
        cursor.execute(sql)
        table_col_data = cursor.fetchall()

        if table_col_data:
            # 初始化用于不重复记录的集合
            unique_records = set()

            for data in table_col_data:
                value_str = str(data[0])
                # 一行一行识别
                matches = detect_sensitive_data(value_str)
                if matches:
                    # 构建唯一标识
                    record_identifier = (
                        "column_name:" + column_name, "sensitive_type:" + ', '.join([str(match) for match in matches]))
                    # 如果不在唯一记录集合中，插入记录并添加到唯一记录集合
                    if record_identifier not in unique_records:
                        unique_records.add(record_identifier)
                        insert_data = f"""INSERT INTO `{database_name}`.monitor_table_sensitive_info 
                                            (`database_name`, `table_name`, `column_name`, `sensitive_info_type`) VALUES 
                                            (%s,%s,%s,%s)"""

                        print(insert_data)
                        # 插入记录到数据库
                        cursor.execute(insert_data, (database_name, table_name, column_name, unique_records))
                        connection.commit()

            if len(unique_records) > 0:
                table_result['columns_with_sensitive_data'].append(unique_records)

    if table_result['columns_with_sensitive_data']:
        results.append(table_result)

    return results


def detect_sensitive_data(content):
    matched_strings = set()
    for pattern_type, pattern_regex in sensitive_info_regex.items():
        complied_regex = re.compile(pattern_regex, re.IGNORECASE)
        matches = re.findall(complied_regex, content)
        if matches:
            matched_strings.add(pattern_type)
    return matched_strings


def replace_sensitive_data_with_star(input_string):
    if len(input_string) < 3:
        return input_string

    # Calculate the number of characters to redact in the middle (half of the length)
    redact_count = len(input_string) // 2

    # Split the input string into two parts: before and after the middle
    middle_start = len(input_string) // 2 - redact_count // 2
    middle_end = len(input_string) // 2 + redact_count // 2

    before_middle = input_string[:middle_start]
    middle = input_string[middle_start:middle_end]
    after_middle = input_string[middle_end:]

    # Redact the middle part
    redacted_middle = "*" * len(middle)

    # Concatenate the parts back together
    redacted_string = before_middle + redacted_middle + after_middle

    return redacted_string


def encrypt_sensitive_data(database_name, table_name, column_name):
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(f"""
            SELECT `{column_name}`
            FROM `{database_name}`.`{table_name}`
            WHERE TRIM(`{column_name}`) IS NOT NULL AND TRIM(`{column_name}`) <> '0'
        """)
        data = cursor.fetchall()
        encrypted_data = []

        for d in data:
            encrypted_value = base64.b64encode(d[0].encode()).decode()
            encrypted_data.append(encrypted_value)

        cursor.close()

        cursor = conn.cursor()

        for i, encrypted_value in enumerate(encrypted_data):
            cursor.execute(f"""
                UPDATE `{database_name}`.`{table_name}`
                SET `{column_name}` = {encrypted_value}
                WHERE `{column_name}` = {data[i][0]}
            """)
        conn.commit()
        cursor.close()
        conn.close()
        print("Encryption complete.")

    except Exception as e:
        print(e)
    finally:
        cursor.close()
        conn.close()


def main_handle():
    db_name = "pase_corehr"
    connection = get_connection()
    create_monitor_table(connection, db_name)
    # 需要检查的表名
    included_tables = ['hr_emp']
    # 不需要检查的表名
    excluded_tables = []
    table_list = get_check_tables(connection, db_name, included_tables, excluded_tables)
    for table_name in table_list:
        mask_data = scan_sensitive_data(connection, db_name, table_name)
        print(mask_data)


if __name__ == '__main__':
    main_handle()
