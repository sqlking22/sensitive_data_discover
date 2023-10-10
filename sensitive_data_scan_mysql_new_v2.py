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
import time

# 数据库连接配置
db_config = {
    "host": "decs.pcl.ac.cn",
    "port": 1346,
    "user": "root",
    "password": "jonHe6377..",
    "charset": 'utf8'
}

sensitive_info_regex = {
    "身份证": r'^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$',
    "电子邮箱": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b',
    "IP地址": r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    "车牌号码": r'^(([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z](([0-9]{5}[DF])|([DF]([A-HJ-NP-Z0-9])[0-9]{4})))|([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-HJ-NP-Z0-9]{4}[A-HJ-NP-Z0-9挂学警港澳使领]))$',
    "银行卡号": r'(([13-79]\d{3})|(2[1-9]\d{2})|(20[3-9]\d)|(8[01-79]\d{2}))\s?\d{4}\s?\d{4}\s?\d{4}(\s?\d{3})?$',
    "联系地址": r'(?=.*[省市区县街道村镇路号栋单元].*?[省市区县街道村镇路号栋单元].*?[省市区县街道村镇路号栋单元].*?[省市区县街道村镇路号栋单元])(?=(?:.*[\u4e00-\u9fa5]){8,}).*[\u4e00-\u9fa5]+.*',
    "电话号码": r'((((010)|(0[2-9]\d{1,2}))[-\s]?)[1-9]\d{6,7}$)|((\+?0?86\-?)?1[3|4|5|7|8][0-9]\d{8}$)'
}


def create_monitor_table(connection, db_name):
    # 创建用于记录敏感信息的表
    sensitive_info_table = f"""
    CREATE TABLE IF NOT EXISTS monitor_table_sensitive_info (
        id INT AUTO_INCREMENT PRIMARY KEY,
        check_date DATE DEFAULT (curdate()) COMMENT '检查日期',
        database_name VARCHAR(255) COMMENT '数据库名',
        table_name VARCHAR(255) COMMENT '含有敏感信息的表名',
        column_name VARCHAR(255) COMMENT '含有敏感信息的表字段名',
        sensitive_info_type VARCHAR(255) COMMENT '敏感信息类型-邮件，手机号码，地址等',
        table_record_count INT COMMENT '表记录总行数',
        scan_count INT COMMENT '扫描数量',
        sensitive_hit_count INT COMMENT '敏感命中数量',
        sensitive_data_percentage FLOAT COMMENT '敏感数据占比',
        is_delete int default 0 COMMENT '删除标识 0-未删除，1-删除',
        into_bigdata_time datetime DEFAULT CURRENT_TIMESTAMP COMMENT '数据写入数仓时间',
        update_bigdata_time datetime DEFAULT CURRENT_TIMESTAMP COMMENT '数仓数据更新时间'
    )"""
    drop_table = f"DROP TABLE IF EXISTS {db_name}.monitor_table_sensitive_info"
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(drop_table)
            cursor.execute(sensitive_info_table)
            connection.commit()

        except Exception as e:
            print(f"执行建表时出错: {e}")
        finally:
            cursor.close()


def get_connection(db_name):
    return pymysql.connect(**db_config, database=db_name)


def get_check_tables(connection, db_name, include_tables, exclude_tables):
    cursor = connection.cursor()
    cursor.execute(f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}' "
                   f"and table_name not like '%_view'")
    tables = [table[0] for table in cursor.fetchall()]

    # 根据配置筛选要查询的表
    if include_tables:
        tables_to_query = [table for table in include_tables if table in tables]
    else:
        tables_to_query = tables

    # 根据排除的表配置过滤表
    if exclude_tables:
        tables_to_query = [table for table in tables_to_query if table not in exclude_tables]

    cursor.close()
    return tables_to_query


def get_table_column(connection, db_name, table_name):
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
    column_list = get_table_column(connection, database_name, table_name)

    # 查询表的记录总行数
    cursor.execute(f"SELECT COUNT(*) FROM `{database_name}`.`{table_name}`")
    table_record_count = cursor.fetchone()[0]

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
            unique_match_type = set()
            sensitive_data_count = 0  # 记录敏感信息数量

            for data in table_col_data:
                value_str = str(data[0])
                # 逐行识别
                match_type = detect_sensitive_data(value_str)
                if match_type:
                    # 构建唯一标识
                    unique_match_type.add(match_type)
                    sensitive_data_count += 1

            if len(unique_match_type) > 0:
                insert_data = f"INSERT INTO `{database_name}`.monitor_table_sensitive_info " \
                              f"(`database_name`, `table_name`, `column_name`, `sensitive_info_type`, " \
                              f"`table_record_count`, `scan_count`, `sensitive_hit_count`, `sensitive_data_percentage`) " \
                              f"VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"

                # 计算敏感数据占比
                sensitive_data_percentage = (sensitive_data_count / len(table_col_data)) * 100 if len(
                    table_col_data) > 0 else 0

                # 插入记录到数据库
                cursor.execute(insert_data, (database_name, table_name, column_name, ", ".join(unique_match_type),
                                             table_record_count, scan_row_limit, sensitive_data_count,
                                             sensitive_data_percentage))
                connection.commit()

                print(f"Table: {table_name}, Column: {column_name}, "
                      f"Sensitive Data Count: {sensitive_data_count}, "
                      f"Sensitive Data Percentage: {sensitive_data_percentage:.2f}%")

    cursor.close()


def detect_sensitive_data(content):
    matched_strings = set()
    for pattern_type, pattern_regex in sensitive_info_regex.items():
        complied_regex = re.compile(pattern_regex, re.IGNORECASE)
        match = complied_regex.match(content)
        if match is not None:
            matched_strings.add(pattern_type)
    # 去掉最后一个逗号和空格
    result = ','.join(str(item) for item in matched_strings)
    return result


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
        conn = get_connection(database_name)
        cursor = conn.cursor()

        cursor.execute(f"""
            SELECT `{column_name}`
            FROM `{database_name}`.`{table_name}`
            WHERE TRIM(`{column_name}`) IS NOT NULL 
              AND TRIM(`{column_name}`) <> '0' 
              AND TRIM(`{column_name}`) <> ''
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
    connection = get_connection(db_name)
    create_monitor_table(connection, db_name)
    # 需要检查的表名
    # included_tables = []
    included_tables = ['hr_emp']
    # 不需要检查的表名
    # excluded_tables = []
    excluded_tables = ['dwd_order_service_fee_view', 'dwd_fa_order_product_view', 'ods_push_configuration']
    table_list = get_check_tables(connection, db_name, included_tables, excluded_tables)
    print("待检查的表数量：" + str(len(table_list)))

    for table_name in table_list:
        # 查询表的行数
        cursor = connection.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM `{db_name}`.`{table_name}`")
        table_size = cursor.fetchone()[0]

        if table_size >= 50001:
            table_type = "大表"
            scan_row_limit = 1000  # 针对大表配置最大扫描数量
        elif 5000 < table_size <= 50000:
            table_type = "中表"
            scan_row_limit = table_size  # 扫描全量数量
        else:
            table_type = "小表"
            scan_row_limit = table_size  # 扫描全量数量

        print(f"Checking {table_name} ({table_type}, 表行数: {table_size})")

        # 扫描表数据
        scan_sensitive_data(connection, db_name, table_name, scan_row_limit)
        cursor.close()

    connection.close()


if __name__ == '__main__':
    # 记录开始时间
    start_time = time.time()
    main_handle()
    # 记录结束时间
    end_time = time.time()
    # 计算执行时间
    execution_time = int(end_time - start_time)
    print(f"程序执行耗时: {execution_time} 秒")
