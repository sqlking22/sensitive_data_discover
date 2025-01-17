#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""************************************************************
github 309892489
敏感信息检测脚本 oracle版：扫描库、schema级别的表或视图的数据，发现其中的敏感字段。
敏感类型包括姓名、电话、身份证号、电子邮箱、地址、银行账号
注：linux OS 在运行脚本前执行 ：export NLS_LANG="SIMPLIFIED CHINESE_CHINA.ZHS16GBK"

************************************************************"""
import re
import pprint
import cx_Oracle
import sys
import os

"""************************************************************
函数名称
    f_sensitive_info
描述
    对库级别扫描出所有敏感字段。
参数
    p_parms        list    参数列表
    p_parms[0]     l_dbinfo         list    数据库连接信息
    p_parms[1]     l_username       string  数据库用户(要大写)
    p_parms[2]     l_num_row        string  表记录数阈值，少于该值的小表全表提取做匹配
    p_parms[3]     l_max_row        string  从数据库中提取出来做正则匹配记录数上限值
    p_parms[4]     l_haterate       string  正回到结果中 取值范围 0-100
    p_parms[5]     l_resault        string  返回到结果的记录，用于人工确认则匹配命中率阈值，高于该值的列返该列是否为敏感字段
    p_parms[6]     l_table_check    string  对表检测的开关(YES/NO)。  YES：检测 NO ：不检测
    p_parms[7]     l_view_check     string  对视图检测的开关(YES/NO)。  YES：检测 NO ：不检测
返回值
    dict{"1_user":l_username,"2_records":[],"3_sum":0}
    其中 2_records 返回结果：
    title1      = 表名称                            
    title2      = 表规模                             
    title3      = 表字段名                       
    title4      = 敏感数据类型 
    title5      = 敏感数据命中率
    title6      = 返回到结果的记录, 用于人工确认该列是否为敏感字段
************************************************************"""
def f_sensitive_info(p_parms):
    pat_tel     = re.compile(r'((((010)|(0[2-9]\d{1,2}))[-\s]?)[1-9]\d{6,7}$)|((\+?0?86\-?)?1[3|4|5|7|8][0-9]\d{8}$)')
    pat_account = re.compile(r'(([13-79]\d{3})|(2[1-9]\d{2})|(20[3-9]\d)|(8[01-79]\d{2}))\s?\d{4}\s?\d{4}\s?\d{4}(\s?\d{3})?$')
    pat_id      = re.compile(r'[1-9]\d{5}(19|20)\d{9}[0-9Xx]$')
    pat_email   = re.compile(r'[a-zA-Z0-9_%+-]{1,}@[a-zA-Z0-9-]{1,}\.[a-zA-Z]{2,4}$')
    """三百个姓开头，排除 白全管申车文党江周南查甘武成华安岳任公常，2或3个汉字，可能以数字结尾"""
    pat_name    = re.compile(r'[\u738b\u674e\u5f20\u5218\u9648\u6768\u9ec4\u8d75\u5434\u5f90\u5b59\u6731\u9a6c\u80e1\u90ed\u6797\u4f55\u9ad8\u6881\u90d1\u7f57\u5b8b\u8c22\u5510\u97e9\u66f9\u8bb8\u9093\u8427\u51af\u66fe\u7a0b\u8521\u5f6d\u6f58\u8881\u4e8e\u8463\u4f59\u82cf\u53f6\u5415\u9b4f\u848b\u7530\u675c\u4e01\u6c88\u59dc\u8303\u5085\u949f\u5362\u6c6a\u6234\u5d14\u9646\u5ed6\u59da\u65b9\u91d1\u90b1\u4e18\u590f\u8c2d\u97e6\u8d3e\u90b9\u77f3\u718a\u5b5f\u79e6\u960e\u859b\u4faf\u96f7\u9f99\u6bb5\u90dd\u5b54\u90b5\u53f2\u6bdb\u4e07\u987e\u8d56\u5eb7\u8d3a\u4e25\u5c39\u94b1\u65bd\u725b\u6d2a\u9f9a\u6c64\u9676\u9ece\u6e29\u83ab\u6613\u6a0a\u4e54\u6bb7\u989c\u5e84\u7ae0\u9c81\u502a\u5e9e\u90a2\u4fde\u7fdf\u84dd\u8042\u9f50\u5411\u845b\u67f4\u4f0d\u8983\u9a86\u5173\u7126\u67f3\u6b27\u795d\u7eaa\u5c1a\u6bd5\u803f\u82a6\u5de6\u5b63\u7b26\u8f9b\u82d7\u8a79\u66f2\u6b27\u9633\u9773\u7941\u8def\u6d82\u5170\u88f4\u6885\u7ae5\u7fc1\u970d\u6e38\u962e\u5c24\u8212\u67ef\u725f\u6ed5\u8c37\u535c\u9976\u5b81\u51cc\u76db\u5355\u5189\u9c8d\u5305\u5c48\u623f\u55bb\u89e3\u84b2\u536b\u7b80\u65f6\u8fde\u9879\u95f5\u90ac\u5409\u9633\u53f8\u8d39\u8499\u5e2d\u664f\u968b\u53e4\u5f3a\u7a46\u59ec\u5bab\u666f\u7c73\u9ea6\u8c08\u67cf\u77bf\u827e\u6c99\u9122\u6842\u7aa6\u90c1\u7f2a\u7545\u5de9\u5353\u891a\u683e\u621a\u5a04\u7504\u90ce\u6c60\u4e1b\u8fb9\u5c91\u519c\u82df\u8fdf\u4fdd\u5546\u81e7\u4f58\u535e\u865e\u5201\u51b7\u5e94\u5321\u6817\u4ec7\u7ec3\u695a\u63ed\u5e08\u5b98\u4f5f\u5c01\u71d5\u6851\u5deb\u6556\u539f\u690d\u909d\u4ef2\u8346\u50a8\u5b97\u697c\u5e72\u82d1\u5bc7\u76d6\u5c60\u97a0\u8363\u4e95\u4e50\u94f6\u595a\u660e\u9ebb\u96cd\u82b1\u95fb\u51bc\u6728\u90dc\u5ec9\u8863\u853a\u548c\u5180\u5360\u95e9\u5e05\u5229\u6ee1][\u4e00-\u9fa5]{1,2}\d*$')
    """包含 县镇路栋村幢街 字样"""
    pat_addr    = re.compile(r'[\u53bf\u9547\u8def\u680b\u6751\u5e62\u8857]')
    [l_dbinfo,l_username,l_num_row,l_max_row,l_haterate,l_result,l_table_check,l_view_check]=p_parms
    l_table_small='NON'
    l_table_big='NON'
    l_view='NON'
    if l_table_check=='YES':
        l_table_small='SMALL'
        l_table_big='BIG'
    if l_view_check=='YES':
        l_view='VIEW'
    l_haterate_float=float(l_haterate)/float(100)
    l_return_stru={"1_user":l_username,"2_records":[],"3_sum":0}
    records=[]
    tns=l_dbinfo[0]+':'+l_dbinfo[1]+'/'+l_dbinfo[2]
    conn=cx_Oracle.connect(l_dbinfo[3],l_dbinfo[4],tns)
    cursor = conn.cursor()
    cursor.execute("""
        select
        a.table_name tn,
        case when nvl(b.NUM_ROWS,"""+str(l_num_row)+"""+1)>"""+str(l_num_row)+""" then 'BIG' else 'SMALL' end type,
        a.column_name cn,
        nvl(b.NUM_ROWS,"""+str(l_num_row)+"""+1) r
        FROM DBA_TAB_COLS a,dba_tables b
        where a.owner=b.OWNER and a.table_name=b.TABLE_NAME and a.owner='"""+l_username+"""' 
        and a.data_type like '%CHAR%' and hidden_column='NO'
        union all
        select
        a.table_name tn,
        'VIEW' type,
        a.column_name cn,
        1 r
        FROM DBA_TAB_COLS a,dba_views b
        where a.owner=b.OWNER and a.table_name=b.view_NAME and a.owner='"""+l_username+"""' 
        and a.data_type like '%CHAR%' and hidden_column='NO'
        """)
    results = cursor.fetchall()
    for r in results:
     try:  
       if r[1]==l_table_big:
        l_sample=float(l_num_row)*float(100)/float(r[3])
        cursor.execute("""
          select trim(\""""+r[2]+"""\") from (select * from (select \""""+r[2]+"""\" from """+l_username+""".\""""+r[0]+"""\"
          sample block ("""+str(l_sample)+""") ) where trim(\""""+r[2]+"""\") is not null and trim(\""""+r[2]+"""\")<>'0')
          where rownum<="""+str(l_max_row))
       if r[1]==l_table_small:
        cursor.execute("""
           select * from (select trim(\""""+r[2]+"""\") from  """+l_username+""".\""""+r[0]+"""\" where trim(\""""+r[2]+"""\") is not null
           and trim(\""""+r[2]+"""\")<>'0')
           where rownum<="""+str(l_max_row))
       if r[1]==l_view:
        cursor.execute("""
           select trim(\""""+r[2]+"""\") from
           (select \""""+r[2]+"""\" from  """+l_username+""".\""""+r[0]+"""\"
           where rownum<="""+str(l_max_row)+""")
           where trim(\""""+r[2]+"""\") is not null
           and trim(\""""+r[2]+"""\")<>'0'""")
       data = cursor.fetchall()
     except Exception as e:
       print(e)
     l_char=0
     l_tel=0
     l_account=0
     l_id=0
     l_email=0
     l_name=0
     l_addr=0
     l_count=len(data)
     sample=''
     sample2=[]
     if data:
       for d in data:
           if pat_account.match(d[0]):
             l_account=l_account+1
           if pat_tel.match(d[0]):
             l_tel=l_tel+1
           if pat_id.match(d[0]):
             l_id=l_id+1
           if pat_email.match(d[0]):
             l_email=l_email+1
           try:
             if pat_name.match(d[0].decode('gbk')):
                 l_name=l_name+1
           except Exception:
             if pat_name.match(d[0]):
                 l_name=l_name+1
           try:
             if pat_addr.search(d[0].decode('gbk')):
                 l_addr=l_addr+1
           except Exception:
             if pat_addr.search(d[0]):
                 l_addr=l_addr+1

       sample1=data[0:l_result]
       for d in sample1:
           sample2.append(d[0])
       sample='\n'.join(sample2)

       if l_char==0:
        if (float(l_account)/float(l_count))>l_haterate_float:
         records.append(r+('ACCOUNT',round((float(l_account)/float(l_count)),2),sample))
        if (float(l_tel)/float(l_count))>l_haterate_float:
         records.append(r+('TEL',round((float(l_tel)/float(l_count)),2),sample))
        if (float(l_id)/float(l_count))>l_haterate_float:
         records.append(r+('ID',round((float(l_id)/float(l_count)),2),sample))
        if (float(l_email)/float(l_count))>l_haterate_float:
         records.append(r+('EMAIL',round((float(l_email)/float(l_count)),2),sample))
        if (float(l_name)/float(l_count))>l_haterate_float:
         records.append(r+('NAME',round((float(l_name)/float(l_count)),2),sample))
        if (float(l_addr)/float(l_count))>l_haterate_float:
         records.append(r+('ADDRESS',round((float(l_addr)/float(l_count)),2),sample))
    l_return_stru["2_records"]=records
    l_return_stru["3_sum"]=len(records)
    cursor.close()
    conn.close()   
    return l_return_stru

"""************************************************************
函数名称
    f_result_insert_db
描述
    将f_sensitive_info返回的结果中的2_records插入数据库对应用户的指定表中。
参数
    p_parms        list    参数列表
    p_parms[0]     l_dbinfo         list    数据库连接信息
    p_parms[1]     l_username       string  数据库用户(要大写)
    p_parms[2]     l_result         string  f_sensitive_info的返回结果中的2_records
    p_parms[3]     l_table          string  插入的表名
    p_parms[4]     l_drop           string  插入数据前是否删除表，YES：删除 NO ：不删除
    p_parms[5]     l_des            string  对插入的表的描述
返回值
    插入是否成功，成功返回YES
************************************************************"""
def f_result_insert_db(p_parms):
    [l_dbinfo,l_username,l_result,l_table,l_drop,l_des]=p_parms
    l_count=0
    l_total=len(l_result)
    if l_total>0:
        conn = cx_Oracle.connect(l_dbinfo[3],l_dbinfo[4],l_dbinfo[0]+':'+l_dbinfo[1]+'/'+l_dbinfo[2])
        cursor = conn.cursor()
        try:
            if l_drop=='YES':
                cursor.execute("""drop table """+l_username+""".\""""+l_table+"""\"
                purge storage""")
            cursor.execute("""
            create table """+l_username+""".\""""+l_table+"""\" (
            TABLE_NAME       VARCHAR2(100),
            TYPE              VARCHAR2(20),
            COLUMN_NAME     VARCHAR2(100),
            R                      NUMBER,
            SENSITIVE_TYPE   VARCHAR2(20),
            HIT_PERCENT      NUMBER,
            SAMPLE             CLOB
            ) pctfree 10 pctused 40
            storage
            (
            initial 8K
            next 8K
            minextents 1
            maxextents 249
            );
            comment on table """+l_username+""".\""""+l_table+"""\"
            is '"""+l_des+"""';""")
            conn.commit()
        except Exception as e:
            print(e)
            conn.rollback()
        cursor.close()
        conn.close()
    l_total=len(l_result)
    if l_total>0:
        conn = cx_Oracle.connect(l_dbinfo[3],l_dbinfo[4],l_dbinfo[0]+':'+l_dbinfo[1]+'/'+l_dbinfo[2])
        cursor = conn.cursor()
        for r in l_result:
            try:
                cursor.execute("""
                insert into """+l_username+""".\""""+l_table+"""\" values ('"""+r[0]+"""','"""+r[1]+"""','"""+r[2]+"""',"""+str(r[3])+""",'"""+r[4]+"""',"""+str(r[5])+""",:sample)""",
                {'sample':r[6]})
                l_count=l_count+1
            except Exception as e:
                print(e)
                conn.rollback()
        conn.commit()
        cursor.close()
        conn.close()
    if l_count==l_total:
        return 'YES'
    else:
        return 'NO'

"""************************************************************
函数名称
    f_tables_of_user
描述
    获取数据库中指定用户的所有表名和视图名称。
参数
    p_parms        list    参数列表
    p_parms[0]     l_dbinfo         list    数据库连接信息
    p_parms[1]     l_username       string  数据库用户(要大写)
    p_parms[2]     l_num_row        string  表记录数阈值，少于该值的小表全表提取做匹配
    p_parms[3]     l_max_row        string  从数据库中提取出来做正则匹配记录数上限值
    p_parms[4]     l_haterate       string  正回到结果中 取值范围 0-100
    p_parms[5]     l_resault        string  返回到结果的记录，用于人工确认则匹配命中率阈值，高于该值的列返该列是否为敏感字段
    p_parms[6]     l_table_check    string  对表检测的开关(YES/NO)。  YES：检测 NO ：不检测
    p_parms[7]     l_view_check     string  对视图检测的开关(YES/NO)。  YES：检测 NO ：不检测
返回值
    字典，包含两个键值对:
    "Tables": 包含所有表名的列表
    "Views": 包含所有视图名的列表
************************************************************"""
def f_tables_of_user(p_parms):
    [l_dbinfo,l_username,l_num_row,l_max_row,l_haterate,l_resault,l_table_check,l_view_check]=p_parms
    l_table_small='NON'
    l_table_big='NON'
    l_view='NON'
    if l_table_check=='YES':
        l_table_small='SMALL'
        l_table_big='BIG'
    if l_view_check=='YES':
        l_view='VIEW'
    tables=[]
    views=[]
    tns=l_dbinfo[0]+':'+l_dbinfo[1]+'/'+l_dbinfo[2]
    conn=cx_Oracle.connect(l_dbinfo[3],l_dbinfo[4],tns)
    cursor = conn.cursor()
    cursor.execute("""
    select
    table_name tn,
    case when nvl(NUM_ROWS,"""+str(l_num_row)+"""+1)>"""+str(l_num_row)+""" then 'BIG' else 'SMALL' end type
    FROM dba_tables where owner='"""+l_username+"""'""")
    results = cursor.fetchall()
    for r in results:
        if r[1]==l_table_small:
            tables.append(r[0])
        if r[1]==l_table_big:
            tables.append(r[0])
    cursor.execute("""
    select
    view_name vn
    FROM dba_views where owner='"""+l_username+"""'""")
    results = cursor.fetchall()
    for r in results:
        views.append(r[0])
    conn.close()
    return {"Tables": tables, "Views": views}

if __name__ == "__main__":
    dbinfo = ["localhost", "1521", "ORCL", "your_username", "your_password"]
    username = "your_username"
    num_row = "100"
    max_row = "10000"
    haterate = "20"
    resault = "100"
    table_check = "YES"
    view_check = "YES"
    result = f_tables_of_user([dbinfo, username, num_row, max_row, haterate, resault, table_check, view_check])
    print("Tables:")
    pprint.pprint(result["Tables"])
    print("Views:")
    pprint.pprint(result["Views"])
