import json
import shlex
import subprocess
import time
import multiprocessing

from sqlalchemy import and_

from web.models import SrcSubDomain, SrcVuln,SrcWeb
from web import DB
from  loguru import logger


def ReadDomain():
    '''读取主域名任务'''
    results = SrcWeb.query.filter(SrcWeb.nuclei == True).first()
    DB.session.commit()
    return results

def WriteDomain(results):
    '''修改主域名任务状态'''
    results.nuclei = False
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.info('修改主域名任务状态SQL错误:%s' % e)

def WriteDb(url,name,severity,srcdomain):
    '''写入数据库'''
    result = SrcVuln.query.filter(and_(SrcVuln.url == url,SrcVuln.vuln_name==name)).count()
    if result:
        logger.info( f'数据库已有该漏洞[{url}]')
        return None

    sql = SrcVuln(url=url,name=name,src_name=srcdomain,severity=severity)
    DB.session.add(sql)
    try:
        DB.session.commit()
    except Exception as e:
        DB.session.rollback()
        logger.info(f'漏洞[{url}]入库失败:{e}')
    logger.info("{} 找到漏洞".format(url))

def action(domain_name,target_url):
    '''子程序执行'''
    a='nuclei  -silent -severity critical,high,medium -nts -json -u {}'.format(target_url)
    args = shlex.split(a)
    logger.info(target_url)
    try:
        out_bytes = subprocess.check_output(args,encoding="utf-8")
    except subprocess.CalledProcessError as e:
        out_bytes = e.output  # Output generated before error
        logger.info("报错{}".format(out_bytes))
    results=out_bytes.split("\n")
    for result in results:
        if not result.startswith("{"):
            continue
        result=json.loads(result)
        info=result.get("info",{})
        matched=result.get("matched","")
        if info:
            severity=info.get("severity","")
            name=info.get("name","")
            logger.info("找到漏洞： {} in {}".format(name,matched))
            ret = send_to_wecom("新漏洞\r\n{} in {}".format(name,matched), "ctwwb9abadbe554a7bbd", "1000002",
                                "ctaSguBmjQc0sOnG59iWOPp-MOfw-HNegiiph6wgPVfE0");
            WriteDb(url=matched,name=name,severity=severity,srcdomain=domain_name)

import json,requests,base64
def send_to_wecom(text,wecom_cid,wecom_aid,wecom_secret,wecom_touid='@all'):
    get_token_url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={wecom_cid}&corpsecret={wecom_secret}"
    response = requests.get(get_token_url).content
    access_token = json.loads(response).get('access_token')
    if access_token and len(access_token) > 0:
        send_msg_url = f'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}'
        data = {
            "touser":wecom_touid,
            "agentid":wecom_aid,
            "msgtype":"text",
            "text":{
                "content":text
            },
            "duplicate_check_interval":600
        }
        response = requests.post(send_msg_url,data=json.dumps(data)).content
        return response
    else:
        return False

def main():
    '''主方法'''
    process_name = multiprocessing.current_process().name
    logger.info(f'nuclei扫描进程启动:{process_name}')
    while True:
        results = ReadDomain()
        if "店" in requests.title or "特卖" in results.title:
            WriteDomain(results)
            continue
        if not results:
            logger.info("30")
            time.sleep(30)  # 没有任务延迟点时间
        else:
            action(results.domain_name,results.url)
            WriteDomain(results)


if __name__ == '__main__':
    main()



