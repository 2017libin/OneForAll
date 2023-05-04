import  threading
import sys
import os
from oneforall import OneForAll
from config.log import logger
from datetime import datetime 

class  MyThread(threading.Thread):
    def  __init__( self, targets: list, outputPath: str):
        self.targets = targets
        self.outputPath = outputPath
        threading.Thread.__init__( self )
    
    def oneforall(self, domain):
        global fileLock
        
        # 1. 关闭控制台打印信息
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
        logger.remove(handler_id=None)
        
        # 2. 开始扫描子域名
        test = OneForAll(target=domain)
        test.dns = True
        test.brute = True
        test.req = True
        test.run()
        datas = test.datas
        
        # 3. 保存扫描结果
        fileLock.acquire()
        with open(self.outputPath, "a+") as f:
            tmp = set()
            f.write(f"# {domain} 子域名收集结果: \n")
            for data in datas:
                subdomain = data.get('subdomain')
                if data.get('alive'):
                    if subdomain not in tmp:
                        tmp.add(subdomain)
                        f.write(subdomain+'\n')
        fileLock.release()
        
        # 4. 打开控制台输出信息
        sys.stdout = sys.__stdout__
        sys.stdout = sys.__stderr__
    
    def  run(self):
        global targetsLock
        while self.targets:
            print(f"剩余 {len(self.targets)} 个未扫描域名")
            target = None
            targetsLock.acquire()
            if self.targets:
                target = self.targets.pop()
            targetsLock.release()
            if target:
                self.oneforall(target)
            
if  "__main__"  ==  __name__:
    targetsLock  =  threading.Lock()
    fileLock  =  threading.Lock()
    
    ThreadList  =  []
    Targets = None
    # 线程数
    ThreadNum = 16
    # 扫描的开始时间
    startTime = datetime.now()
    # 待扫描的域名
    targetsPath = "targets.txt"
    # 扫描结果的输出文件
    outputPath = "results.txt"
    try:
        # 获取扫描目标
        with open(targetsPath, "r") as fp:
            Targets = fp.read().split('\n')
        # print(Targets)
        
        # 创建多线程扫描任务
        for  i in range(ThreadNum):
            t  =  MyThread(Targets, outputPath)
            ThreadList.append(t)
        for  t in ThreadList:
            t.start()
        for  t in ThreadList:
            t.join()
    except Exception:
       pass
    finally:
        sys.stdout = sys.__stdout__
        sys.stdout = sys.__stderr__
        print(f"运行时间 {(datetime.now()-startTime).seconds} 秒")