import socket
from SQL import SQL
import psutil
import time

sql2 = SQL('systeminfo')
if sql2.table_existence_handler():
    sql2.table_reset()
sql2.write({'host':'', 'ip':'', 'internet':2, 'cpu':0.0, 'memory':0.0})

def internet_connectivity():
    try:
        socket.create_connection(('8.8.8.8', 53))
        return 1
    except:
        return 0

def memory_and_cpu_usage():
    cpu_usage = psutil.cpu_percent(interval=1)*10
    memory_usage = psutil.virtual_memory().percent
    return (cpu_usage, memory_usage)

def run():
        host = socket.gethostname()
        ip = socket.gethostbyname(host)

        internet = internet_connectivity()
        cpu, memory = memory_and_cpu_usage()

        data = {'host':host, 'ip':ip, 'internet':internet, 'cpu':cpu, 'memory':memory}

        sql2.update_systeminfo(data)

while True:
     run()
     time.sleep(3)