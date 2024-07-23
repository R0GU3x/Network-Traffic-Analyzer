import mysql.connector as sql

class SQL:

    def __init__(self, table:str):
        self.database, self.table = 'grafanadb', table
        self.con = sql.connect(host='localhost', username='root', password='root', database=self.database)
        self.cur = self.con.cursor()

    def table_existence_handler(self):
        self.cur.execute(f'SHOW TABLES LIKE "{self.table}"')
        if not self.cur.fetchone():
            if self.table == 'packets':
                query = f"CREATE TABLE {self.table} (serial MEDIUMINT, time DOUBLE, src_ip TEXT, src_port MEDIUMINT, dst_ip TEXT, dst_port MEDIUMINT, proto TINYTEXT, flag TINYTEXT, ttl MEDIUMINT,size MEDIUMINT, alert TINYINT, attack TEXT);"
            elif self.table == 'systeminfo':
                query = f'CREATE TABLE {self.table} (host TEXT, ip TEXT, internet TINYINT, cpu DOUBLE, memory DOUBLE)'
            elif self.table == 'geo':
                query = f'CREATE TABLE {self.table} (ip TEXT, org TEXT, latitude DOUBLE, longitude DOUBLE)'
            self.cur.execute(query)
            self.con.commit()
            return False
        return True

    def table_reset(self):
        query = f'DELETE FROM {self.table}'
        self.cur.execute(query)
        self.con.commit()

    def write(self, data:dict):
        if self.table == 'packets':
            query = f'INSERT INTO {self.table} VALUES ({data['serial']}, {data['time']}, "{data['src_ip']}", {data['src_port']}, "{data['dst_ip']}", {data['dst_port']}, "{data['proto']}", "{data['flag']}", {data['ttl']}, {data['size']}, {data['alert']}, "safe");'
        elif self.table == 'systeminfo':
            query = f'INSERT INTO {self.table} VALUES ("{data['host']}", "{data['ip']}", {data['internet']}, {data['cpu']}, {data['memory']})'
        elif self.table == 'geo':
            query = f'INSERT INTO {self.table} VALUES ("{data['ip']}", "{data['org']}", {data['latitude']}, {data['longitude']})'
        self.cur.execute(query)
        self.con.commit()
    
    # used by ML upon finding mailicous activity
    def update_alert(self, serial:int, attack:str):
        query = f'UPDATE {self.table} SET alert=1, attack="{attack}" WHERE serial={serial}'
        self.cur.execute(query)
        self.con.commit()
    
    # used to update systeminfo table
    def update_systeminfo(self, data):
        query = f'UPDATE {self.table} SET host="{data['host']}", ip="{data['ip']}", internet={data['internet']}, cpu={data['cpu']}, memory={data['memory']}'
        self.cur.execute(query)
        self.con.commit()
