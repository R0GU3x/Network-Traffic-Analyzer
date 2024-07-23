import time

class Alert:

    def __init__(self):
        # self.packets = []
        # self.time_stamps = []
        # self.time_interval = None

        with open(r'core\blacklist.txt', 'r') as f:
            self.black_ips = [i.split()[0] for  i in f.readlines()]

    # def reset(self):
    #     self.packets = []
    #     self.time_stamps = []
    #     self.time_interval = None
    # 
    # def dos_attack(self, packet:dict):
    #     current_time = time.time()
        
    #     if len(self.time_stamps) == 0:
    #         self.time_stamps.append(current_time)
    #         self.packets.append(packet)
    #         return None
        
    #     elif len(self.time_stamps) == 1:
    #         self.time_interval = current_time - self.time_stamps[0]
    #         self.time_stamps.append(current_time)
    #         self.packets.append(packet)
    #         return None
        
    #     else:
    #         if current_time - self.time_stamps[-1] > self.time_interval:
    #             self.reset()
    #             return None
            
    #         self.time_stamps.append(current_time)
    #         self.packets.append(packet)
            
    #         if len(self.packets) == 50:
    #             self.reset()
    #             return 1
        
    #     return None

    def check(self, packet:dict) -> int:
        if packet['src_ip'] in self.black_ips or packet['dst_ip'] in self.black_ips:
            return 1
        # elif self.dos_attack(packet):
        #     return 2

        return 0

# packet_handler = Alert()

# packet1 = {'serial': 1, 'time': 1721386942648.6956, 'src_ip': '51.116.253.169', 'src_port': 443, 'dst_ip': '10.224.10.43', 'dst_port': 60005, 'proto': 'tcp', 'flag': 'PSH ACK', 'ttl': 109, 'size': 335, 'alert': 0}
# packet2 = {'serial': 2, 'time': 1721386942650.6956, 'src_ip': '51.116.253.170', 'src_port': 443, 'dst_ip': '10.224.10.44', 'dst_port': 60005, 'proto': 'tcp', 'flag': 'PSH ACK', 'ttl': 109, 'size': 335, 'alert': 0}

# print(packet_handler.dos_attack(packet1))  # Output: None
# print(packet_handler.dos_attack(packet2))  # Output: None

# for i in range(3, 101):
#     packet = {'serial': i, 'time': 1721386942650.6956 + i, 'src_ip': '51.116.253.171', 'src_port': 443, 'dst_ip': '10.224.10.45', 'dst_port': 60005, 'proto': 'tcp', 'flag': 'PSH ACK', 'ttl': 109, 'size': 335, 'alert': 0}
#     result = packet_handler.dos_attack(packet)
#     if result is not None:
#         print(result)  # Output: 1 after 100 packets
