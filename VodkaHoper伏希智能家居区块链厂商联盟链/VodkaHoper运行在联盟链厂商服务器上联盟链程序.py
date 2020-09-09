# /                  _*_coding:utf8_*_                 /
# /              伏希 厂商服务器端联盟链区块程序            /
# /      VodkaHoper IOT BlockChain For Manufacturer    /
# /-------------------作者：蓝一潇---------------------- /
# /--------------------------------------------------- /

# 引入需要用到的库
from time import time
import json
import hashlib
from flask import Flask, jsonify, request
import requests
import random
from Crypto.PublicKey import RSA
from Crypto import Random
import socket

# 创建区块链
class cons_blockchain:

    def __init__(self):
        self.mid = '' # 厂商的id，由伏希的服务器提供，'m'为manufacture的首字母，代指厂商。
        self.mname = 'Eathoublu Co. LTD.,' # 假定的厂商名称。
        self.blockchain = [] # 区块链的列表。
        self.cash_list = [] # 一个小时之内的代金券列表。
        self.message_list = [] # 一个小时之内的消息列表。
        self.user_list = [{'id': '123', 'ip': '127.0.0.1:5000'}]  # 假设现在有一个用户。
        self.m_trust_score_list = [] # 所有厂商的信任分列表 。
        self.mlist = [] # 所有链上在线厂商的列表。
        self.previous_hash = '' # 上一个区块的hash值。
        self.this_hash = '' # 这一个区块的hash值。
        self.rsa_public_key, self.rsa_private_key = self.get_rsa_keys() # 获得一对RSA公私钥，公钥提供给用户加密要出售的数据。
        self.block_hash_timestamp_list = [] # 同一时间全网的所有节点产生的新区块的时间戳与哈希值。
        self.block_hash_timestamp_list_index = 0 # 上述列表的指针。
        self.block_index = 0  # 区块高度指针。
        self.block = self.new_block() # 生成创世区块。
        self.trust_score = 1000 # 初始的厂商信任分1000。
        self.hash_creat_by_self = [] # 本厂商程序一段时间内产生过的所有哈希。
        # self.get_regist()

    # 获得此时的ip地址供其他节点访问。
    def get_self_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        finally:
            s.close()

        return ip + ':5000'

    # 向伏希的服务器提交注册激活请求，服务器将会返回当前链上的所有厂商的列表以及该服务器的唯一id。
    def get_regist(self):
        data = {
            'ip': self.ip,
            'time': time(),
            'mname': self.mname,

        }
        register = requests.post('http://www.vodkahoper-blockchain.com/api/regist/manufactuere', data=json.dumps(data))
        json_response = json.loads(register.text)
        self.mid = json_response['mid']
        self.mlist = json_response['mlist']

    # 随机生成一对RSA公私钥，用于提供给用户加密他们的数据。
    def get_rsa_keys(self):
        random_generator = Random.new().read
        rsa = RSA.generate(1024, random_generator)
        private_key = rsa.exportKey()
        public_key = rsa.publickey().exportKey()

        return public_key, private_key

    # 用于生成自己的新区块
    def new_block(self):
        head = {
            'time':time(),
            'block_size': '',
            'mlist': self.mlist,
            'previous_hash': self.previous_hash,
            'user_list': self.user_list,
        }

        self.block = {
            'head': head,
            'message_list': self.message_list,
            'cash_list': self.cash_list,
            'block_index': self.block_index,
        }

        self.message_list = []
        self.cash_list = []
        self.send_self_block_timestamp_and_hash(time(), hashlib.sha256(json.dumps(self.block)).hexdigest())
        self.block_index = self.block_index + 1

# 根据时间戳排序，获得时间戳最小的新区块并验证，若验证不通过，则请求时间戳排序的下一块
    def request_new_block(self):
        ip = self.get_other_block_ip(index=self.block_hash_timestamp_list_index)
        requester = requests.get('http://'+ip+'/api/provide-new-block')
        new_block_unconfirm = json.loads(requester.text['block'])
        while(not self.check_others_new_block(new_block_unconfirm)):
          try:
            self.block_hash_timestamp_list_index = self.block_hash_timestamp_list_index + 1
            self.get_other_block_ip(index=self.block_hash_timestamp_list_index)
            requester = requests.get('http://' + ip + '/api/provide-new-block')
            new_block_unconfirm = json.loads(requester.text['block'])
          except:
            print 'An Error Appeared.(100)'
          if(self.block_hash_timestamp_list_index >= len(self.block_hash_timestamp_list)):
              break
        self.add_block()
        self.re_initial()

    # 将经过共识的合法区块添加进入区块链列表上
    def add_block(self):
        self.blockchain.append(self.block)

    # 清除现有的消息列表，开始为生成下一个区块作准备
    def re_initial(self):
        self.block_hash_timestamp_list_index = 0
        self.block_hash_timestamp_list = []
        self.hash_creat_by_self = []

    # 检查其他节点生成的新区块的合法性
    def check_others_new_block(self, block):
        get_its_message_list = block['message_list']
        get_its_cash_list = block['cash_list']
        if(len(get_its_cash_list)>=len(self.cash_list) and len(get_its_message_list)>=len(self.message_list)):
            return True
        return False

    # 向交易担保者发出购买用户数据的请求
    def send_buy_data_request(self):
        data = {
            'user_id': '123', # 假定有一个智能家居用户，id为123。
            'buy_time': 1,
            'cash': {
                'id': self.mid,
                'value': 100,
            },
            'mip': self.get_self_ip(),
            'time': time(),
            'RSA_public_keys': self.rsa_public_key,
        }
        hash_value = hashlib.sha256(str(json.dumps(data))).hexdigest()
        data_and_hash = {
            'data': data,
            'hash': hash_value,
        }
        self.hash_creat_by_self.append(str(hash_value))
        self.message_list.append(data_and_hash)
        data_and_hash_encode = json.dumps(data_and_hash)

        for node in self.mlist:
          try:
              ip = node['ip']
              requester = requests.post('http://'+ip+'/api/new/message/smart-contract-1', data=data_and_hash_encode)
              print requester.text
          except:
              print 'An Error Appeared.(101)'
        return

    # 作为交易发起者，收到交易担保者转发的用户数据，向全网广播该交易完成的消息。
    def send_confirm_data_response(self):
        data = {
            'status': 2000,
            'time': time(),
            'mid': self.mid,
            'log': 'Got User Message.',
        }
        data_encode = json.dumps(data)
        self.message_list.append(data)
        for node in self.mlist:
            try:
                ip = node['ip']
                requester = requests.post('http://'+ip+'/api/new/message/new-message', data=data_encode)
                print requester.text
            except:
                print 'An Error Appeared.(102)'
        user_ip = ''
        for user in self.user_list:
            if user['id'] == '123':
                user_ip = user['ip']
                break
        try:
            requester = requests.post('http://'+user_ip+'/api/transaction-confirm')
            print requester.text
        except:
            print 'An Error Appeared.(104)'

    def send_self_block_timestamp_and_hash(self, timestamp, hash_value):

        data = {
            'block': self.block,
            'hash': hash_value,
            'timestamp': timestamp,
            'ip': self.get_self_ip(),
        }
        data_encode = json.dumps(data)
        for node in self.mlist:
            try:
              request_ip = node['ip']
              requester = requests.post('http://'+request_ip+'/api/new/block/get-timestamp-hash', data=data_encode)
              print requester.text
            except:
              print 'An Error Appeared.(103)'

    # 取出全网同一时间生成的所有区块中的第指定块。
    def get_other_block_ip(self, index=0):
        return self.block_hash_timestamp_list[index]['ip']


# 使用flask框架，开启一个网络应用程序。
app = Flask(__name__)

# 实例化上述区块链对象。
blockchain = cons_blockchain()


# 作为交易担保者的智能合约第一步提交接口：接受交易发起者购买用户数据的请求，并附上确认信息，向目标用户发送该购买请求，并生成一条区块链消息，向全网广播这条信息。
@app.route('/api/new/message/smart-contract-1', methods=['POST'])
def get_new_message_guarantee_1():
    values = request.get_data()
    values = json.loads(values)
    user_id = values['data']['user_id']

    user_ip = ''
    for user in blockchain.user_list:
        if user['id'] == user_id:
            user_ip = user['ip']
            break

    data = {
        'guarantee_id': blockchain.mid,
        'request_data': values,
    }
    data = json.dumps(data)
    data_hash_value = hashlib.sha256(data).hexdigest()
    blockchain.hash_creat_by_self.append(str(data_hash_value))
    try:
        requester = requests.post('http://' + user_ip + '/api/transaction-confirm', data=data)
        if requester.status_code == 200:
            ok_data = {
                'log': 'User has got the purchase request.',
                'hash_from_buyer': values['hash'],
                'hash_current': data_hash_value,
                'self_mid': blockchain.mid,
            }
            for node in blockchain.mlist:
                try:
                    ip = node['ip']
                    requester = requests.post('http://'+ip+'/api/new/message/new-message', data=json.dumps(ok_data))
                    print requester.text
                except:
                    print 'An Error Appeared.(102)'
            blockchain.message_list.append(ok_data)
    except:
        print 'An Error Appeared.(104)'

    return 'OK.', 200



# 作为交易担保者的智能合约第二个提交接口：接受用户返回的自己的用户数据，并在验证之后转发给交易发起者。
@app.route('/api/new/message/smart-contract-2', methods=['POST'])
def get_new_message_guarantee_2():
    values = request.get_data()
    values = json.loads(values)
    # if blockchain.mid in values['guarantee_list']:
    # 检察、确认该交易的合法性
    for guarantee in values['guarantee_list']:
        id = guarantee['id']
        if id == blockchain.mid:
            if not guarantee['hash'] in blockchain.hash_creat_by_self:
                return 'This Message Is Counterfeit.', 500
            break

    ip = values['origin_data']['data']['mip']
    data = {
        'user_data': values['self_data'],
        'user_data_hash': values['self_data_hash'],
        'time': time(),
        'mid': blockchain.mid,
        'user_id': values['user_id'],
    }
    blockchain.message_list.append(data)
    data = json.dumps(data)
    requester = requests.post('http://'+ip+'/api/get-user-data', data=data)
    print requester.text
    if requester.status_code == 200:
        return 'Buyer Has Got Your Data.', 200

# 将自己生成的新区块链的哈希和时间戳广播到整个区块链的其他节点之上。
@app.route('/api/new/block/get-timestamp-hash', methods=['POST'])
def get_new_block_by_hash_and_time():
    values = request.get_data()
    values = json.loads(values)
    blockchain.block_hash_timestamp_list.append(values)
    return "Got block's timestamp and hash. ", 200

# 若果自己生成的区块是时间戳最小的且合法的，将自己打包好的区块内容发送给其他节点。
@app.route('/api/provide-new-block', methods=['GET'])
def send_self_new_block():
    response = {
        'block': blockchain.block,
        'id': blockchain.mid,
        'time': time(),
    }
    return jsonify(response), 200

# 接受其他节点对新区块中的伪造消息的申诉（如果有的话）。
@app.route('/api/appeal/get', methods=['POST'])
def get_others_appeal():
    pass

# 确认上述申诉的正确性。
@app.route('/api/appeal/confirm', methods=['POST'])
def confirm_others_appeal():
    pass

# 获得其他节点全网广播的新消息，并计入自己的消息列表。
@app.route('/api/new/message/new-message', methods=['POST'])
def get_new_message():
    values = request.get_data()
    blockchain.message_list.append(values)
    return 'Message got.', 200

# 作为交易发起者，接收用户向自己出售的数据，并将它保存到本地。
@app.route('/api/get-user-data', methods=['POST'])
def get_user_data():
    values = request.get_data()
    values = json.loads(values)
    user_id = values['user_id']
    with open(str(user_id)+'-'+str(random.random())+'.json', 'wb') as f:
        json.dump(values, f, ensure_ascii=False)
        f.close()
    blockchain.send_confirm_data_response()
    message = {
        'mid': blockchain.mid,
        'log': 'User data has got.',
        'time': time(),
    }
    blockchain.message_list.append(message)
    for node in blockchain.mlist:
        try:
            ip = node['ip']
            requester = requests.post('http://' + ip + '/api/new/message/new-message', data=json.dumps(message))
            print requester.text
        except:
            print 'An Error Appeared.(105)'
    return 'Has got the data.OK.', 200

@app.route('/show/whole-chain', methods=['GET'])
def show_chain():
    return str(blockchain.blockchain), 200

# 主页，欢迎页面
@app.route('/', methods=['GET'])
def home():
    return '<h1>Welcome To Use VodkaHoper Consortium BlockChain IOT Smart Home For Manufacturer Server ! </h1>'

# 主程序入口
if __name__ == '__main__':

    print u'欢迎使用VodkaHoper伏希智能家居厂商联盟链！'
    # 在服务器的5000端口上运行该区块链程序
    app.run(host='0.0.0.0', port=5000)


















