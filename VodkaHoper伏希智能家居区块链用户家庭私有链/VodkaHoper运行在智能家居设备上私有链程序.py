# /              _*_ coding:utf-8 _*_                  /
# /            伏希 家庭智能设备端私有区块程序             /
# /       VodkaHoper IOT BlockChain For HomeMiner      /
# /-------------------作者：蓝一潇---------------------- /
# /--------------------------------------------------- /

# 引入需要用到的库
from Crypto.Cipher import AES
import base64
from time import time
import json
import hashlib
from uuid import uuid4
from flask import Flask, jsonify, request
import requests
from Crypto.PublicKey import RSA
from Crypto import Random
import socket
import os
import re
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5

# 创建区块链
class Blockchain(object):

    # 初始化
    def __init__(self):
        self.chain = [] # 创建区块链列表
        self.nodes = set() # 将家庭中智能设备节点ip放入一个集合中
        self.current_messages = [] # 一个小时之内的消息
        self.current_data = []  # 当前设备的数据 每次挖矿的时候会被打包区块
        self.cash = [] # 该私有链上的代金券
        self.info = {} # 信息列表
        self.machine_list = [] # 家庭所有智能智能设备列表
        self.block_head = {} # 生成的新的区块链的头部
        self.mlist = [] # 厂商（联盟链的每个节点）的ip地址列表
        self.ramdom_regist_code = "1234567891234567" # 一串随机的16位数字，用于新设备注册的时候进行验证（在这里我们为了简便而写为一个字符串）。
        self.machine_id = self.get_this_machineID() # 获得这台机器的uuid
        # self.code_signal = raw_input('>>>请输入该机器的初始化暗号:') # 让用户输入一段自定义的字符串用来加入或者创建一个新的智能家庭私有链。（我们为了演示方便，在下一行将其直接定义字符串）
        self.code_signal = "12345678912345678912345678912342"
        self.rsa_public_key, self.rsa_private_key = self.get_rsa_keys() # 生成本设备的RSA公私钥对
        self.set_self_information_to_set() # 将自己的信息先行记录近集合之中
        self.new_block(previous_hash=1, proof=100)
        self.machine_type = 1
        self.cipher = AES.new(self.code_signal) # 生成新的chiper对象，用于加密认证新添加的设备
        self.new_device = {}
        self.usable_ip_list = self.get_usable_ip() # json列表，列出当前所有可用的局域网ip以及type

        self.rsakey = RSA.importKey(self.rsa_public_key)  # 构造加密钥匙
        self.en_cipher = Cipher_pkcs1_v1_5.new(self.rsakey)  # 构造加密保险箱

        self.rsakey = RSA.importKey(self.rsa_private_key) # 构造解密钥匙
        self.de_cipher = Cipher_pkcs1_v1_5.new(self.rsakey) # 构造解密保险箱


        self.information = {
            'mechine_id': self.machine_id,
            'code_signal': self.code_signal,
            'rsa_pub': self.rsa_public_key,
            'rsa_prv': self.rsa_private_key,
        }

        # 将本机信息添加到机器列表中
        self.machine_list.append({
            'id': self.machine_id,
            'pubk': self.rsa_public_key,
            'type': self.machine_type,
        })

        # 机器信息本地持久化
        with open('information.config', 'wb')as f:
            json.dump(self.information, f, ensure_ascii=False)
            f.close()

        print 'VodkaHoper IOT 区块链初始化成功！当前时间：', time()

    # 作为新的设备向其他设备注册节点
    def register(self):

        regist_data_1 = {
            'id': self.machine_id,
            'time': time(),
            'pubk': self.rsa_public_key,
            'type': self.machine_type,
        }
        regist_data_encode = json.dumps(regist_data_1)
        for node in self.get_usable_ip():
          try:
            ip = node['ip']

            register_request = requests.post('http://'+ ip + ':5000/nodes/register-for-homeminer-step-1',
                                         data=regist_data_encode)
            origin = base64.b64decode(json.loads(str(register_request.text))['signal'])
            # password = "12345678912345678912345678912342"  # 由用户输入的16位或24位或32位长的初始密码字符串
            # cipher = AES.new(password)
            regist_code = self.cipher.decrypt(origin)
            #
            regist_data_2 = {
              'id': self.machine_id,
              'code': regist_code,
             }
            regist_data_2_encode = json.dumps(regist_data_2)
            ip = json.loads(str(register_request.text))['host_ip']
            is_succeed = requests.post(b'http://' + ip + b':5000/nodes/register-for-homeminer-step-2',
                                   data=regist_data_2_encode)
            print is_succeed.text
          except:
              print 'An error has appeared.'


    # 获取整个局域网之内所有的ip地址
    def get_usable_ip(self):
        # 轮询所有ip，并将属于该区块链系统的ip返回。
        # json的格式：{'ip':'','type':''}
        text = os.popen('arp -a').read()
        list = re.findall(r'\((.*?)\)', text)
        # print list
        request_data = {
            'id': self.machine_id,
        }
        request_data_encode = json.dumps(request_data)
        usable_list = []
        for ip in list:
            try:
                is_usable = requests.post('http://'+ ip + '/usable',data=request_data_encode)
                if is_usable.status_code == 200 :
                    usable_json = json.loads(str(is_usable.text))
                    usable_list.append({
                        'ip': usable_json['ip'],
                        'type': usable_json['type']
                    })
            except:
                pass

        return usable_list




    # 随机生成公私钥
    def get_rsa_keys(self):
        random_generator = Random.new().read
        rsa = RSA.generate(1024, random_generator)
        private_key = rsa.exportKey()
        #  print private_key
        public_key = rsa.publickey().exportKey()
        #  print public_key

        return public_key, private_key

    # 可以获取在局域网的ip
    def get_host_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        finally:
            s.close()

        return ip

    # 将自身的id以及公钥、ip存入列表
    def set_self_information_to_set(self):

        self.info = {
            'publickey': self.rsa_public_key,
            'id': self.machine_id,
        }
        return 0

    # 获取机器的uuid编号
    def get_this_machineID(self):
        mechine_uuid = str(uuid4()).replace('-', '')
        return mechine_uuid

    # 验证链是否可用
    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index <len(chain):
            block = chain[current_index]
            print(last_block)
            print(block)
            print('\n-------------\n')
            if block['previous_hash'] != self.hash(last_block):
                return False
            if not self.valid_proof(last_block['proof'], block['prooof']):
                return False
            last_block = block
            current_index += 1
        return True

    # 解决冲突
    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)
        for node in neighbours:
            response = requests.get('http://'+str(node)+'/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
        if new_chain:
            self.chain = new_chain
            return True
        return False

    # 新的块
    def new_block(self, proof, previous_hash=None, current_message=None):

        self.block_head = {
            'machine_list': self.machine_list,
            'this_machine': self.machine_id,
            'time': time(),
        }

        self.current_messages = current_message




        block = {
            # 'head': head_json,
            'head': self.block_head,
            'this_machine': self.info,
            'cash': self.cash,
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'messages': self.current_messages,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }

        self.current_messages = []

        self.chain.append(block)

        return block

    # 新的消息记录列表
    def new_message(self, sender, recipient, amount):
        self.current_messages.append({
            'sender':  sender,
            'recipient': recipient,
            'amount': amount,

        })

        return self.last_block['index'] + 1

    # 将区块哈希的静态方法
    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    # 返回该链上的上一个区块
    @property
    def last_block(self):

        return self.chain[-1]

    # 工作量证明
    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    # 判断工作量证明是否合格
    @staticmethod
    def valid_proof(last_proof, proof):
        guess = str(last_proof) + str(proof)
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# 创建一个flask节点
app = Flask(__name__)


# 创建一个全网唯一的uuid
node_identifier = str(uuid4()).replace('-', '')

# 实例化该区块链对象
blockchain = Blockchain()

# 执行消息里面的操作
def option_executor(op_cipher):
    random_generator = Random.new().read
    origin_op = blockchain.de_cipher.decrypt(base64.b64decode(op_cipher), random_generator)
    try:
      operator = os.popen(origin_op).read()
      print operator
    except:
        print 'Option error.'
        return 0
    return 'OK.'


# 注册第一步：新设备注册节点 new 提交需要提交id、时间戳、公钥、type 返回暗号base64
@app.route('/nodes/register-for-homeminer-step-1', methods=['POST'])
def register_nodes_1():
    values = request.get_data()
    # its_uuid = values.get('id')
    # its_time = values.get('time')
    # its_pubk = values.get('pubk')
    # print values

    values = json.loads(str(values))
    print values

    blockchain.new_device = {
        'id': values['id'],
        'time': values['time'],
        'pubk': values['pubk'],
        'type': values['type'],
    }
    response = {
        'host_ip': blockchain.get_host_ip(),
        'signal': base64.b64encode(blockchain.cipher.encrypt(blockchain.ramdom_regist_code))
    }

    return jsonify(response), 200


# 新节点注册第二步 需要提交机器id以及解密后的数字(code)
@app.route('/nodes/register-for-homeminer-step-2', methods=['POST'])
def register_nodes_2():
    values = request.get_data()
    values = json.loads(values)
    its_answer = values['code']
    its_uuid = values['id']
    if not blockchain.ramdom_regist_code == its_answer:
        print blockchain.ramdom_regist_code
        print its_answer
        return 'Wrong answer', 400
    if not blockchain.new_device['id'] == its_uuid:
        return 'Not the same id', 400
    blockchain.machine_list.append({
        'id': its_uuid,
        'pubk': blockchain.new_device['pubk'],
        'type': blockchain.new_device['type'],
    })
    blockchain.new_device = {}
    return 'Regist succeed', 200


# 解决冲突问题
@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

# 搜集设备提交的msg
@app.route('/message/new', methods=['POST'])
def get_new_message():
    values = request.get_data()
    values = json.loads(values) #
    its_data = values['data']
    its_time = values['time']
    its_id = values['id']
    its_type = values['type']
    its_op = values['op']
    blockchain.current_messages.append({
        'data': its_data,
        'time': its_time,
        'id': its_id,
        'type': its_type,
        'op': its_op,
    })
    if its_id == blockchain.machine_id:
       option_executor(values['op'])


    return 'Message has been added.', 200


# 搜集本设备产生的脱敏数据   {'data':'','time':'time','id':'','type':''}
@app.route('/data/new', methods=['POST'])
def get_new_data():
    values = request.get_data()
    values = json.loads(values)
    its_data = values['data']
    its_time = values['time']
    its_id = values['id']
    its_type = values['type']
    blockchain.current_data.append({
        'data': its_data,
        'time': its_time,
        'id': its_id,
        'type': its_type,
    })
    return 'Data has been added.', 200


# 展示整条区块链
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


# 挖矿，将数据上链
@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    blockchain.new_message(
        sender='0',
        recipient=node_identifier,
        amount=1,
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'response_massage': "New Block Forged",
        'index': block['index'],
        'messages': block['messages'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


# 其他设备通过提交id、type来进行查询该节点是否可以使用
@app.route('/usable', methods=['POST'])
def is_usable():
    values = request.get_data()
    values = json.loads(values)
    try:
       if values['id']:
           pass
    except:
       return 'Permission Denied', 401

    response = {
        'type': blockchain.machine_type,
        'ip': blockchain.get_host_ip(),
    }

    return jsonify(response), 200

# 接收厂商购买用户数据的请求
@app.route('/api/transaction-confirm', methods=["POST"])
def sell_user_data():
    values = request.get_data()
    values = json.loads(values)
    end = len(blockchain.chain)
    confirm = raw_input('>>>厂商将用价值'+values['request_data']['cash']['value']+'的代金券购买您的匿名数据（数据将全部经过脱敏），请问您是否允许？(Y/N)')
    if 'N' in confirm:
        return 'User refuse the request.', 500
    start = end - values['request_data']['data']['buy_time']
    if start <= 0:
        start = 0
    self_data = blockchain.chain[start: end]
    its_rsa_key = values['request_data']['data']['RSA_public_keys']
    rsakey = RSA.importKey(its_rsa_key)  # 构造钥匙
    cipher = Cipher_pkcs1_v1_5.new(rsakey)  # 构造保险箱
    cipher_text = base64.b64encode(cipher.encrypt(str(self_data)))  # 进行加密
    blockchain.cash.append(values['request_data']['data']['cash'])
    response_sell_data = {
        'gurantee_list': [],
        'origin_data': values['request_data'],
        'self_data': cipher_text,
        'self_data': hashlib.sha256(str(cipher_text)).hexdigest(),
        'time': time(),
    }
    response_sell_data_encode = json.dumps(response_sell_data)
    for node in blockchain.mlist:
        try:
            ip = node['ip']
            requeter = requests.post('http://'+ip+'/api/new/message/smart-contract-2', data=response_sell_data_encode)
            print requeter.text
        except:
            pass

    return jsonify(response_sell_data), 200


# 主函数入口
if __name__ == '__main__':

    print '欢迎使用VodkaHoper伏希智能家庭私有区块链程序！'
    status = raw_input('>>>键入1：开启一条新的智能家庭区块链；键入2:加入一条已有的智能家庭区块链；')
    if '1' in str(status):
     app.run(host='0.0.0.0', port=5000)

