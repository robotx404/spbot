#!/usr/bin/python

import threading
import socket
import time
import logging
import argparse
import sys



def percentage(part, whole):
  eq = 100.0 * part/whole
  return round(eq,2)


def lenRange(ir=None,txt=None):
   total = 0
   if txt:
      txt = open(txt,'r')
      while True:
        ir = txt.readline().strip()
        if len(ir) == 0:
           break
        if '-' in ir:
           ip1 = map(int, ir.split('-')[0].split('.'))
           ip2 = map(int, ir.split('-')[1].split('.'))
           dlta = ip2[0]-ip1[0], ip2[1]-ip1[1], ip2[2]-ip1[2], ip2[3]-ip1[3]
           total += dlta[1] * 255 * 255 
           total += dlta[2] * 255 
           total += dlta[3]
        else: # if singl ip
           total += 1
      txt.close()
      return total 

   elif ir:
      ip1 = map(int, ir.split('-')[0].split('.'))
      ip2 = map(int, ir.split('-')[1].split('.'))
      dlta = ip2[0]-ip1[0], ip2[1]-ip1[1], ip2[2]-ip1[2], ip2[3]-ip1[3]
      total += dlta[1] * 255 * 255 
      total += dlta[2] * 255 
      total += dlta[3]
      return total 


def ipRange(ir):
   start_ip, end_ip = ir.split('-')[0], ir.split('-')[1]
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   yield start_ip
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      yield ".".join(map(str, temp)) 


def txtRange(txtFile):
   '''support range & singl ip'''
   txt = open(txtFile,'r')
   while True :
      ir = txt.readline().strip()
      if len(ir) == 0 :
         break
      if '-' in ir:
         start_ip, end_ip = ir.split('-')[0], ir.split('-')[1]
         start = list(map(int, start_ip.split(".")))
         end = list(map(int, end_ip.split(".")))
         temp = start
         yield start_ip
         while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
               if temp[i] == 256:
                  temp[i] = 0
                  temp[i-1] += 1
            yield ".".join(map(str, temp)) 
      else: # not range 
        yield ir
   txt.close()


class ping:
   def __init__(self, dns='8.8.8.8', port=443, buff=64):
      self.stop = False
      self.time = None
      self.dns = dns
      self.port = port
      self.buff = buff
   def start(self):
      while not self.stop :
         st = time.time()
         try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.connect((self.dns,self.port))
            sock.send('0'*self.buff)
            self.time = round((time.time()-st),4)
         except socket.timeout:
            self.time='timeout'
         except Exception as err:
            self.time='no connection'
         finally:
            sock.close()
            time.sleep(3)
   def thread(self):
      t = threading.Thread(target=self.start)
      t.start()

ping = ping()

class portScan:
   def __init__(self,ipFile=None,ipLst=None,port=80,logName='log.txt',timeOut=3):
      self.log = logging.getLogger()
      logging.basicConfig(filename=logName,level=logging.DEBUG,format='')
      self.timeout = timeOut
      self.port = port
      if ipFile:
         self.total = lenRange(None,ipFile)
         self.iparg = txtRange(ipFile)
      elif ipLst:
         self.total = lenRange(ipLst)
         self.iparg = ipRange(ipLst)
      self.checked = 0
      self.opened = 0
   def scanner(self,ip):
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((ip,self.port))
        self.log.debug(ip)
        self.opened += 1
      except : 
        pass
      finally:
        sock.close()

   def info(self):
       data = '\nloading({}%)  {} of {} ips\n'.format(percentage(self.checked,self.total),self.checked,self.total)
       data += '-' * 30 +'               \n'
       data += 'MaxTreadlive:{}          \n'.format(threading.activeCount())
       data += 'ipFound:{}               \n'.format(self.opened)
       data += 'ping:{} sec              \n'.format(ping.time)
       sys.stdout.write('\033[F'*6)
       sys.stdout.write('\033[K'*6)
       print data


   def start(self):
      ip = None
      while True:
         try:
            if ip == None:
               ip = self.iparg.next()
            while ping.time  > 100 or ping.time == None:
               print 'No Connection!'
               time.sleep(4)

            time.sleep(ping.time*0.1)
            bot = threading.Thread(target=self.scanner, args=(ip,))
            bot.start()
            self.checked += 1
            ip = None
         except StopIteration:
            break
         except Exception as why:
            pass
         finally:
            self.info()
      ping.stop = True
      print 'Finishing...'
      time.sleep(5)


def args():
   parser = argparse.ArgumentParser()
   parser.add_argument('-p','--port', type=int)
   parser.add_argument('-r','--iprange', type=str)
   parser.add_argument('-f','--ipfile', type=str)
   parser.add_argument('-t','--timeout', type=int,default=3)
   return parser.parse_args()

def main():
   ipfile = args().ipfile
   iprange = args().iprange
   port = args().port
   timeout = args().timeout
   ping.thread()
   time.sleep(1)
   if ipfile or iprange:
      attack = portScan(ipFile=ipfile,ipLst=iprange,port=port,timeOut=timeout)
      attack.start()
   else:
      exit()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        ping.stop = True
        print('exiting...')
        sys.exit(0)

