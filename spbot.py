#!usr/bin/python

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
        ip1 = map(int, ir.split('-')[0].split('.'))
        ip2 = map(int, ir.split('-')[1].split('.'))
        dlta = ip2[0]-ip1[0], ip2[1]-ip1[1], ip2[2]-ip1[2], ip2[3]-ip1[3]
        total += dlta[1] * 255 * 255 
        total += dlta[2] * 255 
        total += dlta[3]
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
   txt = open(txtFile,'r')
   while True :
      ir = txt.readline().strip()
      if len(ir) == 0 :
         break
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
   txt.close()

def checkConn():
   while True:
      try:
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.settimeout(2)
         sock.connect(('8.8.8.8',443))         
         break  
      except: 
         pass
      finally:
         sock.close()

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
       data = 'loading({}%)  {} of {} ips\n'.format(percentage(self.checked,self.total),self.checked,self.total)
       data += 'MaxTreadlive:{}  ipFound:{}\n'.format(threading.activeCount(),self.opened)
       sys.stdout.write('\033[F'*3)
       sys.stdout.write('\033[K'*3)
       print data


   def start(self):
      ip = None
      while True:
         try:
            if ip == None:
               ip = self.iparg.next()
            bot = threading.Thread(target=self.scanner, args=(ip,))
            bot.start()
            self.checked += 1
            ip = None
         except StopIteration:
            break
         except Exception as err:
            checkConn()     #sleep and block flooding or waite if lose conn
         finally:
            self.info()

      while threading.activeCount() != 1:
         time.sleep(0.2)


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

   if ipfile or iprange:
      attack = portScan(ipFile=ipfile,ipLst=iprange,port=port,timeOut=timeout)
      attack.start()
   else:
      exit()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('exiting...')
        sys.exit(0)

