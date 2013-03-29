#!/usr/bin/python

##  Coded by:   Shawn Evans
##  Version:    v.09 beta
##  Email:      Shawn.Evans@KnowledgeCG.com      

import os
import ssl
import socket
import re
import sys
import pprint 

class SSLChecker():

    def __init__(self, host, port, types, verbose):
        highCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "HIGH" 2> /dev/null').read().split('\n')]
        medCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "MEDIUM" 2> /dev/null').read().split('\n')]
        lowCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "LOW:EXP" 2> /dev/null').read().split('\n')]
        sslv2Ciphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "SSLv2" 2> /dev/null').read().split('\n')]
        anonCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "aNULL" 2> /dev/null').read().split('\n')]
        clearCiphers = [re.split('\ +',cipher.strip()) for cipher in os.popen('openssl ciphers -v "eNULL" 2> /dev/null').read().split('\n')]
        self.complete = {'HIGH':highCiphers,'MEDIUM':medCiphers,'LOW':lowCiphers,'SSLv2':sslv2Ciphers,'aNULL':anonCiphers,'eNULL':clearCiphers}
        
        if verbose:
            self.verbose = True
        else:
            self.verbose= False  
        
        self.setHost(host, port) 
        
        try:
            self.sslv2Context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
            self.sslv2Context.options |= ssl.OP_NO_SSLv3
            self.sslv2Context.verify_mode = ssl.CERT_OPTIONAL
        except AttributeError:
            print('[ERROR]\tSSLv2 ciphers are not supported')
            if 'SSLv2' in types: types.remove('SSLv2')
        except IOError:
            print('[ERROR]\tCannot open certificate bundle, you might be using Python 2.7 or earlier')
            sys.exit()
        
        try:
            self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            self.context.options |= ssl.OP_NO_SSLv2
            self.context.verify_mode = ssl.CERT_OPTIONAL
            self.checks = types
        except IOError:
            print('[ERROR]\tCannot open certificate bundle') 
            sys.exit()
        except AttributeError:
            print('[ERROR]\tCannot open certificate bundle, you might be using Python 2.7 or earlier')
            sys.exit()

        self.supported = []
         
    def setHost(self, host, port):
        self.host = host    
        try:
            self.port = int(port)
        except ValueError:
            print('[ERROR]\tInvalid port value.')
            sys.exit()
        
        self.portOpen = self.isOpen(self.host, self.port)
    
 
    def checkCiphers(self):
        for cipherType in self.checks:
            if cipherType in self.complete.keys():
                for cipher in self.complete[cipherType]:
                    if len(cipher) == 1:
                        continue
                    if len(cipher) == 6:
                        name,prot,keyEx,auth,strength,mac = cipher
                    else:
                        name,prot,keyEx,auth,strength,mac,exp = cipher
                    
                    try:
                        strength = re.search('[0-9]{2,4}',strength).group(0)
                    except:
                        strength = 'None'
                    
                    try:
                        self.context.set_ciphers(name)
                    except:
                        continue
        
                    self.sslConnect(name, prot, strength, cipherType, keyEx, .5)
                    
            else:
                print('[ERROR]\tInvalid cipher list')
        
        for supCipher in self.supported:
            name, prot, strength, keyEx, cipherType = supCipher
            print('[ACCEPTED]\t%s\t%s\t%s\t%s\t%s\t%s:%s' % (name.ljust(25), prot, strength, keyEx, cipherType, self.host, self.port))
        self.supported = []

    def sslConnect(self, name, prot, strength, cipherType, keyEx, timeout):    
        if (prot == 'SSLv2'):
            sslSock = self.sslv2Context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
            sslSock = self.context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        if self.portOpen: 
            try:
                sslSock.settimeout(timeout)
                sslSock.connect((self.host, self.port))
                self.supported.append([name,prot,strength,keyEx, cipherType])
                sslSock.close()
            except socket.gaierror:
                print('[ERROR]\tUnable to connect to host %s' % self.host)
                sslSock.close()
            except ssl.SSLError as e:
                if self.verbose:
                    print('[FAILURE]\t%s\t%s\t%s\t%s' % (name.ljust(25), prot, strength, cipherType))
                sslSock.close()
            except socket.error as e:
                if self.verbose:
                    print('[ERROR]\tConnection reset by peer, cipher not supported.  Cipher: %s\tHost:%s' % (name,self.host))
            except Exception as e: 
                print(type(e))
                print(e)
            sslSock.close() 
    
    def hostnameMatch(self):
        if self.portOpen:
            try:
                self.context.set_ciphers('HIGH:MEDIUM')
                sslSock = self.context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                sslSock.settimeout(.5) 
                sslSock.connect((self.host, self.port))
                cert = sslSock.getpeercert()
                if self.verbose:
                    print('[INFO]\tCertificate data:')
                    pprint.pprint(cert)
                ssl.match_hostname(cert, self.host)
                sslSock.close()
            except socket.timeout:
                print('[ERROR]\tConnection timeout, verify host and port: %s:%s') % (self.host, self.port)
                sslSock.close()
            except ssl.SSLError as e:
                print('[INFO]\tCertificate verification error on %s:%s.' % (self.host, self.port))
                sslSock.close()
            except socket.gaierror:
                print('[ERROR]\tUnable to connect to host %s' % self.host)
                pass
            except socket.error:
                if self.verbose:
                    print('[ERROR]\tConnection reset by peer (port closed): ', self.host)
                sslSock.close()
            except ssl.CertificateError:
                for value in cert['subject']:
                    if 'commonName' in value[0]:
                        common = value[0][1]
                print('[INFO]\tHost %s does not match common name %s' % (self.host, common))
                sslSock.close()
            
    def isOpen(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(.5)
        if self.verbose:
            print('[INFO]\tTrying %s:%s' % (ip, port))  
        try:
            s.connect((ip, int(port)))
            s.close()
            if self.verbose:
                print('[INFO]\tport: %s\thost: %s OPEN' % (port, ip))
            return True
        except:
            return False       

def usage():
    print('\nSSL Snake v0.9')
    print('')
    print('-?\tthis junk')
    print('-h\thost or ip')
    print('-f\thost file')
    print('-p\tport (default 443)')
    print('-all\tevery supported cipher')
    print('-high\thigh grade ciphers')
    print('-med\tmedium grade ciphers')
    print('-low\tlow grade ciphers')
    print('-sslv2\tsslv2 ciphers')
    print('-anon\tnull authentication ciphers')
    print('-clear\tclear-text ciphers')
    print('-v\tverbose output (print cert details)')
    print('')
    print('Example:')
    print('python %s -h www.example.com -low -ssl2 -v' % sys.argv[0])
    print('')
    print('Hit me up to complain: Shawn.Evans@knowledgecg.com')
    sys.exit()


if __name__ == '__main__':
    cipherTypes = []
    host = ''
    port = 443
    verbose = False

    if '-h' in sys.argv:
        try:
            host = sys.argv[sys.argv.index('-h')+1]
        except:
            print('[ERROR]\tMissing value for host argument')
            usage()
            sys.exit()
    elif '-f' in sys.argv:
        try:
            hostFile = open(sys.argv[sys.argv.index('-f')+1]).readlines()
            print('[INFO]\tUsing file as source')
        except Exception as e:
            print('[ERROR]\tInvalid host file')
            usage()
            sys.exit()
    else:
        print('[ERROR]\tMissing host')
    if '-p' in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index('-p')+1])
        except:
            print('[ERROR]\tInvalid value for port argument')
            usage()
            sys.exit()

    if '-?' in sys.argv: usage()
    if '-v' in sys.argv: verbose = True
    
    if '-high' in sys.argv: cipherTypes.append('HIGH')
    if '-low' in sys.argv: cipherTypes.append('LOW')
    if '-med' in sys.argv: cipherTypes.append('MEDIUM')
    if '-sslv2' in sys.argv: cipherTypes.append('SSLv2')
    if '-anon' in sys.argv: cipherTypes.append('aNULL')
    if '-clear' in sys.argv: cipherTypes.append('eNULL')
    if '-all' in sys.argv: cipherTypes.extend(['HIGH','MEDIUM','LOW','SSLv2','aNULL','eNULL'])

    if len(cipherTypes) == 0:
        print('[INFO]\tNo valid filters supplied, using -all')
        cipherTypes.extend(['HIGH','MEDIUM','LOW','SSLv2','aNULL','eNULL'])
    if '-f' in sys.argv:
        for hostEntry in hostFile:
            if ':' in hostEntry:
                host = hostEntry.strip().split(':')[0]
                port = hostEntry.strip().split(':')[1]
            else:
                host = hostEntry.strip()
            
            try:
                sslChecker.setHost(host, port)
            except NameError:
                sslChecker = SSLChecker(host, port, cipherTypes, verbose)
            sslChecker.hostnameMatch()
            sslChecker.checkCiphers()
    else:   
        sslChecker = SSLChecker(host, port, cipherTypes, verbose)
        sslChecker.hostnameMatch()
        sslChecker.checkCiphers()

