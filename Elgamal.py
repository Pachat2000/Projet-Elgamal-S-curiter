import random
from Crypto.Util.number import getPrime,isPrime,inverse
from math import gcd,log
import time
import hashlib

def gen(k):
    p=4
    while isPrime(p) !=1:
        q = getPrime(k-1)  #Select a random (k − 1)-bit prime q
        p = 2*q+1 # Compute p←2q + 1, and test whether p is prime
    b= 1
    n=2*q
    while b==1: #If b = 1 then go to step 1
        alpha =  random.randint(1,p-1)
        if (pow(alpha,n//2,p) !=1 and pow(alpha,n//q,p) != 1):
            b = 0

    return p,alpha
        

def genkey(s):
    p,alpha = gen(s)
    a = random.randint(1,p-2)
    h = pow(alpha,a,p)
    return (a,(p,alpha,h))

def encrypt(m, pk):
    k = random.randint(1,pk[0]-2)
    c1 = pow(pk[1],k,pk[0])
    z = pow(pk[2],k,pk[0])
    c2 = (m*z) % pk[0]
    return (c1, c2)

def decrypt(c,key):
  s =  pow(c[0],key[0],key[1][0])
  return  c[1] * inverse(s, key[1][0]) % key[1][0]

def h(msg): #hashage du message
    msg = msg.to_bytes((msg.bit_length() + 7) // 8, 'big') #conversion du message en string pour la hasher puis on le remet en int
    msg = hashlib.sha256(msg).digest()
    msg = int.from_bytes(msg, 'big')
    return msg

def signature(keys,keyp,m):
    k = 0
    while gcd(k,keyp[0]-1) != 1:
        k = random.randint(2, keyp[0]-1)
    mh = h(m)
    r = pow(keyp[1],k,keyp[0])
    inv = inverse(k,keyp[0]-1)
    t1 = (keys * r) %(keyp[0]-1)
    t2 = (mh - t1) %(keyp[0]-1)
    s = (inv * t2) %( keyp[0]-1)
    return (mh,(r,s))
     
def verify(s,keyp):
    if (1 > s[0]  and s[0] > keyp[0]-1):
        return -1
    tmp1 =pow(keyp[2],s[1][0],keyp[0]) # h^r%p ou h = y dans le chapitre 11
    tmp2 = pow(s[1][0],s[1][1],keyp[0]) # r^s%p 
    v1 = (tmp1*tmp2) % keyp[0]
    v2 = pow(keyp[1],s[0], keyp[0]) #alpah ^h(m) % p
    if v1 == v2:
        return 1
    else:
        return -1



def vote_anonime():
    length_key = 150 #taille de la clef init a 150
    candidat_win = -1
    tmp = -1
    tour = 1
    next_tour = [] # tableau contenant les prochain candidat du prochain tours si il tombe tous égaux
    Candidat = int(input("Entrer le nombre de candidat : "))
    if Candidat < 2:
        return
    electeur = int(input("Entrer le nombre de électeur : "))
    if electeur >= length_key:
        length_key = electeur+2
    urne = [] # tableau de vote des candidat 
    key = genkey(length_key)

    
    for i in range (2,Candidat+2):#  Initialise le tableau des scores des candidats
        urne.append(encrypt(i,key[1]))
        next_tour.append(i-2) 
    tmp2 = next_tour.copy() # contient juste le numéro du candidat
    
    while candidat_win == -1:
        for i in range(2,electeur+2): # Les electeur vote pour le candidat de leur choix
            
            vote_pour = random.randint(0,Candidat-1)
            votecrypt = encrypt(vote_pour+2,key[1])
            urne[vote_pour] = (urne[vote_pour][0] * votecrypt[0],urne[vote_pour][1]*votecrypt[1])
            
            
        print("Tour numéro : ",tour, ", des votes")
        
        for i in range(0,Candidat): # On regarde les resultats des votes
            dec = decrypt(urne[i],key)            
            result =  int( log((dec+2 /(i+2)) ,i+2)+0.1 ) -1
            if result == tmp:
                next_tour.append(tmp2[i])
            if result > tmp :
                next_tour.clear()
                tmp = result
                candidat_win = tmp2[i]
                next_tour.append(tmp2[i])
            
            print("candidat ",tmp2[i], ": ",result, " Vote" )
                    
        if len(next_tour) > 1: # On annonce les résulta des votes
            print("Aucun candidat n'a été sélectionner un nouveau tour avec les candidat restant:", len(next_tour))
            tour+=1 # on remet les variables pour initialiser un nouveau tour 
            Candidat = len(next_tour)
            urne.clear()
            tmp2.clear()
            for i in range(0,len(next_tour)):
                urne.append(encrypt(i+2,key[1]))
                tmp2.append(next_tour[i])
                candidat_win =-1
            next_tour.clear()
            time.sleep(2)
            
        else:
            print("Le gagnant des élections est le candidat :",candidat_win,", avec ", tmp, " Votes")
            
if __name__ == '__main__':
    vote_anonime()
    
    
