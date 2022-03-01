import PyQt4
import matplotlib
matplotlib.use('qt4agg')

from pylab import *
import numpy as np
import scipy
import matplotlib.pyplot as plt
import binascii

SBOX=[99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
      202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
      183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 
      4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 
      9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 
      83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 
      208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 
      81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 
      205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 
      96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 
      224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 
      231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 
      186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 
      112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 
      225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 
      140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];


traceSize = 370000
offset = 0
segmentLength = 370000 #for the beginning the segmentLength = traceSize
numberOfTraces = 200



def traceload(fname, traceSize, numberOfTraces):
    '''
    Function wich load traces
    '''
    myfile = open(fname, "r")
    traces = np.zeros((numberOfTraces, traceSize))
    for i in range (0,numberOfTraces):
        traces[i, :] = np.fromfile(myfile, np.uint8, traceSize)
    myfile.close()
    return traces
	

def myin(fname, columns, rows):
    '''
    Function wich open file
    '''
    myfile = open(fname, "r")
    s= np.loadtxt(fname, np.uint8, delimiter=" ")
    myfile.close()
    return s
	
	
def bit_get(byteval,idx):
    '''
    Function wich return the bit of an octet
    '''
    return ((byteval&(1<<idx))!=0)
    

O_traces = traceload("DPA_traces-00112233445566778899aabbccddeeff.bin", traceSize, numberOfTraces)

plt.figure(1)
plt.plot(O_traces[0, :])
plt.title("Consumption of an encryption")

#Targeting the first round
offset = 50000
segmentLength = 30000
traces = O_traces[:,offset:offset+segmentLength]
plt.figure(2)
plt.plot(traces[0, :])
plt.title("Consumption of an encryption")



byteStart=0
ByteEnd=15
keyCandidateStart = 0
keyCandidateStop = 255

columns = 16
rows = numberOfTraces
plaintext = myin('DPA_plaintext.txt', columns, rows)



clef_potentielle=""
# For each subkey
print("Calc each sub key")
print("Max value should be the good sub key")
for b in range(byteStart,ByteEnd+1):
    
    moy_mean=zeros((256,segmentLength))
    max_moy_mean=-1
    dico_max={}

    mean_0 = zeros((256,segmentLength))
    mean_1 = zeros((256,segmentLength))
    counter_0=zeros(256)
    counter_1=zeros(256)
    k=keyCandidateStart

    #Testing each sub key
    for k in range(keyCandidateStart, keyCandidateStop+1):
        #Pour chaque plaintext
        for l in range(len(plaintext)):
            octet=plaintext[l][b]
            #xor with sub key
            xor=octet^k
            #SubBytes
            sbox_res=SBOX[xor]
            #Get final bit
            bit_determinant=bit_get(sbox_res,0)
            #Dispatch traces
            if bit_determinant:
                mean_1[k]+=traces[l]
                counter_1[k]+=1
            else:
                mean_0[k]+=traces[l]
                counter_0[k]+=1
    
        #Calc the means
        mean_0[k]/=counter_0[k]
        mean_1[k]/=counter_1[k]
        moy_mean[k]=abs(mean_1[k]-mean_0[k])
        if b == 0  :
            plt.figure(3)
            plt.plot(moy_mean[0, :])
            plt.title("Exemple de DPA pour le premier octet")
        if b == 1 :
            plt.figure(4)
            plt.plot(moy_mean[0, :])
            plt.title("Exemple de DPA pour le deuxieme octet")

        #Save max value
        val_max = moy_mean[k].max()
        dico_max[k]=val_max

    
    #Save 6 most probable sub key
    max_k=[hex(k)[2:].zfill(2) for k in sorted(dico_max.keys(), key=lambda ok : dico_max[ok], reverse=True)[:6]]
    clef_potentielle+=max_k[0]
    print("Sub key n "+str(b)+" most problable : " +str(max_k[0])) 
    print("5 others potential sub key "+str(b)+" : "+str(max_k[1:]))


print("\n\nKey : "+clef_potentielle)
#afficher les graphiques, prend 1 minute
#show()
