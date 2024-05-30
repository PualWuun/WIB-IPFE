import subprocess
from tqdm import tqdm
import os
curves = ["typea", "typee", "typea1"][:2]
schemes = ["song"]
levels = ["setup", "keygen", "delegate", "encrypt", "decrypt"]

ndList = []
# for n in range(10, 16):
#     for d in range(10, 16):
#         ndList.append([n, d])

ITS = 50

for n in range(10, 160, 10): ndList.append([n, 20])

for d in range(5, 21): ndList.append([10, d])

if not os.path.exists("data/"): os.mkdir("data/")
for sch in schemes:    
    if not os.path.exists(f"data/{sch}"): os.mkdir(f"data/{sch}")
    for name in curves:    
        print("doing", sch, name, "first")
        for nd in tqdm(ndList):
            n, d = nd
            fff = [open(f"data/{sch}/{name}_{level}_{n}_{d}_first.txt", "w") for level in levels]
            p = subprocess.Popen(f"./IPFE_test {n} {d} {sch} {name[4:]} 1 decrypt {ITS} 0", stdout = subprocess.PIPE, shell = True)
            p.communicate()
            d2 = open("tmp_first.txt", "r")
            ddd = d2.readlines()
            while len(ddd) > 7:
                for x in fff: x.write(ddd[0])
                ddd = ddd[1:]
                for x in fff: 
                    x.write(ddd[0])
                    ddd = ddd[1:]
                for x in fff: x.write(ddd[0])
                ddd = ddd[1:]
            d2.close()
        for level in levels:
            print("doing", sch, name, level)
            for nd in tqdm(ndList):
                n, d = nd
                f1 = open(f"data/{sch}/{name}_{level}_{n}_{d}.txt", "w")
                p = subprocess.Popen(f"./IPFE_test {n} {d} {sch} {name[4:]} 0 {level} {ITS} 0", stdout = subprocess.PIPE, shell = True)
                p.communicate()
                d1 = open("tmp.txt", "r")
                f1.write(d1.read())
                d1.close()
                f1.close()
        # exit()
