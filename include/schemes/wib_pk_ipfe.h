#ifndef WIB_IPFE_CPA_INCLUDE_SCHEMES_WIB_IPFE_CPA_H_
#define WIB_IPFE_CPA_INCLUDE_SCHEMES_WIB_IPFE_CPA_H_

#include "pbc/pbc.h"
#include "ibe/MasterKey.h"
#include "ibe/PublicKey.h"
#include "ibe/SecretKey.h"
#include "ibe/CipherText.h"
#include "ibe/HIDparam.h"
#include "utils/func.h"
#include "curve/params.h"
#include <unordered_map>
#include <string>

class WIB_PK_IPFE{
private:
    MasterKeyWIB *MSK;
    PublicKeyWIB *PK;
    bool init = false;
    pairing_t pairing;
    std::unordered_map<std::string, element_t *> Dlog_table;
    ElementList *E_G_H_1_Z_i;
    element_t gs_base, gs_step;
    int Dlog_table_len, gslen;

    element_t *myDlog(element_t &target);

    element_t *myDlog_rho(element_t &base, element_t &target, element_t &Zr); 

public:
    WIB_PK_IPFE();

    WIB_PK_IPFE(std::string &param);

    void change_type(std::string &param);

    ElementList *I2Zp(std::vector<int> p, bool zero_padding);

    ElementList *GenZnList(int len);

    void cleanSetUp();

    PublicKeyWIB *Setup(int n, int d);

    SecretKeyWIB *KeyGen(ElementList *P, ElementList *y, HIDparamWIB *param);

    SecretKeyWIB *KeyGen(PublicKeyWIB *PK, ElementList *P, ElementList *y, HIDparamWIB *param);

    CipherTextWIB *Encrypt(ElementList *P, ElementList *x, HIDparamWIB *param);

    CipherTextWIB *Encrypt(PublicKeyWIB *PK, ElementList *P, ElementList *x, HIDparamWIB *param);

    element_t *Decrypt(CipherTextWIB *CT, SecretKeyWIB *SK);

    element_t *Decrypt(PublicKeyWIB *PK, CipherTextWIB *CT, SecretKeyWIB *SK);

    SecretKeyWIB *Delegate(SecretKeyWIB *SK, ElementList *P_new, HIDparamWIB *param);

    SecretKeyWIB *Delegate(PublicKeyWIB *PK, SecretKeyWIB *SK, ElementList *P_new, HIDparamWIB *param);

    void init_dlog(int table_len);

    void init_max_res(int res);

    std::string toString();

    ~WIB_PK_IPFE();

};

#endif 